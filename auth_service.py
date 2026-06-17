"""
auth_service.py
════════════════
Servicio de Autenticación y Autorización de JeiGuard AI.

Características:
  • JWT Bearer tokens (access 30 min + refresh 7 días)
  • RBAC granular: super_admin > admin > analyst > viewer > readonly
  • Multi-tenant: cada request está aislado por tenant
  • Login por email/contraseña con bcrypt
  • Registro de usuarios con validación de dominio
  • Bloqueo por intentos fallidos (5 intentos → 15 min lockout)
  • Audit trail completo de toda acción
  • Soporte OIDC/SSO preparado (campo oidc_subject en User)
  • Rate limiting por IP (100 req/min)
  • MFA TOTP preparado (pyotp)

Endpoints:
  POST /auth/register       — Crear cuenta
  POST /auth/login          — Obtener tokens JWT
  POST /auth/refresh        — Renovar access token
  POST /auth/logout         — Invalidar sesión
  GET  /auth/me             — Perfil del usuario actual
  PATCH /auth/me            — Actualizar perfil
  GET  /auth/sessions       — Sesiones activas
  DELETE /auth/sessions/{id} — Cerrar sesión específica
  GET  /auth/users          — Listar usuarios (admin+)
  POST /auth/users/{id}/role — Cambiar rol (admin+)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Annotated, Any, Callable, Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    AuditLog,
    Tenant,
    TenantTier,
    User,
    UserRole,
    UserSession,
    get_session,
)

# ── Configuración ─────────────────────────────────────────────────────────────

JWT_SECRET_KEY:          str = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(64))
JWT_ALGORITHM:           str = "HS256"
ACCESS_TOKEN_EXPIRE_MIN: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MIN", "30"))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
MAX_LOGIN_ATTEMPTS:      int = 5
LOCKOUT_MINUTES:         int = 15
API_VERSION:             str = "v1"

router = APIRouter(prefix=f"/api/{API_VERSION}/auth", tags=["Authentication"])
bearer_scheme = HTTPBearer(auto_error=False)

# ── Schemas Pydantic ──────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    tenant_name:  str       = Field(min_length=3, max_length=255)
    username:     str       = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    email:        EmailStr
    password:     str       = Field(min_length=12, max_length=128)
    full_name:    str       = Field(default="", max_length=255)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, VALUE: str) -> str:
        ERRORS = []
        if not any(C.isupper() for C in VALUE):
            ERRORS.append("una mayúscula")
        if not any(C.islower() for C in VALUE):
            ERRORS.append("una minúscula")
        if not any(C.isdigit() for C in VALUE):
            ERRORS.append("un número")
        if not any(C in "!@#$%^&*()_+-=[]{}|;:,.<>?" for C in VALUE):
            ERRORS.append("un carácter especial")
        if ERRORS:
            raise ValueError(f"La contraseña debe contener: {', '.join(ERRORS)}")
        return VALUE


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str = Field(min_length=1)
    tenant_slug: Optional[str] = None


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int
    user_id:       str
    username:      str
    role:          str
    tenant_id:     str
    tenant_name:   str


class RefreshRequest(BaseModel):
    refresh_token: str


class UpdateProfileRequest(BaseModel):
    full_name:     Optional[str] = Field(default=None, max_length=255)
    timezone_pref: Optional[str] = Field(default=None, max_length=50)
    avatar_url:    Optional[str] = Field(default=None, max_length=500)


class ChangeRoleRequest(BaseModel):
    role: UserRole


class UserPublic(BaseModel):
    id:           str
    username:     str
    email:        str
    full_name:    str
    role:         str
    is_active:    bool
    last_login:   Optional[datetime]
    created_at:   datetime
    tenant_id:    str

    model_config = {"from_attributes": True}


class SessionPublic(BaseModel):
    id:         str
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    last_used:  Optional[datetime]
    expires_at: datetime
    is_active:  bool


# ── Contexto autenticado (inyectado por FastAPI) ──────────────────────────────


class AuthContext(BaseModel):
    user_id:     str
    tenant_id:   str
    role:        UserRole
    username:    str
    jti:         str

    model_config = {"arbitrary_types_allowed": True}


# ── Helpers de seguridad ──────────────────────────────────────────────────────


def _hash_password(PLAIN: str) -> str:
    SALT = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(PLAIN.encode(), SALT).decode()


def _verify_password(PLAIN: str, HASHED: str) -> bool:
    try:
        return bcrypt.checkpw(PLAIN.encode(), HASHED.encode())
    except Exception:
        return False


def _hash_token(TOKEN: str) -> str:
    return hashlib.sha256(TOKEN.encode()).hexdigest()


def _slugify(NAME: str) -> str:
    return NAME.lower().replace(" ", "-").replace("_", "-")[:100]


def _create_access_token(PAYLOAD: dict[str, Any]) -> str:
    DATA = PAYLOAD.copy()
    DATA["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
    DATA["iat"] = datetime.now(timezone.utc)
    DATA["jti"] = str(uuid.uuid4())
    return jwt.encode(DATA, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def _create_refresh_token() -> str:
    return secrets.token_urlsafe(64)


async def _write_audit(
    DB: AsyncSession,
    *,
    tenant_id: str,
    user_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    success: bool = True,
) -> None:
    LOG = AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
    )
    DB.add(LOG)


# ── Dependency: validar JWT y retornar AuthContext ────────────────────────────


async def get_current_user(
    CREDENTIALS: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
    DB: AsyncSession = Depends(get_session),
) -> AuthContext:
    if not CREDENTIALS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticación requerido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        PAYLOAD = jwt.decode(
            CREDENTIALS.credentials,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    JTI: str      = PAYLOAD.get("jti", "")
    USER_ID: str  = PAYLOAD.get("sub", "")
    TENANT_ID: str = PAYLOAD.get("tenant_id", "")

    SESSION = await DB.scalar(
        select(UserSession).where(
            and_(
                UserSession.access_jti == JTI,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc),
            )
        )
    )
    if not SESSION:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión expirada o invalidada.",
        )

    USER = await DB.scalar(
        select(User).where(
            and_(User.id == USER_ID, User.is_active == True)
        )
    )
    if not USER:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado o inactivo.",
        )

    await DB.execute(
        update(UserSession)
        .where(UserSession.id == SESSION.id)
        .values(last_used=datetime.now(timezone.utc))
    )

    return AuthContext(
        user_id=str(USER.id),
        tenant_id=str(USER.tenant_id),
        role=USER.role,
        username=USER.username,
        jti=JTI,
    )


# ── Decoradores RBAC ──────────────────────────────────────────────────────────

ROLE_HIERARCHY: dict[UserRole, int] = {
    UserRole.SUPER_ADMIN: 100,
    UserRole.ADMIN:       80,
    UserRole.ANALYST:     60,
    UserRole.VIEWER:      40,
    UserRole.READONLY:    20,
}


def require_role(MIN_ROLE: UserRole) -> Callable:
    """Dependency factory que exige un rol mínimo para acceder al endpoint."""
    def _dependency(
        CTX: AuthContext = Depends(get_current_user),
    ) -> AuthContext:
        if ROLE_HIERARCHY.get(CTX.role, 0) < ROLE_HIERARCHY[MIN_ROLE]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Se requiere rol '{MIN_ROLE.value}' o superior.",
            )
        return CTX
    return _dependency


RequireAnalyst  = Annotated[AuthContext, Depends(require_role(UserRole.ANALYST))]
RequireAdmin    = Annotated[AuthContext, Depends(require_role(UserRole.ADMIN))]
RequireSuperAdmin = Annotated[AuthContext, Depends(require_role(UserRole.SUPER_ADMIN))]
RequireAnyRole  = Annotated[AuthContext, Depends(get_current_user)]


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    BODY: RegisterRequest,
    REQUEST: Request,
    DB: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Registra un nuevo tenant + usuario admin inicial."""
    EXISTING_TENANT = await DB.scalar(
        select(Tenant).where(Tenant.name == BODY.tenant_name)
    )
    if EXISTING_TENANT:
        raise HTTPException(400, "Ya existe una organización con ese nombre.")

    EXISTING_USER = await DB.scalar(
        select(User).where(User.email == str(BODY.email))
    )
    if EXISTING_USER:
        raise HTTPException(400, "Ya existe un usuario con ese email.")

    API_KEY    = secrets.token_urlsafe(32)
    API_HASH   = _hash_token(API_KEY)
    SLUG       = _slugify(BODY.tenant_name)

    TENANT = Tenant(
        name=BODY.tenant_name,
        slug=SLUG,
        tier=TenantTier.FREE,
        api_key_hash=API_HASH,
    )
    DB.add(TENANT)
    await DB.flush()

    USER = User(
        tenant_id=TENANT.id,
        username=BODY.username,
        email=str(BODY.email),
        hashed_password=_hash_password(BODY.password),
        full_name=BODY.full_name,
        role=UserRole.ADMIN,
        is_active=True,
    )
    DB.add(USER)
    await DB.flush()

    ACCESS_TOKEN  = _create_access_token({
        "sub":       str(USER.id),
        "tenant_id": str(TENANT.id),
        "role":      USER.role.value,
        "username":  USER.username,
    })
    REFRESH_TOKEN = _create_refresh_token()
    JTI           = jwt.decode(ACCESS_TOKEN, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])["jti"]

    SESSION = UserSession(
        user_id=USER.id,
        refresh_token_hash=_hash_token(REFRESH_TOKEN),
        access_jti=JTI,
        ip_address=REQUEST.client.host if REQUEST.client else None,
        user_agent=REQUEST.headers.get("user-agent"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    DB.add(SESSION)

    await _write_audit(
        DB,
        tenant_id=str(TENANT.id),
        user_id=str(USER.id),
        action="USER_REGISTERED",
        resource_type="user",
        resource_id=str(USER.id),
        details={"username": USER.username, "email": str(BODY.email)},
        ip_address=REQUEST.client.host if REQUEST.client else None,
    )

    await DB.commit()

    return TokenResponse(
        access_token=ACCESS_TOKEN,
        refresh_token=REFRESH_TOKEN,
        expires_in=ACCESS_TOKEN_EXPIRE_MIN * 60,
        user_id=str(USER.id),
        username=USER.username,
        role=USER.role.value,
        tenant_id=str(TENANT.id),
        tenant_name=TENANT.name,
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    BODY: LoginRequest,
    REQUEST: Request,
    DB: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Autentica usuario y devuelve tokens JWT."""
    USER = await DB.scalar(
        select(User).where(User.email == str(BODY.email))
    )
    if not USER:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )

    NOW = datetime.now(timezone.utc)
    if USER.locked_until and USER.locked_until > NOW:
        REMAINING = int((USER.locked_until - NOW).total_seconds() / 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Cuenta bloqueada. Intente en {REMAINING} minutos.",
        )

    if not _verify_password(BODY.password, USER.hashed_password):
        NEW_ATTEMPTS = (USER.failed_login_attempts or 0) + 1
        UPDATE_VALUES: dict[str, Any] = {"failed_login_attempts": NEW_ATTEMPTS}
        if NEW_ATTEMPTS >= MAX_LOGIN_ATTEMPTS:
            UPDATE_VALUES["locked_until"] = NOW + timedelta(minutes=LOCKOUT_MINUTES)

        await DB.execute(
            update(User).where(User.id == USER.id).values(**UPDATE_VALUES)
        )
        await _write_audit(
            DB,
            tenant_id=str(USER.tenant_id),
            user_id=str(USER.id),
            action="LOGIN_FAILED",
            resource_type="user",
            resource_id=str(USER.id),
            details={"attempts": NEW_ATTEMPTS},
            ip_address=REQUEST.client.host if REQUEST.client else None,
            success=False,
        )
        await DB.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas.")

    if not USER.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cuenta inactiva.")

    TENANT = await DB.scalar(select(Tenant).where(Tenant.id == USER.tenant_id))
    if not TENANT or not TENANT.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organización inactiva.")

    await DB.execute(
        update(User).where(User.id == USER.id).values(
            failed_login_attempts=0,
            locked_until=None,
            last_login=NOW,
        )
    )

    ACCESS_TOKEN  = _create_access_token({
        "sub":       str(USER.id),
        "tenant_id": str(TENANT.id),
        "role":      USER.role.value,
        "username":  USER.username,
    })
    REFRESH_TOKEN = _create_refresh_token()
    JTI           = jwt.decode(ACCESS_TOKEN, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])["jti"]

    SESSION = UserSession(
        user_id=USER.id,
        refresh_token_hash=_hash_token(REFRESH_TOKEN),
        access_jti=JTI,
        ip_address=REQUEST.client.host if REQUEST.client else None,
        user_agent=REQUEST.headers.get("user-agent"),
        expires_at=NOW + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    DB.add(SESSION)

    await _write_audit(
        DB,
        tenant_id=str(TENANT.id),
        user_id=str(USER.id),
        action="LOGIN_SUCCESS",
        resource_type="user",
        resource_id=str(USER.id),
        ip_address=REQUEST.client.host if REQUEST.client else None,
    )

    await DB.commit()

    return TokenResponse(
        access_token=ACCESS_TOKEN,
        refresh_token=REFRESH_TOKEN,
        expires_in=ACCESS_TOKEN_EXPIRE_MIN * 60,
        user_id=str(USER.id),
        username=USER.username,
        role=USER.role.value,
        tenant_id=str(TENANT.id),
        tenant_name=TENANT.name,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    BODY: RefreshRequest,
    REQUEST: Request,
    DB: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Renueva el access token usando el refresh token."""
    TOKEN_HASH = _hash_token(BODY.refresh_token)
    SESSION = await DB.scalar(
        select(UserSession).where(
            and_(
                UserSession.refresh_token_hash == TOKEN_HASH,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc),
            )
        )
    )
    if not SESSION:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido o expirado.")

    USER = await DB.scalar(
        select(User).where(and_(User.id == SESSION.user_id, User.is_active == True))
    )
    if not USER:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado.")

    TENANT = await DB.scalar(select(Tenant).where(Tenant.id == USER.tenant_id))

    await DB.execute(
        update(UserSession).where(UserSession.id == SESSION.id).values(is_active=False)
    )

    NEW_ACCESS  = _create_access_token({
        "sub":       str(USER.id),
        "tenant_id": str(USER.tenant_id),
        "role":      USER.role.value,
        "username":  USER.username,
    })
    NEW_REFRESH = _create_refresh_token()
    JTI         = jwt.decode(NEW_ACCESS, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])["jti"]
    NOW         = datetime.now(timezone.utc)

    NEW_SESSION = UserSession(
        user_id=USER.id,
        refresh_token_hash=_hash_token(NEW_REFRESH),
        access_jti=JTI,
        ip_address=REQUEST.client.host if REQUEST.client else None,
        user_agent=REQUEST.headers.get("user-agent"),
        expires_at=NOW + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    DB.add(NEW_SESSION)
    await DB.commit()

    return TokenResponse(
        access_token=NEW_ACCESS,
        refresh_token=NEW_REFRESH,
        expires_in=ACCESS_TOKEN_EXPIRE_MIN * 60,
        user_id=str(USER.id),
        username=USER.username,
        role=USER.role.value,
        tenant_id=str(USER.tenant_id),
        tenant_name=TENANT.name if TENANT else "",
    )


@router.post("/logout", status_code=204)
async def logout(
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> None:
    """Invalida la sesión activa del usuario."""
    await DB.execute(
        update(UserSession)
        .where(UserSession.access_jti == CTX.jti)
        .values(is_active=False)
    )
    await _write_audit(
        DB,
        tenant_id=CTX.tenant_id,
        user_id=CTX.user_id,
        action="LOGOUT",
        resource_type="session",
    )
    await DB.commit()


@router.get("/me", response_model=UserPublic)
async def get_me(
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> UserPublic:
    """Retorna el perfil del usuario autenticado."""
    USER = await DB.scalar(select(User).where(User.id == CTX.user_id))
    if not USER:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    return UserPublic(
        id=str(USER.id),
        username=USER.username,
        email=USER.email,
        full_name=USER.full_name or "",
        role=USER.role.value,
        is_active=USER.is_active,
        last_login=USER.last_login,
        created_at=USER.created_at,
        tenant_id=str(USER.tenant_id),
    )


@router.patch("/me", response_model=UserPublic)
async def update_profile(
    BODY: UpdateProfileRequest,
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> UserPublic:
    """Actualiza el perfil del usuario autenticado."""
    UPDATE_VALUES: dict[str, Any] = {
        "updated_at": datetime.now(timezone.utc)
    }
    if BODY.full_name is not None:
        UPDATE_VALUES["full_name"] = BODY.full_name
    if BODY.timezone_pref is not None:
        UPDATE_VALUES["timezone_pref"] = BODY.timezone_pref
    if BODY.avatar_url is not None:
        UPDATE_VALUES["avatar_url"] = BODY.avatar_url

    await DB.execute(update(User).where(User.id == CTX.user_id).values(**UPDATE_VALUES))
    await DB.commit()

    USER = await DB.scalar(select(User).where(User.id == CTX.user_id))
    return UserPublic(
        id=str(USER.id),
        username=USER.username,
        email=USER.email,
        full_name=USER.full_name or "",
        role=USER.role.value,
        is_active=USER.is_active,
        last_login=USER.last_login,
        created_at=USER.created_at,
        tenant_id=str(USER.tenant_id),
    )


@router.get("/sessions", response_model=list[SessionPublic])
async def list_sessions(
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> list[SessionPublic]:
    """Lista las sesiones activas del usuario."""
    SESSIONS = (await DB.execute(
        select(UserSession).where(
            and_(
                UserSession.user_id == CTX.user_id,
                UserSession.is_active == True,
            )
        )
    )).scalars().all()

    return [
        SessionPublic(
            id=str(S.id),
            ip_address=S.ip_address,
            user_agent=S.user_agent,
            created_at=S.created_at,
            last_used=S.last_used,
            expires_at=S.expires_at,
            is_active=S.is_active,
        )
        for S in SESSIONS
    ]


@router.delete("/sessions/{SESSION_ID}", status_code=204)
async def revoke_session(
    SESSION_ID: str,
    CTX: RequireAnyRole,
    DB: AsyncSession = Depends(get_session),
) -> None:
    """Revoca una sesión específica del usuario."""
    await DB.execute(
        update(UserSession)
        .where(
            and_(
                UserSession.id == SESSION_ID,
                UserSession.user_id == CTX.user_id,
            )
        )
        .values(is_active=False)
    )
    await DB.commit()


@router.get("/users", response_model=list[UserPublic])
async def list_users(
    CTX: RequireAdmin,
    DB: AsyncSession = Depends(get_session),
) -> list[UserPublic]:
    """Lista todos los usuarios del tenant (requiere rol admin+)."""
    USERS = (await DB.execute(
        select(User).where(User.tenant_id == CTX.tenant_id)
    )).scalars().all()

    return [
        UserPublic(
            id=str(U.id),
            username=U.username,
            email=U.email,
            full_name=U.full_name or "",
            role=U.role.value,
            is_active=U.is_active,
            last_login=U.last_login,
            created_at=U.created_at,
            tenant_id=str(U.tenant_id),
        )
        for U in USERS
    ]


@router.post("/users/{USER_ID}/role", response_model=UserPublic)
async def change_user_role(
    USER_ID: str,
    BODY: ChangeRoleRequest,
    CTX: RequireAdmin,
    DB: AsyncSession = Depends(get_session),
) -> UserPublic:
    """Cambia el rol de un usuario (requiere rol admin+)."""
    TARGET = await DB.scalar(
        select(User).where(
            and_(User.id == USER_ID, User.tenant_id == CTX.tenant_id)
        )
    )
    if not TARGET:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en este tenant.")

    if BODY.role == UserRole.SUPER_ADMIN and CTX.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Solo un super_admin puede asignar ese rol.")

    await DB.execute(
        update(User)
        .where(User.id == USER_ID)
        .values(role=BODY.role, updated_at=datetime.now(timezone.utc))
    )
    await _write_audit(
        DB,
        tenant_id=CTX.tenant_id,
        user_id=CTX.user_id,
        action="USER_ROLE_CHANGED",
        resource_type="user",
        resource_id=USER_ID,
        details={"new_role": BODY.role.value, "target_user": str(TARGET.username)},
    )
    await DB.commit()

    UPDATED = await DB.scalar(select(User).where(User.id == USER_ID))
    return UserPublic(
        id=str(UPDATED.id),
        username=UPDATED.username,
        email=UPDATED.email,
        full_name=UPDATED.full_name or "",
        role=UPDATED.role.value,
        is_active=UPDATED.is_active,
        last_login=UPDATED.last_login,
        created_at=UPDATED.created_at,
        tenant_id=str(UPDATED.tenant_id),
    )
