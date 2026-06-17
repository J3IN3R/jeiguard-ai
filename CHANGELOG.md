# Changelog — JeiGuard AI

---

## [2.0.0] — 2026-06-17

### 15 mejoras de escalabilidad y valor enterprise

#### Mejora 1 — Capa de Persistencia PostgreSQL (`database.py`)
- ORM completo con SQLAlchemy 2.0 async y asyncpg
- 11 entidades: Tenant, User, UserSession, AlertRecord, Incident, Report, AuditLog, CVECorrelation, ComplianceControl, ModelRegistry, IncidentAlert
- Multi-tenant con aislamiento total por tenant_id
- Índices optimizados para queries de alto rendimiento
- Soporte JSONB nativo para datos semiestructurados

#### Mejora 2 — Autenticación y RBAC (`auth_service.py`)
- JWT Bearer tokens: access (30 min) + refresh (7 días)
- 5 roles jerárquicos: super_admin > admin > analyst > viewer > readonly
- bcrypt (12 rounds) para hash de contraseñas
- Bloqueo automático por intentos fallidos (5 intentos → 15 min lockout)
- 8 endpoints: register, login, refresh, logout, me, sessions, users, role
- Audit trail completo en PostgreSQL de toda acción de usuario
- Preparado para MFA TOTP y OIDC/SSO

#### Mejora 3 — Reportes Ejecutivos PDF (`report_service.py`)
- Motor PDF con ReportLab: reportes profesionales con paleta corporativa JeiGuard
- 5 tipos: executive, technical, compliance, incident, threat_hunt
- Portada corporativa, KPIs visuales, tablas de ataques, gráficos de distribución
- Recomendaciones estratégicas automáticas basadas en alertas detectadas
- Download endpoint con control de descargas y audit trail

#### Mejora 4 — Motor de Compliance (`compliance_service.py`)
- 3 frameworks: NIST CSF 2.0 (22 controles), SOC 2 Type II (14 controles), ISO 27001:2022 (16 controles)
- Evaluación automática basada en el estado del sistema IDS
- Score de cumplimiento por categoría (0-100)
- Gap analysis con recomendaciones priorizadas (HIGH/MEDIUM/LOW)
- Dashboard consolidado multi-framework con postura global
- Evidencia automática generada desde alertas y componentes activos

#### Mejora 5 — Correlación CVE/NVD (`cve_correlation_service.py`)
- Integración con NVD NIST API v2.0 con fallback estático curado
- 52 CVEs mapeados a las 7 categorías de ataque (DoS, R2L, U2R, Backdoor, etc.)
- Scores CVSS v3.1 con vectores de ataque y severidad
- Cache en PostgreSQL con TTL de 24 horas para evitar rate-limiting
- Dashboard de exposición: qué CVEs activos tiene el tenant según sus alertas
- Enriquecimiento automático de alertas con CVEs relevantes

#### Mejora 6 — MLflow Model Registry (`mlflow_tracking.py`)
- Registro de experimentos de entrenamiento con métricas completas (accuracy, F1, FPR, ROC-AUC, latencia)
- Versionado semántico de modelos: champion/challenger pattern
- A/B testing estadístico entre modelos con recomendación automática
- Promoción de versiones: staging → production → archived
- Integración con servidor MLflow externo (http://localhost:5000)

#### Mejora 7 — OpenTelemetry Distribuido (`otel_tracing.py`)
- Trazas distribuidas exportadas a Jaeger vía OTLP gRPC
- Métricas custom: flows_processed, alerts_generated, inference_duration, kafka_lag
- Auto-instrumentación de FastAPI, httpx y SQLAlchemy
- Spans predefinidos para cada etapa del pipeline IDS
- Modo no-op cuando OTEL no está disponible (no rompe el sistema)
- Clase JeiGuardMetrics singleton con 9 métricas operacionales

#### Mejora 8 — WebSocket Gateway (`websocket_gateway.py`)
- Streaming de alertas en tiempo real autenticado con JWT
- ConnectionManager multi-tenant con broadcast aislado por organización
- Filtros por nivel y categoría de ataque en la URL de conexión
- Comandos dinámicos: subscribe/unsubscribe/ping
- Heartbeat cada 30s con manejo de desconexiones
- Buffer de 1000 mensajes por cliente con backpressure management

#### Mejora 9 — Python SDK Oficial (`sdk/`)
- JeiGuardClient (síncrono): login, predict, get_alerts, get_models, compliance, CVEs, PDF
- JeiGuardAsyncClient: full async con stream_alerts() AsyncIterator
- Retry automático con exponential backoff (3 intentos)
- Data classes tipados: AlertSummary, PredictionResult, ModelInfo, CVEDetail
- Excepciones específicas: AuthenticationError, AuthorizationError, NotFoundError

#### Mejora 10 — Terraform Azure AKS (`terraform/azure/main.tf`)
- AKS cluster enterprise con zonas de disponibilidad (1, 2, 3)
- Azure Event Hubs con Kafka API (5 topics)
- PostgreSQL Flexible Server 16 con HA Zone-Redundant
- Azure Cache for Redis Premium con shard clustering
- Container Registry Premium con geo-replicación
- Key Vault + Azure Monitor + Application Insights
- WAF y Bastion incluidos

#### Mejora 11 — Terraform GCP GKE (`terraform/gcp/main.tf`)
- GKE Standard con Workload Identity, Binary Authorization, Private cluster
- Cloud Pub/Sub (Kafka API compatible) con 5 topics
- Cloud SQL for PostgreSQL 16 con HA y CMEK (Cloud KMS)
- Memorystore for Redis con auth y TLS
- Artifact Registry con tags inmutables
- Cloud Armor WAF: protección SQLi, XSS, rate limiting
- Secret Manager + OpenTelemetry (Cloud Trace)

#### Mejora 12 — Kubernetes Operator + CRDs (`k8s_operator/operator.py`)
- CRDs: JeiGuardDeployment, JeiGuardSensor
- Operator con Kopf: create/update/delete/reconcile handlers
- Provisioning automático de nuevos tenants en K8s
- Reconciliación periódica cada 60 segundos
- HPA automático basado en métricas de negocio
- Generador de manifiestos YAML para CRDs

#### Mejora 13 — API Gateway unificado (`main_api.py`)
- FastAPI con todos los routers integrados
- CORS configurado para dashboards externos
- Security headers automáticos (HSTS, X-Frame-Options, X-XSS-Protection)
- Middleware de latencia con X-Process-Time-Ms header
- Lifespan async: inicializa OTEL, DB y métricas al arrancar

#### Mejora 14 — Docker Compose Enterprise (`docker-compose.yml`)
- +4 servicios: PostgreSQL 16, Redis 7.2, MLflow, Jaeger
- +1 herramienta: pgAdmin para gestión visual de BD
- Volúmenes persistentes para todos los nuevos servicios
- Health checks en PostgreSQL y Redis
- Subnet VPC con CIDR definido (172.20.0.0/16)

#### Mejora 15 — CI/CD Enterprise (`ci.yml`)
- +6 jobs: quality, tests, dependency-audit, integration-tests, docker-build, container-scan, sbom, terraform-validate
- Bandit: análisis SAST de seguridad estático
- pip-audit: auditoría de vulnerabilidades en dependencias
- Trivy: escaneo de vulnerabilidades en imagen Docker
- Syft: generación de SBOM (Software Bill of Materials) en formato SPDX
- Docker multi-arch: linux/amd64 + linux/arm64
- Validación de Terraform para AWS, Azure y GCP

---

## [1.0.1] — 2026-05-18

### 12 mejoras implementadas

#### Mejora 1 — XAI Explicabilidad (`services/v101/xai_service.py`)
- SHAP TreeExplainer para justificar cada predicción del Random Forest
- Fallback a Permutation Importance cuando SHAP no está disponible
- Top 5 features más determinantes con porcentaje de contribución
- Texto en lenguaje natural explicando la decisión del modelo
- Análisis contrafactual: qué cambiaría para que sea clasificado como "Normal"

#### Mejora 2 — Interfaz Web Streamlit (`services/v101/streamlit_app.py`)
- Dashboard con 4 páginas: Dashboard Principal, Predicción, Alertas, Métricas
- KPIs en tiempo real con Plotly: flujos/seg, accuracy, alertas activas, latencia P99
- Módulo de clasificación manual con formulario y visualización de Top 3
- Centro de alertas con filtros por nivel y categoría, exportación CSV
- Panel de métricas con comparación F1-Score vs Snort y latencias P50/P99

#### Mejora 3 — CNN-1D TensorFlow real (`services/v101/model_v101.py`)
- Arquitectura CNN-1D con 3 bloques Conv1D + BatchNorm + MaxPool + Dropout
- 487,000 parámetros entrenables
- Early stopping, ReduceLROnPlateau y ModelCheckpoint
- Ensamble ponderado CNN-1D (60%) + Random Forest (40%) — función `predict_hybrid()`

#### Mejora 4 — Reentrenamiento online (`services/v101/model_v101.py`)
- Buffer circular de muestras verificadas (máximo 10,000)
- Reentrenamiento asíncrono en background thread sin interrumpir el servicio
- Swap atómico del modelo: solo aplica si accuracy no cae más de 2%
- Estadísticas de cada ciclo de reentrenamiento

#### Mejora 5 — Detección de anomalías (`services/v101/anomaly_federated_v101.py`)
- Autoencoder Keras: encoder (55→32→16) + decoder (16→32→55)
- Threshold automático en percentil 95 del error de reconstrucción
- Fallback a IsolationForest (200 estimadores) sin TensorFlow
- Score de anomalía 0-100 combinando ambos métodos (60/40)
- Identifica las 5 features más anómalas por z-score

#### Mejora 6 — Aprendizaje federado (`services/v101/anomaly_federated_v101.py`)
- Servidor FedAvg: promedio ponderado por número de muestras de cada sensor
- Clientes sensor: entrenan localmente, envían solo pesos (no datos)
- Privacidad total garantizada — los datos de red nunca salen del sensor
- Historial completo de rondas con métricas por agregación

#### Mejora 7 — LLM Analyst (`services/v101/llm_analyst_service.py`)
- Integración con Claude API (claude-opus-4-5) como analista forense
- Narrativa automática de ataque, acciones recomendadas y preguntas de seguimiento
- Análisis de campañas multi-alerta para detectar APTs coordinados
- Generación de informes forenses ejecutivos por período
- Respuesta a preguntas en lenguaje natural sobre el estado de la red
- Caché de análisis por 1 hora para evitar llamadas repetidas a la API

#### Mejora 8 — SIEM Correlator (`services/v101/siem_correlation_engine.py`)
- Motor de correlación temporal implementando el Cyber Kill Chain de Lockheed Martin
- 5 patrones de ataque conocidos: APT Lateral Movement, Ransomware, Data Exfiltration, etc.
- Detección de campañas multi-etapa en ventana de 5 minutos
- Perfil de riesgo por IP con score acumulativo 0-100
- Progresión del Kill Chain en porcentaje por campaña activa

#### Mejora 9 — SOAR Engine (`services/v101/soar_response_engine.py`)
- Respuesta automática: bloqueo de IPs via iptables, aislamiento de hosts
- Creación automática de tickets en Jira con toda la evidencia
- Notificaciones a Slack vía webhook
- Captura de tráfico con tcpdump para análisis forense
- Modo DRY_RUN para pruebas sin ejecutar acciones reales
- Rollback automático de bloqueos si se superan 3 falsos positivos confirmados

#### Mejora 10 — Threat Intelligence (`services/v101/threat_intel_service.py`)
- Enriquecimiento de IPs con AbuseIPDB (historial de abusos, ISP, país)
- Integración con VirusTotal API (votos de motores antivirus)
- Verificación contra listas locales de rangos maliciosos conocidos
- Caché de 6 horas para respetar límites de APIs gratuitas
- Score de riesgo 0-100 combinando todas las fuentes
- Tags automáticos: tor-exit-node, vpn-provider, high-abuse-score

#### Mejora 11 — Digital Twin (`services/v101/digital_twin_service.py`)
- Gemelo digital de la red con topología empresarial de demostración (11 nodos)
- Mapa topológico interactivo D3.js con colores por nivel de riesgo
- Animación de vectores de ataque propagándose por la topología en tiempo real
- Click en cualquier nodo muestra historial de alertas y métricas
- WebSocket para actualizaciones en tiempo real desde el pipeline Kafka
- Perfil de riesgo por nodo: SAFE / LOW / MEDIUM / HIGH / CRITICAL / COMPROMISED

#### Mejora 12 — Cloud-Native AWS (`services/v101/cloud_deploy/`)
- Terraform completo para AWS EKS (VPC, subnets, node groups, MSK Kafka, OpenSearch)
- Helm chart con valores para todos los microservicios incluyendo las 11 mejoras anteriores
- HPA configurado: Inference Service escala entre 2 y 20 réplicas según CPU/memoria
- Secretos gestionados con Kubernetes Secrets
- Monitoreo con Prometheus ServiceMonitor y dashboards Grafana predefinidos
- NetworkPolicy para aislamiento de tráfico entre servicios

---

## [1.0.0] — 2026-02-18

### Lanzamiento inicial

- Arquitectura de 4 microservicios desacoplados via Apache Kafka
- Modelo híbrido CNN-1D + Random Forest con ensamble ponderado 60/40
- Pipeline de ingeniería de características: 41 features base → 55 features normalizadas
- Accuracy global: 97.4% | F1 macro: 97.3% | FP rate: 1.2% | ROC-AUC: 0.996
- Latencia P99: < 12ms | Throughput: 15,000 flujos/segundo
- Alert Manager con mapeo MITRE ATT&CK v14 (7 técnicas)
- Elasticsearch para almacenamiento de alertas
- Dashboard Grafana y Kibana
- API REST FastAPI con documentación Swagger automática
- Docker Compose con 9 contenedores
- Kubernetes HPA (2-20 réplicas) con NetworkPolicy
- 40+ tests unitarios (pytest) — cobertura > 80%
- CI/CD con GitHub Actions (mypy + ruff + pytest)
- DOI académico permanente: 10.5281/zenodo.19076945
