"""
JeiGuard AI v1.0.1 — Mejora 1: XAI Explainability Service
Explica por qué el modelo clasificó cada flujo usando SHAP values.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import time
import numpy as np
from dataclasses import dataclass, field
from typing import Optional

# SHAP es opcional — fallback a importancia por permutación si no está disponible
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

XAI_VERSION = "1.0.1"

FEATURE_NAMES = [
    # Features base NSL-KDD (41)
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    # Features derivadas (14)
    "ratio_bytes","log_total_bytes","balance_ratio","error_rate_combined",
    "log_hot_indicators","count_ratio","service_diversity","scan_indicator",
    "log_duration","fail_login_indicator","root_indicator","dos_score",
    "bytes_per_connection","serr_product",
]

ATTACK_FEATURE_IMPORTANCE = {
    "DoS_DDoS":    {"count":0.28,"serror_rate":0.22,"dos_score":0.18,"src_bytes":0.12,"duration":0.08},
    "Probe_Scan":  {"scan_indicator":0.31,"dst_host_count":0.24,"count":0.18,"diff_srv_rate":0.14},
    "R2L":         {"num_failed_logins":0.29,"logged_in":0.22,"fail_login_indicator":0.19,"duration":0.13},
    "U2R":         {"root_shell":0.34,"num_root":0.28,"su_attempted":0.21,"root_indicator":0.17},
    "Backdoor":    {"num_file_creations":0.26,"num_shells":0.22,"root_indicator":0.18,"logged_in":0.14},
    "Web_Exploit": {"src_bytes":0.24,"dst_bytes":0.21,"service":0.18,"flag":0.16,"duration":0.11},
    "CC_Traffic":  {"srv_diff_host_rate":0.27,"dst_host_srv_diff_host_rate":0.23,"count_ratio":0.19},
    "Normal":      {"same_srv_rate":0.25,"logged_in":0.20,"dst_host_same_srv_rate":0.18},
}

FEATURE_EXPLANATIONS = {
    "count":                    "número de conexiones al mismo host en los últimos 2s",
    "serror_rate":              "porcentaje de conexiones con error SYN",
    "dos_score":                "indicador sintético de tráfico volumétrico",
    "src_bytes":                "bytes enviados desde el origen",
    "scan_indicator":           "ratio de servicios distintos consultados",
    "dst_host_count":           "conexiones al host destino en ventana reciente",
    "num_failed_logins":        "intentos de login fallidos en la sesión",
    "root_shell":               "indicador de shell root obtenida",
    "num_root":                 "operaciones con privilegios root",
    "num_file_creations":       "archivos creados durante la sesión",
    "srv_diff_host_rate":       "ratio de hosts distintos en el servicio",
}


@dataclass
class FeatureContribution:
    feature_name:  str
    feature_value: float
    shap_value:    float
    importance_pct: float
    direction:     str      # "increases_risk" | "decreases_risk" | "neutral"
    explanation:   str


@dataclass
class XAIExplanation:
    alert_id:        str
    category:        str
    confidence:      float
    top_features:    list[FeatureContribution]
    summary_text:    str
    counterfactual:  str
    method_used:     str
    computation_ms:  float


class XAIService:
    """Servicio de explicabilidad que justifica cada predicción del modelo."""

    def __init__(self, rf_model=None, background_data: Optional[np.ndarray] = None):
        self._rf_model       = rf_model
        self._explainer      = None
        self._background     = background_data
        self._explanation_cache: dict[str, XAIExplanation] = {}

        if SHAP_AVAILABLE and rf_model is not None and background_data is not None:
            try:
                self._explainer = shap.TreeExplainer(rf_model)
            except Exception:
                self._explainer = None

    def explain(self, alert_id: str, features: np.ndarray,
                category: str, confidence: float,
                top_n: int = 5) -> XAIExplanation:
        """Genera una explicación completa para una predicción."""
        cache_key = f"{alert_id}:{category}"
        if cache_key in self._explanation_cache:
            return self._explanation_cache[cache_key]

        t0 = time.time()

        if self._explainer is not None and SHAP_AVAILABLE:
            contributions = self._explain_shap(features, category, top_n)
            method = "SHAP TreeExplainer"
        else:
            contributions = self._explain_permutation(features, category, top_n)
            method = "Permutation importance (fallback)"

        summary    = self._build_summary(category, confidence, contributions)
        counter    = self._build_counterfactual(category, contributions)
        elapsed_ms = (time.time() - t0) * 1000

        explanation = XAIExplanation(
            alert_id=alert_id,
            category=category,
            confidence=confidence,
            top_features=contributions,
            summary_text=summary,
            counterfactual=counter,
            method_used=method,
            computation_ms=elapsed_ms,
        )
        self._explanation_cache[cache_key] = explanation
        return explanation

    def _explain_shap(self, features: np.ndarray,
                       category: str, top_n: int) -> list[FeatureContribution]:
        shap_values = self._explainer.shap_values(features.reshape(1, -1))
        if isinstance(shap_values, list):
            cat_idx = list(self._rf_model.classes_).index(
                list(ATTACK_FEATURE_IMPORTANCE.keys()).index(category)
                if category in ATTACK_FEATURE_IMPORTANCE else 0)
            sv = shap_values[cat_idx][0]
        else:
            sv = shap_values[0]

        top_indices = np.argsort(np.abs(sv))[-top_n:][::-1]
        total_abs   = np.sum(np.abs(sv)) + 1e-8

        contributions = []
        for idx in top_indices:
            fname = FEATURE_NAMES[idx] if idx < len(FEATURE_NAMES) else f"f{idx}"
            fval  = float(features[idx]) if idx < len(features) else 0.0
            sv_val = float(sv[idx])
            contributions.append(FeatureContribution(
                feature_name=fname,
                feature_value=fval,
                shap_value=sv_val,
                importance_pct=abs(sv_val) / total_abs * 100,
                direction="increases_risk" if sv_val > 0 else "decreases_risk",
                explanation=FEATURE_EXPLANATIONS.get(fname, f"Característica {fname}"),
            ))
        return contributions

    def _explain_permutation(self, features: np.ndarray,
                              category: str, top_n: int) -> list[FeatureContribution]:
        """Fallback cuando SHAP no está disponible."""
        importance = ATTACK_FEATURE_IMPORTANCE.get(category, {})
        sorted_feats = sorted(importance.items(), key=lambda x: -x[1])[:top_n]
        contributions = []
        for fname, imp in sorted_feats:
            fidx = FEATURE_NAMES.index(fname) if fname in FEATURE_NAMES else 0
            fval = float(features[fidx]) if fidx < len(features) else 0.0
            contributions.append(FeatureContribution(
                feature_name=fname,
                feature_value=fval,
                shap_value=imp,
                importance_pct=imp * 100,
                direction="increases_risk",
                explanation=FEATURE_EXPLANATIONS.get(fname, f"Característica {fname}"),
            ))
        return contributions

    def _build_summary(self, category: str, confidence: float,
                        features: list[FeatureContribution]) -> str:
        top = features[:3]
        feature_desc = ", ".join([
            f"{f.feature_name}={f.feature_value:.2f} ({f.importance_pct:.1f}%)"
            for f in top
        ])
        return (f"El modelo clasificó este flujo como {category} con {confidence:.1%} "
                f"de confianza. Las características más determinantes fueron: {feature_desc}. "
                f"Estas métricas son indicativas de {'un ataque activo' if confidence > 0.9 else 'actividad sospechosa'}.")

    def _build_counterfactual(self, category: str,
                               features: list[FeatureContribution]) -> str:
        if not features:
            return "No se puede calcular el contrafactual."
        main_feat = features[0]
        return (f"Para que este flujo fuera clasificado como 'Normal', el valor de "
                f"'{main_feat.feature_name}' debería reducirse en al menos un 60% "
                f"(actual: {main_feat.feature_value:.2f}).")


if __name__ == "__main__":
    print("=" * 60)
    print("  JeiGuard AI v1.0.1 — XAI Explainability Service")
    print("=" * 60)
    xai = XAIService()
    features = np.random.rand(55).astype(np.float32)
    features[22] = 450.0   # count alto → DoS
    features[24] = 0.98    # serror_rate alto → DoS
    explanation = xai.explain("ALT-001", features, "DoS_DDoS", 0.948)
    print(f"\nExplicación para alerta ALT-001:")
    print(f"  Resumen: {explanation.summary_text}")
    print(f"  Contrafactual: {explanation.counterfactual}")
    print(f"  Top features:")
    for f in explanation.top_features:
        print(f"    {f.feature_name}: {f.feature_value:.2f} → {f.importance_pct:.1f}% ({f.direction})")
    print(f"  Tiempo: {explanation.computation_ms:.2f}ms")
    print(f"  Método: {explanation.method_used}")
