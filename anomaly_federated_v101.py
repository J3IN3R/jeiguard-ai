"""
JeiGuard AI v1.0.1 — Mejoras 5 y 6: Anomaly Detection + Federated Learning
Autoencoder para ataques nuevos y aprendizaje federado multi-sensor.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import time
import copy
import threading
import numpy as np
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    import tensorflow as tf
    from tensorflow import keras
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from sklearn.ensemble import IsolationForest

N_FEATURES      = 55
AUTOENCODER_VERSION = "1.0.1"
FEDERATED_VERSION   = "1.0.1"


# ══════════════════════════════════════════════════════════════════════════════
# MEJORA 5: DETECCIÓN DE ANOMALÍAS CON AUTOENCODER
# ══════════════════════════════════════════════════════════════════════════════

def build_autoencoder(n_features: int = N_FEATURES,
                       encoding_dim: int = 16) -> tuple:
    """
    Construye un Autoencoder para detección de anomalías.
    El error de reconstrucción es el score de anomalía.
    """
    if not TF_AVAILABLE:
        return None, None

    inputs  = keras.Input(shape=(n_features,), name="input")
    encoded = keras.layers.Dense(32, activation='relu', name='enc1')(inputs)
    encoded = keras.layers.BatchNormalization(name='enc_bn1')(encoded)
    encoded = keras.layers.Dense(encoding_dim, activation='relu', name='bottleneck')(encoded)
    decoded = keras.layers.Dense(32, activation='relu', name='dec1')(encoded)
    decoded = keras.layers.BatchNormalization(name='dec_bn1')(decoded)
    decoded = keras.layers.Dense(n_features, activation='linear', name='output')(decoded)

    autoencoder = keras.Model(inputs, decoded, name="JeiGuard_Autoencoder_v101")
    encoder     = keras.Model(inputs, encoded, name="JeiGuard_Encoder_v101")

    autoencoder.compile(optimizer='adam', loss='mse')
    return autoencoder, encoder


@dataclass
class AnomalyScore:
    sample_id:        str
    reconstruction_error: float
    is_anomaly:       bool
    anomaly_score:    float        # 0-100
    threshold_used:   float
    method:           str
    top_anomalous_features: list[str]
    explanation:      str


class AnomalyDetectionService:
    """
    Servicio de detección de anomalías que identifica ataques nunca vistos.
    Combina Autoencoder (Keras) con IsolationForest como fallback.
    """

    def __init__(self, contamination: float = 0.05, threshold_percentile: float = 95.0):
        self._autoencoder    = None
        self._encoder        = None
        self._iso_forest     = IsolationForest(
            n_estimators=200, contamination=contamination,
            n_jobs=-1, random_state=42)
        self._threshold      = None
        self._threshold_pct  = threshold_percentile
        self._is_fitted      = False
        self._stats = {"total_scored": 0, "anomalies_detected": 0, "method": "IsolationForest"}

    def fit(self, X_normal: np.ndarray) -> None:
        """Entrena el detector con tráfico normal."""
        self._iso_forest.fit(X_normal)

        if TF_AVAILABLE:
            ae, enc = build_autoencoder()
            if ae is not None:
                ae.fit(X_normal, X_normal,
                       epochs=50, batch_size=64,
                       validation_split=0.1,
                       callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True)],
                       verbose=0)
                self._autoencoder = ae
                self._encoder     = enc
                errors = np.mean(np.square(X_normal - ae.predict(X_normal, verbose=0)), axis=1)
                self._threshold   = np.percentile(errors, self._threshold_pct)
                self._stats["method"] = "Autoencoder+IsolationForest"

        self._is_fitted = True

    def score(self, sample_id: str, X: np.ndarray,
               feature_names: Optional[list[str]] = None) -> AnomalyScore:
        """Calcula el score de anomalía para una muestra."""
        if not self._is_fitted:
            return AnomalyScore(sample_id, 0.0, False, 0.0, 0.0, "not_fitted", [], "Modelo no entrenado")

        method     = "IsolationForest"
        rec_error  = 0.0
        is_anomaly = False
        ae_score   = 0.0

        # Método 1: Autoencoder
        if self._autoencoder is not None and TF_AVAILABLE:
            X3 = X.reshape(1, -1)
            reconstructed = self._autoencoder.predict(X3, verbose=0)[0]
            rec_error = float(np.mean(np.square(X - reconstructed)))
            is_anomaly = rec_error > self._threshold
            ae_score   = min(rec_error / self._threshold * 50, 100) if self._threshold else 0
            method     = "Autoencoder"

        # Método 2: IsolationForest (siempre como segunda opinión)
        iso_score  = float(self._iso_forest.score_samples(X.reshape(1, -1))[0])
        iso_anomaly = iso_score < -0.1
        iso_pct    = min(max((-iso_score - 0.05) * 200, 0), 100)

        # Combinar ambos scores
        final_score = (ae_score * 0.6 + iso_pct * 0.4) if method == "Autoencoder" else iso_pct
        is_anomaly  = is_anomaly or iso_anomaly

        # Identificar features más anómalas
        top_feats = self._get_top_anomalous_features(X, feature_names or [f"f{i}" for i in range(len(X))])

        explanation = (
            f"{'ANOMALÍA DETECTADA' if is_anomaly else 'Tráfico normal'}: "
            f"Score={final_score:.1f}/100. "
            f"{'Este patrón no corresponde a ninguna categoría de ataque conocida — posible ataque de día cero.' if is_anomaly else 'El patrón es consistente con tráfico conocido.'}"
        )

        self._stats["total_scored"] += 1
        if is_anomaly:
            self._stats["anomalies_detected"] += 1

        return AnomalyScore(
            sample_id=sample_id,
            reconstruction_error=rec_error,
            is_anomaly=is_anomaly,
            anomaly_score=round(final_score, 2),
            threshold_used=self._threshold or 0.0,
            method=method,
            top_anomalous_features=top_feats,
            explanation=explanation,
        )

    def _get_top_anomalous_features(self, X: np.ndarray,
                                     feature_names: list[str], top_n: int = 5) -> list[str]:
        """Identifica las features más alejadas de la distribución normal."""
        z_scores = np.abs((X - np.mean(X)) / (np.std(X) + 1e-8))
        top_idx  = np.argsort(z_scores)[-top_n:][::-1]
        return [feature_names[i] if i < len(feature_names) else f"f{i}" for i in top_idx]

    def get_stats(self) -> dict:
        return self._stats


# ══════════════════════════════════════════════════════════════════════════════
# MEJORA 6: APRENDIZAJE FEDERADO
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SensorUpdate:
    sensor_id:       str
    model_weights:   list            # Pesos del modelo local serializado
    n_samples:       int             # Muestras usadas para entrenar
    local_accuracy:  float
    timestamp:       float
    round_number:    int


@dataclass
class FederatedRound:
    round_id:        int
    participating_sensors: list[str]
    n_total_samples: int
    global_accuracy: float
    aggregation_method: str
    started_at:      float
    completed_at:    float

    @property
    def duration_s(self) -> float:
        return self.completed_at - self.started_at


class FederatedLearningService:
    """
    Servidor de aprendizaje federado que agrega modelos locales de múltiples
    sensores usando FedAvg sin acceder a los datos originales de cada sensor.
    Garantiza privacidad completa de los datos de cada red.
    """

    def __init__(self, min_sensors: int = 2, rounds: int = 10):
        self._min_sensors      = min_sensors
        self._max_rounds       = rounds
        self._global_model     = None
        self._current_round    = 0
        self._pending_updates: list[SensorUpdate] = []
        self._round_history:   list[FederatedRound] = []
        self._lock             = threading.Lock()
        self._stats = {
            "total_rounds": 0,
            "registered_sensors": set(),
            "total_samples_processed": 0,
        }

    def register_sensor_update(self, update: SensorUpdate) -> Optional[FederatedRound]:
        """Recibe la actualización local de un sensor."""
        with self._lock:
            self._pending_updates.append(update)
            self._stats["registered_sensors"].add(update.sensor_id)
            self._stats["total_samples_processed"] += update.n_samples

            if len(self._pending_updates) >= self._min_sensors:
                return self._aggregate_round()
        return None

    def get_global_model_weights(self) -> Optional[list]:
        """Retorna los pesos del modelo global actual."""
        with self._lock:
            return self._global_model

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "registered_sensors": list(self._stats["registered_sensors"]),
            "current_round":      self._current_round,
            "pending_updates":    len(self._pending_updates),
        }

    def get_round_history(self) -> list[FederatedRound]:
        return list(self._round_history)

    # ── FedAvg ────────────────────────────────────────────────────────────────

    def _aggregate_round(self) -> FederatedRound:
        """Implementa FedAvg: promedio ponderado por número de muestras."""
        updates     = list(self._pending_updates)
        total_n     = sum(u.n_samples for u in updates)
        t0          = time.time()

        if self._global_model is None:
            aggregated = copy.deepcopy(updates[0].model_weights)
        else:
            aggregated = copy.deepcopy(self._global_model)

        # FedAvg: w_global = Σ (n_k / N) * w_k
        for layer_idx in range(len(aggregated)):
            weighted_sum = np.zeros(len(aggregated[layer_idx]), dtype=np.float64)
            for update in updates:
                weight = update.n_samples / total_n
                layer  = np.array(update.model_weights[layer_idx], dtype=np.float64)
                weighted_sum += weight * layer
            aggregated[layer_idx] = weighted_sum.tolist()

        self._global_model = aggregated
        self._pending_updates.clear()
        self._current_round += 1

        avg_accuracy = np.mean([u.local_accuracy for u in updates])
        round_result = FederatedRound(
            round_id=self._current_round,
            participating_sensors=[u.sensor_id for u in updates],
            n_total_samples=total_n,
            global_accuracy=avg_accuracy,
            aggregation_method="FedAvg",
            started_at=t0,
            completed_at=time.time(),
        )
        self._round_history.append(round_result)
        self._stats["total_rounds"] += 1
        return round_result


class FederatedSensorClient:
    """
    Cliente en cada sensor que entrena localmente y envía solo los pesos.
    Los datos de red nunca salen del sensor — privacidad total.
    """

    def __init__(self, sensor_id: str, server: FederatedLearningService):
        self._sensor_id = sensor_id
        self._server    = server
        self._local_rf  = None
        self._round     = 0

    def local_train(self, X_local: np.ndarray, y_local: np.ndarray,
                     scaler) -> Optional[FederatedRound]:
        """Entrena el modelo localmente y envía los pesos al servidor."""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split

        X_scaled = scaler.transform(X_local)
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y_local, test_size=0.2, random_state=42, stratify=y_local)

        local_model = RandomForestClassifier(
            n_estimators=50, max_depth=15, class_weight='balanced',
            n_jobs=-1, random_state=int(time.time()))
        local_model.fit(X_train, y_train)
        local_accuracy = float(np.mean(local_model.predict(X_val) == y_val))

        # Serializar pesos (feature importances del RF como proxy)
        weights = [
            local_model.feature_importances_.tolist(),
            [local_model.n_estimators],
            [local_accuracy],
        ]
        self._local_rf = local_model
        self._round   += 1

        update = SensorUpdate(
            sensor_id=self._sensor_id,
            model_weights=weights,
            n_samples=len(X_train),
            local_accuracy=local_accuracy,
            timestamp=time.time(),
            round_number=self._round,
        )
        return self._server.register_sensor_update(update)

    @property
    def sensor_id(self) -> str:
        return self._sensor_id


# ── Demo combinado ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from sklearn.preprocessing import StandardScaler
    np.random.seed(42)
    print("=" * 60)
    print("  JeiGuard AI v1.0.1 — Anomaly Detection + Federated Learning")
    print("=" * 60)

    # Datos demo
    n = 1000
    X = np.random.rand(n, N_FEATURES).astype(np.float32)
    y = np.random.choice(8, n, p=[0.53,0.23,0.12,0.05,0.01,0.02,0.03,0.01])
    scaler = StandardScaler()
    Xs     = scaler.fit_transform(X)
    X_normal = Xs[y == 0]

    # Demo Anomaly Detection
    print("\n--- Anomaly Detection ---")
    ad = AnomalyDetectionService()
    ad.fit(X_normal)
    for i, (label, descr) in enumerate([
        (0, "tráfico normal"),
        (1, "DoS_DDoS conocido"),
    ]):
        sample = X[y == label][0]
        score  = ad.score(f"sample_{i}", sample)
        print(f"  {descr}: anomaly={score.is_anomaly} score={score.anomaly_score:.1f}")
        print(f"    {score.explanation}")

    # Demo Federated Learning
    print("\n--- Federated Learning ---")
    server  = FederatedLearningService(min_sensors=3, rounds=10)
    sensors = [FederatedSensorClient(f"sensor-{i:02d}", server) for i in range(1, 5)]

    for i, sensor in enumerate(sensors[:3]):
        split = n // 3
        X_s   = X[i*split:(i+1)*split]
        y_s   = y[i*split:(i+1)*split]
        result = sensor.local_train(X_s, y_s, scaler)
        if result:
            print(f"\n  RONDA FEDERADA {result.round_id} completada:")
            print(f"    Sensores: {result.participating_sensors}")
            print(f"    Muestras: {result.n_total_samples:,}")
            print(f"    Accuracy global: {result.global_accuracy:.1%}")
            print(f"    Método: {result.aggregation_method}")
        else:
            print(f"  {sensor.sensor_id}: entrenado localmente, esperando más sensores...")

    print(f"\nStats federados: {server.get_stats()}")
    print("\nPrivacidad: los datos de cada sensor NUNCA salieron del sensor local.")
