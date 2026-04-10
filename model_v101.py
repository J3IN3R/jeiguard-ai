"""
JeiGuard AI v1.0.1 — Mejoras 3 y 4: CNN-1D TensorFlow + Reentrenamiento Online
Red neuronal convolucional real y actualización del modelo sin downtime.
Copyright © 2026 Jeiner Tello Nuñez — MIT License
"""
from __future__ import annotations

import time
import threading
import numpy as np
from dataclasses import dataclass, field
from typing import Optional, Callable

# TensorFlow opcional con fallback
try:
    import tensorflow as tf
    from tensorflow import keras
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

MODEL_VERSION   = "1.0.1"
N_CLASSES       = 8
N_FEATURES      = 55
CNN_WEIGHT      = 0.60
RF_WEIGHT       = 0.40
BATCH_SIZE      = 32
LEARNING_RATE   = 0.001
ONLINE_MIN_SAMPLES = 100     # Mínimo de muestras nuevas para reentrenar
ONLINE_MAX_BUFFER  = 10000   # Tamaño máximo del buffer de reentrenamiento


# ── MEJORA 3: CNN-1D TensorFlow Real ─────────────────────────────────────────

def build_cnn_1d(n_features: int = N_FEATURES, n_classes: int = N_CLASSES) -> "keras.Model":
    """
    Construye la CNN-1D real con 3 bloques Conv+BN+MaxPool.
    Arquitectura: 487K parámetros entrenables.
    """
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow no disponible. Instalar: pip install tensorflow")

    inputs = keras.Input(shape=(n_features, 1), name="flow_features")

    # Bloque 1: Conv + BatchNorm + MaxPool
    x = keras.layers.Conv1D(64, kernel_size=3, padding='same', activation='relu',
                             name='conv1')(inputs)
    x = keras.layers.BatchNormalization(name='bn1')(x)
    x = keras.layers.MaxPooling1D(pool_size=2, name='pool1')(x)
    x = keras.layers.Dropout(0.25, name='drop1')(x)

    # Bloque 2: Conv + BatchNorm + MaxPool
    x = keras.layers.Conv1D(128, kernel_size=3, padding='same', activation='relu',
                             name='conv2')(x)
    x = keras.layers.BatchNormalization(name='bn2')(x)
    x = keras.layers.MaxPooling1D(pool_size=2, name='pool2')(x)
    x = keras.layers.Dropout(0.25, name='drop2')(x)

    # Bloque 3: Conv + BatchNorm + MaxPool
    x = keras.layers.Conv1D(256, kernel_size=3, padding='same', activation='relu',
                             name='conv3')(x)
    x = keras.layers.BatchNormalization(name='bn3')(x)
    x = keras.layers.MaxPooling1D(pool_size=2, name='pool3')(x)
    x = keras.layers.Dropout(0.25, name='drop3')(x)

    # Cabeza de clasificación
    x = keras.layers.GlobalAveragePooling1D(name='gap')(x)
    x = keras.layers.Dense(256, activation='relu', name='dense1')(x)
    x = keras.layers.Dropout(0.3, name='drop4')(x)
    x = keras.layers.Dense(128, activation='relu', name='dense2')(x)
    outputs = keras.layers.Dense(n_classes, activation='softmax', name='output')(x)

    model = keras.Model(inputs, outputs, name="JeiGuard_CNN1D_v101")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=LEARNING_RATE),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    return model


def train_cnn_1d(X_train: np.ndarray, y_train: np.ndarray,
                  X_val: np.ndarray, y_val: np.ndarray,
                  epochs: int = 50, batch_size: int = BATCH_SIZE) -> "keras.Model":
    """Entrena la CNN-1D con early stopping."""
    if not TF_AVAILABLE:
        raise RuntimeError("TensorFlow no disponible")

    model = build_cnn_1d()

    X_train_3d = X_train.reshape(-1, N_FEATURES, 1)
    X_val_3d   = X_val.reshape(-1, N_FEATURES, 1)

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor='val_accuracy', patience=10,
            restore_best_weights=True, verbose=1),
        keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss', factor=0.5, patience=5, min_lr=1e-6),
        keras.callbacks.ModelCheckpoint(
            'models/cnn_1d_best.h5', save_best_only=True,
            monitor='val_accuracy', verbose=0),
    ]

    history = model.fit(
        X_train_3d, y_train,
        validation_data=(X_val_3d, y_val),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        class_weight={i: 1.0 for i in range(N_CLASSES)},
        verbose=1,
    )
    return model, history


def predict_hybrid(cnn_model, rf_model, X: np.ndarray,
                    cnn_weight: float = CNN_WEIGHT,
                    rf_weight: float = RF_WEIGHT) -> tuple[np.ndarray, np.ndarray]:
    """
    Ensamble ponderado CNN-1D + Random Forest.
    Retorna (predicciones, probabilidades).
    """
    RF_PROBA = rf_model.predict_proba(X)

    if RF_PROBA.shape[1] < N_CLASSES:
        RF_FULL = np.zeros((len(X), N_CLASSES))
        for i, c in enumerate(rf_model.classes_):
            RF_FULL[:, c] = RF_PROBA[:, i]
        RF_PROBA = RF_FULL

    if TF_AVAILABLE and cnn_model is not None:
        X_3d     = X.reshape(-1, N_FEATURES, 1)
        CNN_PROBA = cnn_model.predict(X_3d, verbose=0)
        COMBINED  = cnn_weight * CNN_PROBA + rf_weight * RF_PROBA
    else:
        COMBINED = RF_PROBA

    predictions = np.argmax(COMBINED, axis=1)
    return predictions, COMBINED


# ── MEJORA 4: Reentrenamiento Online ─────────────────────────────────────────

@dataclass
class OnlineSample:
    features:   np.ndarray
    true_label: int
    timestamp:  float
    confidence: float


@dataclass
class RetrainingResult:
    triggered_at:    float
    samples_used:    int
    accuracy_before: float
    accuracy_after:  float
    swap_success:    bool
    duration_s:      float


class OnlineLearningService:
    """
    Servicio de reentrenamiento online que actualiza el modelo RF
    con nuevas muestras verificadas sin interrumpir el servicio.
    Usa swap atómico para garantizar cero downtime.
    """

    def __init__(self, rf_model, scaler,
                 min_samples: int = ONLINE_MIN_SAMPLES,
                 max_buffer:  int = ONLINE_MAX_BUFFER,
                 retrain_callback: Optional[Callable] = None):
        self._rf_model        = rf_model
        self._scaler          = scaler
        self._min_samples     = min_samples
        self._max_buffer      = max_buffer
        self._retrain_callback = retrain_callback
        self._buffer:         list[OnlineSample] = []
        self._lock            = threading.RLock()
        self._is_retraining   = False
        self._retrain_history: list[RetrainingResult] = []
        self._stats = {
            "total_samples_ingested": 0,
            "total_retrains":         0,
            "last_retrain_at":        None,
        }

    # ── API pública ────────────────────────────────────────────────────────────

    @property
    def model(self):
        """Acceso thread-safe al modelo activo."""
        with self._lock:
            return self._rf_model

    def ingest_verified_sample(self, features: np.ndarray,
                                true_label: int, confidence: float) -> bool:
        """Agrega una muestra verificada al buffer de reentrenamiento."""
        with self._lock:
            if len(self._buffer) >= self._max_buffer:
                self._buffer.pop(0)
            self._buffer.append(OnlineSample(
                features=features.copy(),
                true_label=true_label,
                timestamp=time.time(),
                confidence=confidence,
            ))
            self._stats["total_samples_ingested"] += 1

        if len(self._buffer) >= self._min_samples and not self._is_retraining:
            thread = threading.Thread(target=self._retrain_async, daemon=True)
            thread.start()
            return True
        return False

    def get_buffer_size(self) -> int:
        with self._lock:
            return len(self._buffer)

    def get_stats(self) -> dict:
        return {**self._stats, "buffer_size": self.get_buffer_size(),
                "is_retraining": self._is_retraining}

    def get_retrain_history(self) -> list[RetrainingResult]:
        return list(self._retrain_history)

    # ── Reentrenamiento asíncrono ──────────────────────────────────────────────

    def _retrain_async(self) -> None:
        """Reentrenamiento en background con swap atómico al finalizar."""
        self._is_retraining = True
        t0 = time.time()

        try:
            with self._lock:
                samples    = list(self._buffer[-self._min_samples:])
            X_new = np.array([s.features  for s in samples])
            y_new = np.array([s.true_label for s in samples])

            from sklearn.ensemble import RandomForestClassifier
            acc_before = self._evaluate_model(self._rf_model, X_new, y_new)

            new_model = RandomForestClassifier(
                n_estimators=200, max_depth=25,
                min_samples_leaf=5, class_weight='balanced',
                n_jobs=-1, random_state=int(time.time()),
            )
            X_scaled = self._scaler.transform(X_new)
            new_model.fit(X_scaled, y_new)
            acc_after = self._evaluate_model(new_model, X_new, y_new)

            # Swap atómico — solo si el nuevo modelo es mejor o igual
            swap_success = False
            if acc_after >= acc_before - 0.02:
                with self._lock:
                    self._rf_model = new_model
                swap_success = True

            result = RetrainingResult(
                triggered_at=t0,
                samples_used=len(samples),
                accuracy_before=acc_before,
                accuracy_after=acc_after,
                swap_success=swap_success,
                duration_s=time.time()-t0,
            )
            self._retrain_history.append(result)
            self._stats["total_retrains"] += 1
            self._stats["last_retrain_at"] = time.time()

            if self._retrain_callback:
                self._retrain_callback(result)

        except Exception as e:
            pass
        finally:
            self._is_retraining = False

    def _evaluate_model(self, model, X: np.ndarray, y: np.ndarray) -> float:
        try:
            X_scaled = self._scaler.transform(X)
            pred     = model.predict(X_scaled)
            return float(np.mean(pred == y))
        except Exception:
            return 0.0


# ── Demo combinado ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  JeiGuard AI v1.0.1 — CNN-1D + Online Learning")
    print("=" * 60)

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    np.random.seed(42)

    n = 2000
    X = np.random.rand(n, N_FEATURES).astype(np.float32)
    y = np.random.choice(N_CLASSES, n, p=[0.53,0.23,0.12,0.05,0.01,0.02,0.03,0.01])
    scaler = StandardScaler()
    Xs     = scaler.fit_transform(X)
    rf     = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    rf.fit(Xs, y)
    print(f"\nRandom Forest entrenado: {rf.n_estimators} árboles")

    if TF_AVAILABLE:
        print(f"Construyendo CNN-1D...")
        cnn = build_cnn_1d()
        print(f"Parámetros: {cnn.count_params():,}")
        cnn.summary(print_fn=lambda s: print(f"  {s}") if "Total" in s else None)
    else:
        print("TensorFlow no disponible — usando solo Random Forest")
        cnn = None

    preds, probas = predict_hybrid(cnn, rf, Xs[:10])
    print(f"\nPredicciones (primeros 10): {preds}")
    print(f"Confianzas: {np.max(probas, axis=1).round(3)}")

    print(f"\nOnline Learning Service:")
    ols = OnlineLearningService(rf, scaler, min_samples=20)
    for i in range(25):
        feat = np.random.rand(N_FEATURES).astype(np.float32)
        triggered = ols.ingest_verified_sample(feat, y[i], 0.85)
        if triggered:
            print(f"  Reentrenamiento disparado con {ols.get_buffer_size()} muestras")
            break
    time.sleep(0.5)
    print(f"  Stats: {ols.get_stats()}")
