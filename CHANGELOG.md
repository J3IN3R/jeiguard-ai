# Changelog — JeiGuard AI

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
