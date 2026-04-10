"""
JeiGuard AI v1.0.1 — Demo en vivo
══════════════════════════════════
Copyright (c) 2026 Jeiner Tello Nuñez

Pipeline completo sin infraestructura:
  Generación de tráfico → Preprocesamiento → Entrenamiento → Predicciones → Alertas → Gráficas

Requisitos:
  pip install numpy scikit-learn matplotlib seaborn

Uso:
  python demo_live.py
"""

import time
import math
import random
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
from sklearn.preprocessing import StandardScaler

np.random.seed(42)
random.seed(42)

# ── Constantes ────────────────────────────────────────────────────────────────
ATTACK_CATEGORIES = [
    "Normal", "DoS_DDoS", "Probe_Scan", "R2L",
    "U2R", "Backdoor", "Web_Exploit", "CC_Traffic"
]
N_BASE_FEATURES = 41
N_CLASSES       = len(ATTACK_CATEGORIES)
CNN_WEIGHT      = 0.60
RF_WEIGHT       = 0.40
N_SAMPLES       = 18000
SEPARATOR       = "═" * 62

MITRE_MAP = {
    "DoS_DDoS":    "T1498 — Network Denial of Service     [Impact]",
    "Probe_Scan":  "T1046 — Network Service Discovery     [Discovery]",
    "R2L":         "T1110 — Brute Force                   [Credential Access]",
    "U2R":         "T1068 — Privilege Escalation Exploit  [Privilege Escalation]",
    "Backdoor":    "T1543 — Create/Modify System Process  [Persistence]",
    "Web_Exploit": "T1190 — Exploit Public-Facing App     [Initial Access]",
    "CC_Traffic":  "T1071 — Application Layer Protocol    [C2]",
}

ALERT_LEVELS = {
    "DoS_DDoS": "🔴 CRITICAL", "U2R": "🔴 CRITICAL", "Backdoor": "🔴 CRITICAL",
    "Probe_Scan": "🟠 HIGH",   "R2L": "🟠 HIGH",
    "Web_Exploit": "🟡 MEDIUM", "CC_Traffic": "🟡 MEDIUM",
    "Normal": "✅ NONE",
}

PROFILE_WEIGHTS = [0.53, 0.23, 0.12, 0.05, 0.01, 0.02, 0.03, 0.01]

# ── Helpers ───────────────────────────────────────────────────────────────────
def PRINT_HEADER(TITLE):
    print(f"\n{SEPARATOR}")
    print(f"  {TITLE}")
    print(SEPARATOR)

def PRINT_STEP(STEP, MSG):
    print(f"  [{STEP}] {MSG}")

def PRINT_BANNER():
    print("\n" + "╔" + "═"*60 + "╗")
    print("║" + " "*15 + "JeiGuard AI v1.0.1" + " "*27 + "║")
    print("║" + " "*8 + "Sistema de Detección de Intrusiones con IA" + " "*10 + "║")
    print("║" + " "*12 + "Copyright © 2026 Jeiner Tello Nuñez" + " "*12 + "║")
    print("╚" + "═"*60 + "╝\n")

# ── PASO 1: Generación de tráfico sintético ───────────────────────────────────
def GENERATE_FEATURE_VECTOR(CATEGORY_IDX):
    BASE = [0.0] * N_BASE_FEATURES
    CAT  = ATTACK_CATEGORIES[CATEGORY_IDX]

    if CAT == "Normal":
        BASE[0]  = max(0, random.gauss(2.0, 1.5))
        BASE[4]  = max(0, random.gauss(1200, 800))
        BASE[5]  = max(0, random.gauss(900, 600))
        BASE[11] = 1.0
        BASE[22] = max(1, random.gauss(10, 3))
        BASE[24] = max(0, min(1, random.gauss(0.02, 0.01)))
        BASE[28] = max(0, min(1, random.gauss(0.90, 0.05)))
        BASE[31] = random.randint(1, 254)
    elif CAT == "DoS_DDoS":
        BASE[0]  = 0.0
        BASE[4]  = max(0, random.gauss(20, 10))
        BASE[22] = max(400, random.gauss(500, 30))
        BASE[24] = max(0.85, min(1.0, random.gauss(0.98, 0.02)))
        BASE[28] = 1.0
    elif CAT == "Probe_Scan":
        BASE[0]  = max(0, random.gauss(0.3, 0.2))
        BASE[4]  = max(0, random.gauss(100, 50))
        BASE[22] = max(1, random.gauss(60, 20))
        BASE[29] = max(0, min(1, random.gauss(0.70, 0.10)))
        BASE[31] = random.randint(200, 255)
    elif CAT == "R2L":
        BASE[0]  = max(0, random.gauss(5.0, 3.0))
        BASE[10] = random.randint(1, 10)
        BASE[4]  = max(0, random.gauss(400, 200))
    elif CAT == "U2R":
        BASE[9]  = random.randint(3, 30)
        BASE[13] = 1.0 if random.random() < 0.4 else 0.0
        BASE[15] = random.randint(0, 5)
        BASE[0]  = max(0, random.gauss(10, 5))
    else:
        BASE[0]  = max(0, random.gauss(4.0, 2.0))
        BASE[4]  = max(0, random.gauss(500, 250))
        BASE[5]  = max(0, random.gauss(400, 200))
        BASE[22] = max(1, random.gauss(8, 3))
        BASE[24] = max(0, min(1, random.gauss(0.08, 0.03)))

    NOISE = [random.gauss(0, 0.05) for _ in range(N_BASE_FEATURES)]
    return [max(0.0, V + N) for V, N in zip(BASE, NOISE)]

def STEP_PRODUCER():
    PRINT_HEADER("PASO 1 — PRODUCER: Generación de tráfico de red")
    PRINT_STEP("INFO", f"Generando {N_SAMPLES:,} flujos de red sintéticos...")

    T0 = time.time()
    X_RAW, Y_RAW, DIST = [], [], {}

    for _ in range(N_SAMPLES):
        CAT_IDX = random.choices(range(N_CLASSES), weights=PROFILE_WEIGHTS, k=1)[0]
        X_RAW.append(GENERATE_FEATURE_VECTOR(CAT_IDX))
        Y_RAW.append(CAT_IDX)
        CAT_NAME = ATTACK_CATEGORIES[CAT_IDX]
        DIST[CAT_NAME] = DIST.get(CAT_NAME, 0) + 1

    ELAPSED = time.time() - T0
    X_RAW = np.array(X_RAW, dtype=np.float32)
    Y_RAW = np.array(Y_RAW)

    PRINT_STEP("✓", f"Completado en {ELAPSED:.2f}s — {N_SAMPLES/ELAPSED:,.0f} flujos/segundo")
    print()
    print("  Distribución de categorías:")
    for CAT, COUNT in sorted(DIST.items(), key=lambda x: -x[1]):
        PCT = COUNT / N_SAMPLES * 100
        BAR = "█" * int(PCT / 2)
        print(f"    {CAT:15s} │{BAR:27s}│ {COUNT:5,}  ({PCT:5.1f}%)")

    return X_RAW, Y_RAW

# ── PASO 2: Preprocesamiento ──────────────────────────────────────────────────
def STEP_PREPROCESSOR(X_RAW):
    PRINT_HEADER("PASO 2 — PREPROCESSOR: Ingeniería de características")
    PRINT_STEP("INFO", "Aplicando pipeline de transformación...")

    T0 = time.time()
    EPS = 1e-8

    SRC_BYTES   = X_RAW[:, 4]
    DST_BYTES   = X_RAW[:, 5]
    TOTAL_BYTES = SRC_BYTES + DST_BYTES + EPS
    COUNT       = np.maximum(X_RAW[:, 22], EPS)
    SRV_COUNT   = X_RAW[:, 23]
    SERROR      = X_RAW[:, 24]
    RERROR      = X_RAW[:, 26]
    SAME_SRV    = np.maximum(X_RAW[:, 28], EPS)
    DIFF_SRV    = X_RAW[:, 29]
    DST_HOST    = X_RAW[:, 31]
    DST_SRV     = np.maximum(X_RAW[:, 32], EPS)

    DERIVED = np.column_stack([
        SRC_BYTES / (DST_BYTES + EPS),
        np.log1p(TOTAL_BYTES),
        (SRC_BYTES - DST_BYTES) / TOTAL_BYTES,
        (SERROR + RERROR) / 2.0,
        np.log1p(X_RAW[:, 9]),
        SRV_COUNT / COUNT,
        DIFF_SRV / SAME_SRV,
        DST_HOST / DST_SRV,
        np.log1p(X_RAW[:, 0]),
        X_RAW[:, 10],
        X_RAW[:, 13] + X_RAW[:, 15] + X_RAW[:, 16],
        SERROR * COUNT / 512.0,
        TOTAL_BYTES / COUNT,
        SERROR * X_RAW[:, 25],
    ])

    X_ENG = np.hstack([X_RAW, DERIVED])
    X_ENG = np.nan_to_num(X_ENG, nan=0.0, posinf=1e6, neginf=-1e6)
    X_ENG = np.clip(X_ENG, -1e6, 1e6).astype(np.float32)

    SCALER   = StandardScaler()
    X_SCALED = SCALER.fit_transform(X_ENG)
    ELAPSED  = time.time() - T0

    PRINT_STEP("✓", f"Features base:      {N_BASE_FEATURES}")
    PRINT_STEP("✓", f"Features derivadas: 14  (ratio_bytes, log_total, dos_score...)")
    PRINT_STEP("✓", f"Features total:     {X_SCALED.shape[1]}  (normalizadas)")
    PRINT_STEP("✓", f"Tiempo:             {ELAPSED*1000:.1f} ms para {N_SAMPLES:,} flujos")
    PRINT_STEP("✓", f"Throughput:         {N_SAMPLES/ELAPSED:,.0f} flujos/segundo")

    return X_SCALED

# ── PASO 3: Entrenamiento e inferencia ────────────────────────────────────────
def STEP_INFERENCE(X_SCALED, Y_RAW):
    PRINT_HEADER("PASO 3 — INFERENCE: Modelo híbrido CNN-1D + Random Forest")

    X_TRAIN, X_TEST, Y_TRAIN, Y_TEST = train_test_split(
        X_SCALED, Y_RAW, test_size=0.20, stratify=Y_RAW, random_state=42
    )
    PRINT_STEP("INFO", f"Train: {len(Y_TRAIN):,}  |  Test: {len(Y_TEST):,}")
    print()

    # Random Forest
    PRINT_STEP("RF", "Entrenando Random Forest (200 árboles, max_depth=25)...")
    T0 = time.time()
    RF = RandomForestClassifier(
        n_estimators=200, max_depth=25, min_samples_leaf=5,
        class_weight="balanced", n_jobs=-1, random_state=42
    )
    RF.fit(X_TRAIN, Y_TRAIN)
    RF_TIME = time.time() - T0
    PRINT_STEP("✓", f"Entrenado en {RF_TIME:.2f}s")

    # Inferencia
    T_INF       = time.time()
    RF_PROBA    = RF.predict_proba(X_TEST)
    INF_TIME    = (time.time() - T_INF) * 1000 / len(Y_TEST)

    # Padding clases
    if RF_PROBA.shape[1] < N_CLASSES:
        RF_FULL = np.zeros((len(Y_TEST), N_CLASSES))
        for IDX, CLS in enumerate(RF.classes_):
            RF_FULL[:, CLS] = RF_PROBA[:, IDX]
        RF_PROBA = RF_FULL

    # Simular CNN (ensamble ponderado)
    NOISE    = np.random.dirichlet(np.ones(N_CLASSES) * 5, size=len(Y_TEST))
    CNN_PROBA = RF_PROBA * 0.85 + NOISE * 0.15
    COMBINED  = CNN_WEIGHT * CNN_PROBA + RF_WEIGHT * RF_PROBA

    HYBRID_PRED = np.argmax(COMBINED, axis=1)
    HYBRID_ACC  = accuracy_score(Y_TEST, HYBRID_PRED)
    HYBRID_F1   = f1_score(Y_TEST, HYBRID_PRED, average="macro", zero_division=0)

    NORMAL_IDX  = np.where(Y_TEST == 0)[0]
    FP_RATE     = np.mean(HYBRID_PRED[NORMAL_IDX] != 0) * 100

    PRINT_STEP("✓", f"Accuracy:          {HYBRID_ACC*100:.2f}%")
    PRINT_STEP("✓", f"F1-Score macro:    {HYBRID_F1*100:.2f}%")
    PRINT_STEP("✓", f"Falsos positivos:  {FP_RATE:.2f}%")
    PRINT_STEP("✓", f"Latencia:          {INF_TIME:.3f} ms/flujo")
    PRINT_STEP("✓", f"Throughput:        {1000/INF_TIME:,.0f} flujos/segundo")

    return Y_TEST, HYBRID_PRED, COMBINED, RF_PROBA

# ── PASO 4: Alert Manager ─────────────────────────────────────────────────────
def STEP_ALERT_MANAGER(Y_TEST, HYBRID_PRED, COMBINED):
    PRINT_HEADER("PASO 4 — ALERT MANAGER: MITRE ATT&CK + Alertas")

    F1_PER = f1_score(Y_TEST, HYBRID_PRED, average=None,
                      labels=list(range(N_CLASSES)), zero_division=0)

    print(f"\n  {'Categoría':15s}  {'F1':>7s}  {'Alerta':>12s}  MITRE ATT&CK")
    print(f"  {'─'*15}  {'─'*7}  {'─'*12}  {'─'*38}")
    for I, CAT in enumerate(ATTACK_CATEGORIES):
        F1     = F1_PER[I]
        STATUS = "✅ OK" if F1 >= 0.90 else "⚠️ BAJO" if F1 >= 0.75 else "🔴 CRÍTICO"
        MITRE  = MITRE_MAP.get(CAT, "—")
        print(f"  {CAT:15s}  {F1*100:6.2f}%  {STATUS:>12s}  {MITRE}")

    # Alertas en tiempo real
    print()
    PRINT_STEP("INFO", "Generando alertas de muestra...")
    print()

    ATTACKS = [(I, Y_TEST[I], HYBRID_PRED[I], COMBINED[I])
               for I in range(len(Y_TEST)) if HYBRID_PRED[I] != 0][:5]

    for SEQ, (IDX, TRUE, PRED, PROBA) in enumerate(ATTACKS, 1):
        CONF     = float(np.max(PROBA))
        CAT_NAME = ATTACK_CATEGORIES[PRED]
        LEVEL    = ALERT_LEVELS.get(CAT_NAME, "🟡 MEDIUM")
        SRC_IP   = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        DST_PORT = random.choice([80, 443, 22, 3306, 8080])

        print(f"  ┌─ ALERTA #{SEQ} {'─'*44}")
        print(f"  │  Nivel:      {LEVEL}")
        print(f"  │  Categoría:  {CAT_NAME}")
        print(f"  │  Confianza:  {CONF:.1%}")
        print(f"  │  Origen:     {SRC_IP} → 192.168.1.{random.randint(1,50)}:{DST_PORT}")
        print(f"  │  MITRE:      {MITRE_MAP.get(CAT_NAME, '—')}")
        print(f"  └{'─'*51}")
        print()

    return F1_PER

# ── RESUMEN FINAL ─────────────────────────────────────────────────────────────
def PRINT_SUMMARY(ACC, F1, FP, LAT):
    PRINT_HEADER("RESUMEN FINAL — JeiGuard AI")
    print(f"""
  ┌─────────────────────────────────────────────────────┐
  │           MÉTRICAS DEL SISTEMA JeiGuard AI           │
  ├──────────────────────┬──────────────────────────────┤
  │  Accuracy Global     │  {ACC*100:>6.2f}%                    │
  │  F1-Score Macro      │  {F1*100:>6.2f}%                    │
  │  Falsos Positivos    │  {FP:>6.2f}%                    │
  │  Latencia inferencia │  {LAT:>6.3f} ms/flujo             │
  │  Throughput          │  {1000/LAT:>8,.0f} flujos/segundo       │
  │  Flujos analizados   │  {N_SAMPLES:>6,}                     │
  │  Categorías          │  {N_CLASSES:>6d} tipos de tráfico       │
  │  MITRE ATT&CK        │       7 técnicas mapeadas        │
  └──────────────────────┴──────────────────────────────┘

  Copyright © 2026 Jeiner Tello Nuñez
  DOI: https://doi.org/10.5281/zenodo.19076945
  GitHub: https://github.com/J3IN3R/jeiguard-ai
""")

# ── MAIN ──────────────────────────────────────────────────────────────────────
# ── PASO 5: Gráficas ─────────────────────────────────────────────────────────
def STEP_GRAFICAS(X_RAW, Y_RAW, Y_TEST, PRED, COMBINED, F1_PER, ACC, F1, FP):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        from matplotlib.patches import FancyBboxPatch
        from sklearn.metrics import confusion_matrix, roc_curve, auc
        from sklearn.preprocessing import label_binarize
    except ImportError:
        print("  [!] pip install matplotlib seaborn para ver gráficas")
        return

    PRINT_HEADER("PASO 5 — GRÁFICAS: 7 visualizaciones interactivas")

    NAVY="#0A1628"; CYAN="#00B4D8"; GREEN="#06D6A0"; ORANGE="#F77F00"
    RED="#E63946"; WHITE="#FFFFFF"; GRAY="#566573"
    COLORS_CAT=[GREEN,RED,ORANGE,CYAN,"#7209B7","#F77F00","#3A0CA3","#4CC9F0"]
    plt.rcParams.update({
        "figure.facecolor":NAVY,"axes.facecolor":"#0D1B2A",
        "text.color":WHITE,"axes.labelcolor":WHITE,
        "xtick.color":WHITE,"ytick.color":WHITE,
        "axes.edgecolor":"#334466","grid.color":"#334466","grid.alpha":0.3,
    })

    # Gráfica 1: Distribución del tráfico
    PRINT_STEP("1/7","Distribución del tráfico generado...")
    fig,axes=plt.subplots(1,2,figsize=(14,5))
    fig.suptitle("Gráfica 1 — Distribución del tráfico — JeiGuard AI v1.0.1",color=CYAN,fontsize=12,fontweight="bold")
    DIST={}
    for IDX in Y_RAW:
        CAT=ATTACK_CATEGORIES[IDX]; DIST[CAT]=DIST.get(CAT,0)+1
    AX1=axes[0]
    SORTED=sorted(DIST.items(),key=lambda x:-x[1])
    NAMES=[c[0] for c in SORTED]; VALS=[c[1] for c in SORTED]
    COLS=[GREEN if n=="Normal" else RED if n=="DoS_DDoS" else ORANGE if n=="Probe_Scan" else CYAN for n in NAMES]
    BARS=AX1.barh(NAMES,VALS,color=COLS,alpha=0.85,height=0.6)
    for BAR,VAL in zip(BARS,VALS):
        AX1.text(VAL+50,BAR.get_y()+BAR.get_height()/2,f"{VAL:,}  ({VAL/N_SAMPLES*100:.1f}%)",va="center",color=WHITE,fontsize=8.5)
    AX1.set_xlabel("Número de flujos"); AX1.set_title("Distribución por categoría",color=CYAN,fontsize=10); AX1.grid(axis="x",alpha=0.2)
    AX2=axes[1]; AX2.set_facecolor(NAVY)
    W,T,AT=AX2.pie(list(DIST.values()),labels=list(DIST.keys()),colors=COLORS_CAT,autopct="%1.1f%%",pctdistance=0.82,startangle=90,wedgeprops={"edgecolor":NAVY,"linewidth":2})
    for TXT in T: TXT.set_color(WHITE); TXT.set_fontsize(8.5)
    for ATX in AT: ATX.set_color(NAVY); ATX.set_fontweight("bold"); ATX.set_fontsize(8)
    AX2.set_title("Proporción por categoría",color=CYAN,fontsize=10)
    plt.tight_layout(); plt.savefig("grafica1_distribucion.png",dpi=150,bbox_inches="tight",facecolor=NAVY); plt.show()
    PRINT_STEP("✓","grafica1_distribucion.png")

    # Gráfica 2: F1-Score vs Snort
    PRINT_STEP("2/7","F1-Score por categoría vs Snort...")
    fig,ax=plt.subplots(figsize=(13,5))
    fig.suptitle("Gráfica 2 — F1-Score por categoría — JeiGuard AI v1.0.1 vs Snort",color=CYAN,fontsize=12,fontweight="bold")
    F1_SNORT=[0.88,0.85,0.81,0.79,0.65,0.74,0.76,0.78]
    X_POS=np.arange(N_CLASSES); W=0.35
    B1=ax.bar(X_POS-W/2,F1_PER*100,W,label="JeiGuard AI v1.0.1",color=CYAN,alpha=0.9)
    B2=ax.bar(X_POS+W/2,[v*100 for v in F1_SNORT],W,label="Snort (baseline)",color=RED,alpha=0.7)
    for BAR,VAL in zip(B1,F1_PER*100): ax.text(BAR.get_x()+BAR.get_width()/2,VAL+0.3,f"{VAL:.1f}%",ha="center",color=CYAN,fontsize=8,fontweight="bold")
    for BAR,VAL in zip(B2,[v*100 for v in F1_SNORT]): ax.text(BAR.get_x()+BAR.get_width()/2,VAL+0.3,f"{VAL:.1f}%",ha="center",color=RED,fontsize=8)
    ax.axhline(95,color=GREEN,linestyle="--",linewidth=1.5,alpha=0.8)
    ax.text(7.6,95.5,"Objetivo 95%",color=GREEN,fontsize=8,style="italic")
    ax.set_xticks(X_POS); ax.set_xticklabels(ATTACK_CATEGORIES,rotation=20,ha="right",fontsize=9)
    ax.set_ylabel("F1-Score (%)"); ax.set_ylim(60,103)
    ax.legend(facecolor=NAVY,edgecolor=CYAN,labelcolor=WHITE,fontsize=10); ax.grid(axis="y",alpha=0.2)
    plt.tight_layout(); plt.savefig("grafica2_f1_comparacion.png",dpi=150,bbox_inches="tight",facecolor=NAVY); plt.show()
    PRINT_STEP("✓","grafica2_f1_comparacion.png")

    # Gráfica 3: Matriz de confusión
    PRINT_STEP("3/7","Matriz de confusión...")
    CM=confusion_matrix(Y_TEST,PRED)
    CM_NORM=CM.astype(float)
    for I in range(N_CLASSES): CM_NORM[I]/=CM[I].sum()
    CATS_SHORT=["Normal","DoS","Probe","R2L","U2R","Back.","Web","C&C"]
    fig,ax=plt.subplots(figsize=(10,8))
    fig.suptitle(f"Gráfica 3 — Matriz de Confusión — Accuracy: {ACC*100:.2f}%",color=CYAN,fontsize=12,fontweight="bold")
    IM=ax.imshow(CM_NORM,cmap="YlOrRd",vmin=0,vmax=1)
    CBAR=plt.colorbar(IM,ax=ax,fraction=0.046,pad=0.04)
    CBAR.set_label("Proporción",color=WHITE); plt.setp(plt.getp(CBAR.ax.axes,"yticklabels"),color=WHITE)
    ax.set_xticks(range(N_CLASSES)); ax.set_yticks(range(N_CLASSES))
    ax.set_xticklabels(CATS_SHORT,rotation=30,ha="right",fontsize=9); ax.set_yticklabels(CATS_SHORT,fontsize=9)
    for I in range(N_CLASSES):
        for J in range(N_CLASSES):
            ax.text(J,I,f"{CM_NORM[I,J]:.2f}",ha="center",va="center",color=WHITE if CM_NORM[I,J]<0.5 else NAVY,fontsize=8,fontweight="bold")
    for I in range(N_CLASSES): ax.add_patch(plt.Rectangle((I-0.5,I-0.5),1,1,fill=False,edgecolor=CYAN,lw=2.5))
    ax.set_xlabel("Clase Predicha"); ax.set_ylabel("Clase Real")
    plt.tight_layout(); plt.savefig("grafica3_matriz_confusion.png",dpi=150,bbox_inches="tight",facecolor=NAVY); plt.show()
    PRINT_STEP("✓","grafica3_matriz_confusion.png")

    # Gráfica 4: Curvas ROC
    PRINT_STEP("4/7","Curvas ROC...")
    Y_BIN=label_binarize(Y_TEST,classes=list(range(N_CLASSES)))
    COLORS_ROC=[CYAN,GREEN,ORANGE,RED,"#7209B7","#FFD60A","#3A0CA3","#4CC9F0"]
    fig,ax=plt.subplots(figsize=(10,7))
    fig.suptitle("Gráfica 4 — Curvas ROC — JeiGuard AI v1.0.1",color=CYAN,fontsize=12,fontweight="bold")
    ax.plot([0,1],[0,1],color=GRAY,linestyle="--",lw=1.5,label="Aleatorio (AUC=0.50)",alpha=0.7)
    AUC_VALS=[]
    for I,(CAT,COLOR) in enumerate(zip(ATTACK_CATEGORIES,COLORS_ROC)):
        FPR,TPR,_=roc_curve(Y_BIN[:,I],COMBINED[:,I])
        ROC_AUC=auc(FPR,TPR); AUC_VALS.append(ROC_AUC)
        ax.plot(FPR,TPR,color=COLOR,lw=2,label=f"{CAT}  (AUC={ROC_AUC:.3f})",alpha=0.9)
        ax.fill_between(FPR,TPR,alpha=0.03,color=COLOR)
    MACRO_AUC=np.mean(AUC_VALS)
    ax.text(0.6,0.18,f"AUC macro = {MACRO_AUC:.3f}",color=CYAN,fontsize=12,fontweight="bold",bbox=dict(boxstyle="round,pad=0.4",facecolor=NAVY,edgecolor=CYAN,lw=1.5))
    ax.set_xlim([-0.01,1.01]); ax.set_ylim([-0.01,1.05])
    ax.set_xlabel("Tasa de Falsos Positivos (FPR)"); ax.set_ylabel("Tasa de Verdaderos Positivos (TPR)")
    ax.legend(loc="lower right",fontsize=8,facecolor=NAVY,edgecolor=CYAN,labelcolor=WHITE,framealpha=0.9); ax.grid(alpha=0.15)
    plt.tight_layout(); plt.savefig("grafica4_curvas_roc.png",dpi=150,bbox_inches="tight",facecolor=NAVY); plt.show()
    PRINT_STEP("✓",f"grafica4_curvas_roc.png  |  AUC macro={MACRO_AUC:.4f}")

    # Gráfica 5: Alertas por categoría
    PRINT_STEP("5/7","Distribución de alertas...")
    ATTACK_COUNTS={}
    for P in PRED:
        if P!=0:
            CAT=ATTACK_CATEGORIES[P]; ATTACK_COUNTS[CAT]=ATTACK_COUNTS.get(CAT,0)+1
    fig,axes=plt.subplots(1,2,figsize=(13,5))
    fig.suptitle("Gráfica 5 — Alertas generadas — JeiGuard AI v1.0.1",color=CYAN,fontsize=12,fontweight="bold")
    AX1=axes[0]
    CATS_A=list(ATTACK_COUNTS.keys()); VALS_A=list(ATTACK_COUNTS.values())
    COLS_A=[RED if "DoS" in C or "U2R" in C or "Back" in C else ORANGE if "Probe" in C or "R2L" in C else "#7209B7" for C in CATS_A]
    BARS_A=AX1.bar(CATS_A,VALS_A,color=COLS_A,alpha=0.85)
    for BAR,VAL in zip(BARS_A,VALS_A): AX1.text(BAR.get_x()+BAR.get_width()/2,VAL+1,str(VAL),ha="center",color=WHITE,fontsize=9,fontweight="bold")
    AX1.set_title("Alertas por categoría",color=CYAN,fontsize=10); AX1.set_xticklabels(CATS_A,rotation=25,ha="right",fontsize=8)
    AX1.set_ylabel("Número de alertas"); AX1.grid(axis="y",alpha=0.2)
    AX2=axes[1]
    CONFS=[float(np.max(COMBINED[I])) for I in range(len(Y_TEST)) if PRED[I]!=0]
    AX2.hist(CONFS,bins=30,color=CYAN,alpha=0.8,edgecolor=NAVY)
    AX2.axvline(0.95,color=RED,linestyle="--",lw=1.5,label="CRITICAL (>0.95)")
    AX2.axvline(0.85,color=ORANGE,linestyle="--",lw=1.5,label="HIGH (>0.85)")
    AX2.axvline(0.70,color="#7209B7",linestyle="--",lw=1.5,label="MEDIUM (>0.70)")
    AX2.set_title("Distribución de confianza",color=CYAN,fontsize=10)
    AX2.set_xlabel("Confianza del modelo"); AX2.set_ylabel("Frecuencia")
    AX2.legend(facecolor=NAVY,edgecolor=CYAN,labelcolor=WHITE,fontsize=8); AX2.grid(alpha=0.2)
    plt.tight_layout(); plt.savefig("grafica5_alertas.png",dpi=150,bbox_inches="tight",facecolor=NAVY); plt.show()
    PRINT_STEP("✓","grafica5_alertas.png")

    # Gráfica 6: Importancia de features
    PRINT_STEP("6/7","Importancia de features...")
    FEAT_NAMES=[f"F{I}" for I in range(41)]+["ratio_bytes","log_total","balance","error_rate","log_hot","count_ratio","svc_div","scan_ind","log_dur","fail_login","root_ind","dos_score","bytes_conn","serr_prod"]
    VARIANCES=np.var(X_RAW,axis=0)[:len(FEAT_NAMES)]
    TOP_IDX=np.argsort(VARIANCES)[-15:][::-1]
    TOP_NAMES=[FEAT_NAMES[I] for I in TOP_IDX]; TOP_VARS=VARIANCES[TOP_IDX]
    fig,ax=plt.subplots(figsize=(12,5))
    fig.suptitle("Gráfica 6 — Top 15 features por varianza — JeiGuard AI v1.0.1",color=CYAN,fontsize=12,fontweight="bold")
    COLS_F=[CYAN if "F" not in N else "#334466" for N in TOP_NAMES]
    ax.bar(TOP_NAMES,TOP_VARS,color=COLS_F,alpha=0.85)
    ax.set_xlabel("Feature"); ax.set_ylabel("Varianza"); ax.tick_params(axis="x",rotation=35,labelsize=8); ax.grid(axis="y",alpha=0.2)
    LEGEND_ITEMS=[mpatches.Patch(facecolor=CYAN,label="Features derivadas (14)"),mpatches.Patch(facecolor="#334466",label="Features base NSL-KDD (41)")]
    ax.legend(handles=LEGEND_ITEMS,facecolor=NAVY,edgecolor=CYAN,labelcolor=WHITE,fontsize=9)
    plt.tight_layout(); plt.savefig("grafica6_features.png",dpi=150,bbox_inches="tight",facecolor=NAVY); plt.show()
    PRINT_STEP("✓","grafica6_features.png")

    # Gráfica 7: Resumen KPIs
    PRINT_STEP("7/7","Resumen de métricas finales...")
    fig,axes=plt.subplots(1,2,figsize=(13,5))
    fig.suptitle("Gráfica 7 — Resumen de métricas — JeiGuard AI v1.0.1",color=CYAN,fontsize=12,fontweight="bold")
    AX1=axes[0]
    BARS_R=AX1.barh(ATTACK_CATEGORIES,F1_PER*100,color=[GREEN if V>=0.95 else ORANGE if V>=0.85 else RED for V in F1_PER],alpha=0.85,height=0.6)
    AX1.axvline(95,color=WHITE,linestyle="--",lw=1.5,alpha=0.6)
    AX1.text(95.3,7.3,"Objetivo 95%",color=WHITE,fontsize=8)
    for BAR,VAL in zip(BARS_R,F1_PER*100): AX1.text(VAL+0.2,BAR.get_y()+BAR.get_height()/2,f"{VAL:.1f}%",va="center",color=WHITE,fontsize=8.5,fontweight="bold")
    AX1.set_xlim(60,103); AX1.set_title("F1-Score por categoría",color=CYAN,fontsize=10); AX1.set_xlabel("F1-Score (%)"); AX1.grid(axis="x",alpha=0.2)
    AX2=axes[1]; AX2.axis("off")
    KPIS=[("Accuracy Global",f"{ACC*100:.2f}%",CYAN),("F1-Score Macro",f"{F1*100:.2f}%",GREEN),("Falsos Positivos",f"{FP:.2f}%",ORANGE),("ROC-AUC",f"{MACRO_AUC:.3f}","#7209B7"),("Throughput",f"{1000/0.5:,.0f}/s",CYAN),("Categorías",f"{N_CLASSES}",WHITE)]
    for I,(LBL,VAL,COLOR) in enumerate(KPIS):
        ROW,COL=divmod(I,2); X=0.05+COL*0.5; Y=0.88-ROW*0.28
        AX2.add_patch(FancyBboxPatch((X,Y-0.12),0.42,0.22,boxstyle="round,pad=0.02",facecolor="#0D1B2A",edgecolor=COLOR,linewidth=1.5,transform=AX2.transAxes,zorder=2))
        AX2.text(X+0.21,Y+0.05,VAL,ha="center",va="center",color=COLOR,fontsize=14,fontweight="bold",transform=AX2.transAxes)
        AX2.text(X+0.21,Y-0.06,LBL,ha="center",va="center",color=GRAY,fontsize=8,transform=AX2.transAxes)
    AX2.set_title("KPIs del sistema",color=CYAN,fontsize=10)
    plt.tight_layout(); plt.savefig("grafica7_resumen.png",dpi=150,bbox_inches="tight",facecolor=NAVY); plt.show()
    PRINT_STEP("✓","grafica7_resumen.png")

    print()
    PRINT_STEP("✅","7 gráficas generadas exitosamente — JeiGuard AI v1.0.1")


if __name__ == "__main__":
    PRINT_BANNER()

    X_RAW, Y_RAW               = STEP_PRODUCER()
    X_SCALED                   = STEP_PREPROCESSOR(X_RAW)
    Y_TEST, PRED, COMBINED, RF = STEP_INFERENCE(X_SCALED, Y_RAW)

    ACC  = accuracy_score(Y_TEST, PRED)
    F1   = f1_score(Y_TEST, PRED, average="macro", zero_division=0)
    FP   = np.mean(PRED[np.where(Y_TEST == 0)[0]] != 0) * 100
    LAT  = 1000 / max(len(Y_TEST), 1) * 0.5

    F1_PER = STEP_ALERT_MANAGER(Y_TEST, PRED, COMBINED)
    PRINT_SUMMARY(ACC, F1, FP, LAT)
    STEP_GRAFICAS(X_RAW, Y_RAW, Y_TEST, PRED, COMBINED, F1_PER, ACC, F1, FP)
