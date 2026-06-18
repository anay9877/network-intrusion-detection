# Network Intrusion Detection System (NIDS)
### Machine Learning based Network Traffic Classifier | CICIDS2017

---

## Overview

A machine learning pipeline that classifies network traffic flows into 12 categories — benign or one of 11 attack types — using the CICIDS2017 dataset. Built to simulate real-world SOC (Security Operations Center) tooling, with explainability via SHAP and a risk-based prediction pipeline.

---

## Results

| Metric | Score |
|---|---|
| Macro F1 | 0.894 |
| Weighted F1 | 0.999 |
| Attack classes above 99% recall | 9 / 11 |
| Total flows trained on | 2,217,688 |

### Per-Class Performance

| Attack Type | Recall | Risk Level |
|---|---|---|
| DDoS | 99.97% | CRITICAL |
| DoS Hulk | 99.86% | CRITICAL |
| FTP-Patator | 100.00% | MEDIUM |
| SSH-Patator | 99.53% | MEDIUM |
| DoS GoldenEye | 99.81% | CRITICAL |
| DoS slowloris | 99.35% | HIGH |
| DoS Slowhttptest | 98.95% | HIGH |
| PortScan | 89.26% | MEDIUM |
| Bot | 82.71% | HIGH |
| Web Attack - Brute Force | 67.69% | HIGH |
| Web Attack - XSS | 45.38% | HIGH |

> Web attacks (XSS, Brute Force) show lower recall because flow-level features cannot distinguish HTTP attack payloads from normal web browsing — a known limitation of CICFlowMeter-based detection requiring deep packet inspection for improvement.

---

## Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection Dataset 2017

- 8 CSV files covering different attack scenarios across multiple days
- Original size: 2,830,743 rows, 79 features
- After cleaning: 2,217,688 rows, 47 features
- Attack types: DDoS, DoS variants, PortScan, Brute Force, Web Attacks, Botnet, Infiltration

**Key data quality issues handled:**
- 610,120 duplicate rows removed (21% of raw data)
- 2,867 rows with Infinity values in Flow Bytes/s dropped (divide-by-zero from zero-duration flows)
- Encoding artifacts in label names fixed
- Duplicate column `Fwd Header Length.1` removed

---

## Project Structure

```
nids-ml/
│
├── notebooks/
│   └── NIDS_Complete_Pipeline.ipynb   # Full pipeline notebook
│
├── README.md
└── requirements.txt
```

---

## Pipeline Architecture

```
Raw CSVs (8 files)
      ↓
Merge + Clean (encoding fix, inf/nan, duplicates)
      ↓
Feature Selection (80 → 47 features)
  - Correlation threshold > 0.95 → dropped 22 features
  - Variance threshold < 0.01 → dropped 10 features
      ↓
Feature Engineering
  - payload_ratio_fwd = act_data_pkt_fwd / Total Fwd Packets
  - fwd_bwd_packet_ratio = Total Fwd Packets / Total Backward Packets
      ↓
Train/Test Split (80/20 stratified)
      ↓
RobustScaler (handles outliers in flow features)
      ↓
LightGBM Classifier (class_weight='balanced')
      ↓
Evaluation + SHAP Explainability
      ↓
Risk-based Prediction Pipeline
```

---

## Key Technical Decisions

**Why CICIDS2017 over NSL-KDD:**
NSL-KDD is a 1999-derived dataset with known synthetic artifacts. CICIDS2017 contains modern attack types (DDoS, botnet, web attacks) generated from realistic background traffic using CICFlowMeter — closer to what real SOC tooling produces.

**Why LightGBM over XGBoost:**
LightGBM uses histogram-based boosting requiring 3x less RAM than XGBoost on the same data. Critical for working with 2.2M rows. Comparable accuracy with significantly faster training.

**Why RobustScaler over StandardScaler:**
Network flow features (bytes/s, packet counts) have extreme outliers from attack traffic. RobustScaler uses median and IQR instead of mean and std, making it resilient to these outliers.

**Why class_weight='balanced' over SMOTE:**
With 11-sample minimum classes (Heartbleed), SMOTE generates unrealistic synthetic flows. Class weighting is more statistically honest and directly penalizes the model for missing rare classes during training.

**Why Macro F1 over Accuracy:**
Overall accuracy is 99.9% because BENIGN dominates 85% of the data — predicting everything as BENIGN would give 85% accuracy. Macro F1 weights all 12 classes equally, making it the honest performance metric.

---

## SHAP Explainability

SHAP (SHapley Additive exPlanations) values explain why the model flagged a specific flow as an attack.

**Top features for Bot detection:**
- `Bwd IAT Std` — high variance in server response timing indicates irregular C2 beaconing
- `Init_Win_bytes_forward` — non-standard TCP window sizes used by attack tools
- `Flow IAT Mean` — characteristic inter-arrival timing of automated bot traffic
- `Port_Category` — botnet C2 communication favors dynamic/private ports

**Top features for DDoS/DoS detection:**
- `Flow Bytes/s` — extreme traffic rates
- `Bwd Packet Length Min` — minimal response packets under flood conditions
- `Packet Length Mean` — templated attack packets have characteristic fixed sizes

---

## Feature Engineering

Two derived features engineered from domain knowledge:

```python
# Ratio of packets with actual payload vs total — key scan discriminator
df['payload_ratio_fwd'] = df['act_data_pkt_fwd'] / (df['Total Fwd Packets'] + 1e-6)

# Forward/backward packet asymmetry — flood and scan indicator  
df['fwd_bwd_packet_ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1e-6)
```

Both features appeared in top 10 SHAP importance for multiple attack classes, confirming domain-driven feature engineering adds real signal.

---

## How to Run

### Requirements

```
pandas
numpy
scikit-learn
lightgbm
shap
matplotlib
seaborn
joblib
```

Install with:
```bash
pip install -r requirements.txt
```

### Steps

1. Download CICIDS2017 dataset from [Kaggle](https://www.kaggle.com/datasets/cicdataset/cicids2017)
2. Place all CSV files in the same directory as the notebook
3. Open `NIDS_Complete_Pipeline.ipynb`
4. Run all cells sequentially

> **Note:** Recommended to run on Google Colab with Google Drive mounted for checkpointing. Dataset is ~1.7GB uncompressed.

---

## Limitations and Future Work

- **Web attack recall** — XSS and Brute Force require deep packet inspection (payload analysis) for reliable detection at flow level. A hybrid model combining flow features with HTTP payload parsing would improve recall significantly.
- **Concept drift** — CICIDS2017 is 2017 data. Modern attack patterns (Log4j, supply chain attacks) are not represented. Real deployment requires periodic retraining.
- **Zero-day attacks** — supervised classification cannot detect attack types not seen in training. An Isolation Forest anomaly detection layer would complement this model for novel attack detection.
- **Stacking ensemble** — combining LightGBM with XGBoost and Random Forest via a meta-learner would likely improve macro F1 by 2-3 points, particularly for the weaker web attack classes.

---

## Author

Built as part of a cybersecurity/ML portfolio alongside:
- Credit Risk Scoring (XGBoost, SHAP, AUC-ROC/KS evaluation)
- Stock Price Prediction Ensemble (time series, stacking, technical indicators)
