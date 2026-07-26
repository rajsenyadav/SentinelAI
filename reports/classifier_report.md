# SentinelAI — Attack Classification Model Evaluation Report

## 1. Executive Summary

The multi-class Attack Classifier categorizes detected behavioral anomalies into 7 enterprise threat types. Based on empirical comparison across Random Forest, XGBoost, and Extra Trees, **XGBoost** was selected as the primary production engine.

## 2. Algorithm Comparison & Justification

```
        Model  Accuracy  Precision (Weighted)  Recall (Weighted)  F1 Score (Weighted)  Train Time (s)  Inference Time (ms/sample)                        Explainability                      Scalability
      XGBoost    0.9236                0.9310             0.9236               0.9253           0.794                      0.1118 High (SHAP & Tree Feature Importance) Excellent (Parallelized CPU/GPU)
  Extra Trees    0.8935                0.9015             0.8935               0.8725           0.240                      0.0942 High (SHAP & Tree Feature Importance) Excellent (Parallelized CPU/GPU)
Random Forest    0.8403                0.8470             0.8403               0.8234           0.451                      0.0945 High (SHAP & Tree Feature Importance) Excellent (Parallelized CPU/GPU)
```

### Model Selection Rationale:
- **Accuracy & F1 Superiority:** XGBoost achieved top-tier weighted F1 score on temporal test splits.
- **Low Inference Latency:** Sub-millisecond inference per sample makes it suitable for real-time SIEM/SOAR log pipelines.
- **Feature Attribution:** Tree-based split gain metrics map directly to SHAP explainability in Module 6.

## 3. Detailed Performance Evaluation

```

============================================================
SENTINELAI — ATTACK CLASSIFICATION EVALUATION REPORT
============================================================
Overall Accuracy:       0.9120
Weighted F1-Score:      0.9135
Macro F1-Score:         0.8819

--- PER-CLASS PERFORMANCE ---
                       precision    recall  f1-score   support

          brute_force       1.00      0.80      0.89         5
  credential_stuffing       0.67      1.00      0.80         2
      device_spoofing       0.74      0.85      0.79        53
    impossible_travel       0.88      1.00      0.94        58
        insider_drift       0.99      0.87      0.93       183
     lateral_movement       0.96      0.98      0.97        92
low_slow_exfiltration       0.83      0.90      0.86        39

             accuracy                           0.91       432
            macro avg       0.87      0.91      0.88       432
         weighted avg       0.92      0.91      0.91       432


--- CONFUSION MATRIX ---
                       brute_force  credential_stuffing  device_spoofing  impossible_travel  insider_drift  lateral_movement  low_slow_exfiltration
brute_force                      4                    1                0                  0              0                 0                      0
credential_stuffing              0                    2                0                  0              0                 0                      0
device_spoofing                  0                    0               45                  5              2                 0                      1
impossible_travel                0                    0                0                 58              0                 0                      0
insider_drift                    0                    0               16                  3            160                 0                      4
lateral_movement                 0                    0                0                  0              0                90                      2
low_slow_exfiltration            0                    0                0                  0              0                 4                     35

--- TOP FEATURE IMPORTANCES ---
                  Feature  Importance
        command_diversity    0.250349
      unique_resources_1h    0.091889
            command_count    0.081249
      suspicious_cmd_flag    0.065641
     unique_resources_24h    0.048555
      action_type_encoded    0.047673
         bytes_per_second    0.044531
        bytes_transferred    0.040470
         session_duration    0.036089
resource_category_encoded    0.033014
============================================================
```

## 4. Sample SOC JSON Output

```json
{
  "attack_type": "Low & Slow Exfiltration",
  "confidence": 0.608,
  "severity": "Critical",
  "top_features": [
    "unique_resources_1h",
    "unique_resources_24h",
    "command_diversity"
  ]
}
```

## 5. Strengths, Weaknesses & Future Improvements

### Strengths:
- **High Multi-Class Discrimination:** Near-perfect separation between distinct attack signatures (e.g. Brute Force vs Impossible Travel).
- **Interpretable Output:** Provides confidence scores, severity tiers, and top contributing feature names.

### Weaknesses:
- **Insider Drift Ambiguity:** Insider drift exhibits subtle boundary overlap with normal behavioral shifts.

### Future Improvements:
- Implement sequential recurrent modeling (LSTM/GRU or Temporal Transformers) for long-term behavioral trajectories.
