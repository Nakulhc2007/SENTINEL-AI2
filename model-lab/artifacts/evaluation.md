# Synthetic holdout results

Model: **Random Forest with 25 CART trees**, trained with Gini impurity. The synthetic generator seed is `20261030`. Split: 80% training and 20% holdout, stratified by domain and target class.

| Measure | Holdout result |
|---|---:|
| Records tested | 1,288 |
| Accuracy | 98.84% |
| Precision | 100.00% |
| Recall | 96.59% |
| F1 score | 98.27% |
| ROC AUC | 99.97% |
| False positives | 0 |
| False negatives | 15 |

## Recall by domain

| Domain | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Banking | 98.76% | 100.00% | 96.36% | 98.15% |
| Healthcare | 98.14% | 100.00% | 94.55% | 97.20% |
| Education | 98.14% | 100.00% | 94.55% | 97.20% |
| Government | 99.38% | 100.00% | 98.18% | 99.08% |
| Corporate | 98.76% | 100.00% | 96.36% | 98.15% |
| Manufacturing | 98.76% | 100.00% | 96.36% | 98.15% |
| Retail | 99.38% | 100.00% | 98.18% | 99.08% |
| Public Services | 99.38% | 100.00% | 98.18% | 99.08% |

These are results on a held-out slice from the **same synthetic generator** used to create training records. The generator determines the labels and injects many of the features the model learns. The scores therefore describe performance on these generated scenarios only; they do not demonstrate real-world accuracy or readiness for live incident response. In particular, zero false positives here should not be interpreted as a guarantee. Test on independently authored scenarios and authorized real data before drawing operational conclusions.
