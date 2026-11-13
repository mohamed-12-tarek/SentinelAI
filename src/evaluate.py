import pandas as pd
import numpy as np
from pathlib import Path
import joblib

from train import detect_and_classify
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)
import matplotlib.pyplot as plt

PROJECT_ROOT = Path.cwd().parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"

model_bundle = joblib.load(
    MODELS_DIR / "SentinelAi_model.joblib"
)

anomaly_pipeline = model_bundle["anomaly_pipeline"]
attack_pipeline = model_bundle["attack_pipeline"]
FEATURES = model_bundle['features']

test_df = pd.read_parquet(PROCESSED_DIR / "test.parquet")

X_test = test_df[FEATURES]

y_train_binary = test_df['Bin Label']
if_pred = anomaly_pipeline.predict(X_test)

y_pred_binary = np.where(if_pred == -1, 1, 0)

print("ISOLATION FOREST RESULTS\n")
print(f"Accuracy Score: {accuracy_score(y_train_binary, y_pred_binary)}")
print(f"Precision Score: {precision_score(y_train_binary, y_pred_binary, zero_division=0)}")
print(f"Recall Score: {recall_score(y_train_binary, y_pred_binary, zero_division=0)}")
print(f"F1 Score: {f1_score(y_train_binary, y_pred_binary, zero_division=0)}\n")
report_binary = classification_report(
    y_train_binary, 
    y_pred_binary,
    target_names=['BENIGN', 'ATTACK'],
    zero_division=0
    )
print(f"Classification Report: {report_binary}")

attack_test = test_df[
    test_df["Bin Label"] == 1
]

X_test_attack = attack_test[FEATURES]
y_test_attack = attack_test["Attack Type"]

rf_predictions = attack_pipeline.predict(
    X_test_attack
)

print("Random Forest Results\n")

print(
    classification_report(
        y_test_attack,
        rf_predictions,
        zero_division=0
    )
)

cm = confusion_matrix(
    y_test_attack,
    rf_predictions,
    labels=attack_pipeline.classes_
)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=attack_pipeline.classes_
)

disp.plot(
    cmap="Blues",
    xticks_rotation=90,
    values_format="d"
)

plt.title("Random Forest - Attack Classification")
plt.tight_layout()
plt.show()

results = detect_and_classify(test_df)

y_true = test_df["Bin Label"].astype(int)

y_pred = (results["status"] == "ANOMALY").astype(int)

print("SENTINELAI END-TO-END RESULTS")

print("Accuracy:", accuracy_score(y_true, y_pred))

print(classification_report(
    y_true,
    y_pred,
    target_names=["BENIGN", "ATTACK"]
))

cm = confusion_matrix(y_true, y_pred)

ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["BENIGN", "ATTACK"]
).plot(cmap="Blues", values_format="d")

plt.title("SentinelAI End-to-End Confusion Matrix")
plt.show()
