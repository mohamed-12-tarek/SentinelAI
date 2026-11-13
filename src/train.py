import pandas as pd 
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from pathlib import Path

PROJECT_ROOT = Path.cwd().parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"

MODELS_DIR.mkdir(parents=True, exist_ok=True)

train_df = pd.read_parquet(PROCESSED_DIR / "train.parquet")
val_df = pd.read_parquet(PROCESSED_DIR / "validation.parquet")
test_df = pd.read_parquet(PROCESSED_DIR / "test.parquet")

TARGETS = ['Label', 'Bin Label', 'Attack Type']
FEATURES = [col for col in train_df if col not in TARGETS]

X_train_normal = train_df.loc[train_df['Bin Label'] == 0, FEATURES]
X_val = val_df[FEATURES]
attack_train = train_df[train_df['Bin Label'] == 1]

X_train_attack = attack_train[FEATURES]
y_train_attack = attack_train['Attack Type']

anomaly_pipeline = Pipeline([
    (
        'Preprocessor',
        ColumnTransformer(
            [
                ('numeric', SimpleImputer(strategy='median'), FEATURES)
            ]
        )
    ),
    
    (
        'detector',
        IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42, 
            n_jobs=-1
        )
    )
])

anomaly_pipeline.fit(X_train_normal)
score_val = anomaly_pipeline.decision_function(X_val)

print(score_val)

attack_pipeline = Pipeline([
    (
        'Preprocessor',
        ColumnTransformer(
            [
                ('numeric', SimpleImputer(strategy='median'), FEATURES)
            ]
        )
    ),

    (
        'classifier',
        RandomForestClassifier(
            n_estimators=300,
            max_depth=8,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced_subsample'
        )
    )
])

attack_pipeline.fit(X_train_attack, y_train_attack)

def detect_and_classify(network_flows):
    missing_features = [
        feature for feature in FEATURES
        if feature not in network_flows.columns
    ]
    
    if missing_features:
        raise ValueError(f"Missing Features {missing_features}")
    
    if network_flows.empty:
        return pd.DataFrame(columns=['status', 'attack_type'], index=network_flows.index)
    
    X = network_flows[FEATURES]
    anomaly_pred = anomaly_pipeline.predict(X)
    
    is_anomaly = anomaly_pred == -1
    
    res = pd.DataFrame({
        'status': 'BENIGN',
        'attack_type': None
    }, index=network_flows.index)
    
    if is_anomaly.any():
        X_anomalies = X.iloc[is_anomaly]
        pred_attack_type = attack_pipeline.predict(X_anomalies)
        
        res.loc[is_anomaly, "status"] = 'ANOMALY'
        res.loc[is_anomaly, "attack_type"] = pred_attack_type
        
    return res

model_bundle = {
    "anomaly_pipeline": anomaly_pipeline,
    "attack_pipeline": attack_pipeline,
    "features": FEATURES
}

joblib.dump(
    model_bundle,
    MODELS_DIR / "SentinelAi_model.joblib"
)
