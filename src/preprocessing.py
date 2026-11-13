import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split

from sklearn.preprocessing import (
    StandardScaler,
    LabelEncoder
)
from pathlib import Path
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer

from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

PROJECT_ROOT = Path.cwd().parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "combined_shuffled.parquet"
)

PROCESSED_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
)

df = pd.read_parquet(DATA_PATH)

df.columns = df.columns.str.strip()

drop_exact_cols = [
    'Fwd Segment Size Avg',
    'Bwd Segment Size Avg',
    'URG Flag Count',
    'Average Packet Size',
    'Attempted Category',
    'Src IP dec',
    'Src Port',
    'ICMP Code',
    'ICMP Type',
    'Timestamp', 
    'Dst IP dec', 
    'Packet Length Variance'
]

drop_calc_cols = [
    'Flow Packets/s',
    'Flow Bytes/s',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Down/Up Ratio',
    'Total TCP Flow Time'
]

drop_const_cols = [
    'Bwd URG Flags',
    'Fwd URG Flags',
    'Source_File'
    
]

droped = drop_exact_cols + drop_calc_cols + drop_const_cols
df.drop(columns=droped, inplace=True)

feat = [col for col in df.columns if col != "Label"]
df = df.drop_duplicates(subset=feat, ignore_index=True)

df['Bin Label'] = np.where(df['Label'] == 'BENIGN', 'BENIGN', 'ATTACK')

for col in ["Fwd Header Length", "Bwd Header Length"]:
    df.loc[df[col] < 0, col] = np.nan

def to_attack_type(label: str) -> str:
    if label == "BENIGN":
        return "BENIGN"
    if "Attempted" in label:
        return "ATTEMPTED"
    if label.startswith("Web Attack"):
        return "Web Attack"
    if label in ("Portscan", "Infiltration - Portscan"):
        return "PortScan"
    if label in ("Infiltration", "Heartbleed"):
        return "Other"
    return label

df["Attack Type"] = df["Label"].map(to_attack_type)

attempted = df[df["Attack Type"] == "ATTEMPTED"]
attempted.to_parquet(PROCESSED_DIR / "attempted.parquet", index=False)

df_v1 = df[df["Attack Type"] != "ATTEMPTED"]

nan_cnt = df_v1.isna().sum()
print(nan_cnt[nan_cnt > 0])
print("shape:", df_v1.shape)

idx_train, idx_tmp = train_test_split(
    df_v1.index, test_size=0.30,
    stratify=df_v1["Attack Type"], random_state=42
)
idx_val, idx_test = train_test_split(
    idx_tmp, test_size=0.50,
    stratify=df_v1.loc[idx_tmp, "Attack Type"], random_state=42
)

train, val, test = df_v1.loc[idx_train], df_v1.loc[idx_val], df_v1.loc[idx_test]

print(pd.concat({"train": train["Attack Type"].value_counts(),
                 "val":   val["Attack Type"].value_counts(),
                 "test":  test["Attack Type"].value_counts()}, axis=1))

targets = ["Label", "Attack Type", "Bin Label"]

X_train = train.drop(columns=targets)
X_val   = val.drop(columns=targets)
X_test  = test.drop(columns=targets)

y_train = train[targets].copy()
y_val   = val[targets].copy()
y_test  = test[targets].copy()

cat_cols = df_v1.select_dtypes(exclude='number').columns
for col in cat_cols:
    print(f"\n######## {col} ########")
    print(f"{df_v1[col].value_counts(dropna=False)}\n")

sets = [y_train, y_val, y_test]
le = LabelEncoder()

for st in sets:
    st['Bin Label'] = st['Bin Label'].map({
        'BENIGN': 0,
        'ATTACK': 1
    })
    
y_train['Attack Type'] = le.fit_transform(y_train['Attack Type'])
y_val['Attack Type'] = le.transform(y_val['Attack Type'])
y_test['Attack Type'] = le.transform(y_test['Attack Type'])

le_mapping = dict(zip(le.classes_, le.transform(le.classes_)))
le_mapping

sample_size = min(300000, len(X_train))
X_sample = X_train.sample(sample_size, random_state=42)
y_sample = y_train.loc[X_sample.index, "Attack Type"]

model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
model.fit(X_sample, y_sample)

importances = pd.Series(model.feature_importances_, index=X_sample.columns)

top_features = importances.sort_values(ascending=False).head(20)

final_selected_features = importances[importances > 0.005].index.tolist()
X_train_selected = X_train[final_selected_features]
X_val_selected = X_val[final_selected_features]
X_test_selected = X_test[final_selected_features]

print(f"Original Features: {X_train.shape[1]}")
print(f"Selected Features: {X_train_selected.shape[1]}")
print(f"Removed Features: {X_train.shape[1] - X_train_selected.shape[1]}\n")
print(top_features)

top_features.plot(kind='barh', figsize=(10, 6))
plt.title("Top 20 Important Features")
plt.show()

if 'Fwd Header Length' in X_train_selected.columns:
    X_train_selected[X_train_selected['Fwd Header Length'].isna()]

train_processed = pd.concat(
    [X_train_selected, y_train],
    axis=1
)

val_processed = pd.concat(
    [X_val_selected, y_val],
    axis=1
)

test_processed = pd.concat(
    [X_test_selected, y_test],
    axis=1
)

train_processed.to_parquet(
    PROCESSED_DIR / "train.parquet",
    index=False
)

val_processed.to_parquet(
    PROCESSED_DIR / "validation.parquet",
    index=False
)

test_processed.to_parquet(
    PROCESSED_DIR / "test.parquet",
    index=False
)
