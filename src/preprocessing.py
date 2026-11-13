import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split

from sklearn.preprocessing import (
    StandardScaler,
    LabelEncoder
)
from pathlib import Path
from sklearn.impute import SimpleImputer

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "combined_shuffled.parquet"
)

df = pd.read_parquet(DATA_PATH)


