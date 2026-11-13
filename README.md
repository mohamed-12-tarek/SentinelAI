# 🛡️ SentinelAI — Network Intrusion Detection System

**An AI-powered network intrusion detection system for identifying malicious network traffic and classifying cyberattacks using Machine Learning.**

## 📌 Project Overview

SentinelAI is a Machine Learning-based Network Intrusion Detection System (NIDS) designed to analyze network traffic and detect potentially malicious activities.

The project uses the **CICIDS-2017 dataset** to train supervised Machine Learning models capable of distinguishing between legitimate network traffic and malicious traffic, then identifying the specific attack category.

The main goal is to build a reliable and structured intrusion detection pipeline that can recognize different types of network attacks based on network flow features.

## 🎯 Project Objectives

- Detect malicious network traffic.
- Distinguish between benign and malicious network flows.
- Classify detected attacks into their corresponding categories.
- Analyze network traffic characteristics and identify important features.
- Evaluate Machine Learning models using appropriate classification metrics.
- Build a modular and reproducible ML pipeline.

## 🏗️ System Architecture

SentinelAI follows a **Two-Stage Supervised Classification Architecture**.

### Stage 1 — Binary Classification

The first model determines whether a network flow is:

- **BENIGN:** Legitimate network traffic.
- **ATTACK:** Potentially malicious network traffic.

### Stage 2 — Multi-Class Classification

If Stage 1 identifies a flow as an attack, the second model predicts its attack category.

Examples include:

- DoS Hulk
- DDoS
- PortScan
- FTP-Patator
- SSH-Patator
- DoS GoldenEye
- Botnet
- Web Attacks
- Infiltration

The final prediction combines the results of both stages.

```text
             Network Flow
                   |
                   ▼
          Stage 1: Binary Model
                   |
             ┌─────┴─────┐
             ▼           ▼
           BENIGN      ATTACK
             |           |
             ▼           ▼
          Benign     Stage 2: Multi-Class
          Traffic         Model
                             |
                             ▼
                      Attack Category
```

## 📊 Dataset

This project uses the **CICIDS-2017 dataset**, a publicly available network intrusion detection dataset developed by the Canadian Institute for Cybersecurity.

The dataset contains benign traffic and multiple types of network attacks.

### Dataset Files

The project uses five CSV files:

- `Monday.csv`
- `Tuesday.csv`
- `Wednesday.csv`
- `Thursday.csv`
- `Friday.csv`

### Dataset Preparation

The original CSV files are combined into a single dataset using DuckDB.

The processed dataset contains approximately:

- **2,099,971 rows**
- **90 columns**

The combined dataset is stored in Parquet format to improve storage efficiency and data-loading performance.

> The dataset is not included in this repository. Users must obtain CICIDS-2017 from its official source.

Dataset source: [Canadian Institute for Cybersecurity — CICIDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html)

## ⚙️ Data Processing Pipeline

The project follows a structured data preparation workflow:

1. **Data Loading:** Load and combine the original CSV files.
2. **Exploratory Data Analysis (EDA):** Understand feature distributions, class imbalance, missing values, correlations, and outliers.
3. **Data Validation:** Check dataset integrity and target labels.
4. **Data Cleaning:** Handle invalid numerical values and missing data.
5. **Feature Selection:** Remove redundant or unsuitable features based on EDA findings.
6. **Target Engineering:** Create the binary target for Stage 1.
7. **Data Splitting:** Separate training, validation, and testing datasets.
8. **Feature Transformation:** Apply imputation, scaling, and label encoding where appropriate.
9. **Model Training:** Train and evaluate the two classification stages.

**Important:** Preprocessing transformations should be fitted on training data only to prevent data leakage.

## 🧰 Technologies & Tools

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Pandas | Data manipulation |
| NumPy | Numerical operations |
| DuckDB | Efficient data processing |
| PyArrow | Parquet file support |
| Scikit-learn | Preprocessing and ML models |
| Matplotlib | Data visualization |
| Seaborn | Exploratory data analysis |
| Jupyter Notebook | Interactive experimentation |

## 📁 Project Structure

```text
SentinelAI/
│
├── data/
│   ├── raw/
│   │   └── CICIDS-2017 CSV files
│   │
│   └── processed/
│       ├── combined_shuffled.parquet
│       └── eda_sample.parquet
│
├── notebooks/
│   └── EDA notebooks
│
├── src/
│   └── preprocessing.py
│
├── models/
│
├── reports/
│
├── .gitignore
├── requirements.txt
└── README.md
```

*The structure represents the intended project organization; folders and modules may be added as development progresses.*

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/mohamed-12-tarek/SentinelAI.git

cd SentinelAI
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

Activate it:

**Windows:**

```powershell
.venv\Scripts\activate
```

**Linux / macOS:**

```bash
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Prepare the Dataset

Download CICIDS-2017 and place the original CSV files inside:

```text
data/raw/
```

After preparing and combining the dataset, ensure that the processed Parquet file is available at:

```text
data/processed/combined_shuffled.parquet
```

### 5. Run the Preprocessing Script

```bash
python src/preprocessing.py
```

## 📈 Model Evaluation

The models will be evaluated using classification metrics suitable for imbalanced datasets.

Planned evaluation metrics include:

- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix
- Classification Report

Particular attention will be given to **Recall, Precision, and F1-Score**, since detecting malicious traffic while controlling false alarms is important for intrusion detection systems.

## 🔒 Project Scope

SentinelAI currently focuses on **offline network traffic analysis and classification** using historical network flow data.

It is not currently a live network monitoring or packet-capturing system.

## 🛣️ Future Improvements

- Experiment with different Machine Learning algorithms.
- Optimize model performance under class imbalance.
- Perform feature importance analysis.
- Compare different classification approaches.
- Develop an inference pipeline.
- Build an interactive dashboard for displaying detection results.
- Explore deployment options for the trained models.

## 👨‍💻 Author

**Mohamed Tarek**

GitHub: [mohamed-12-tarek](https://github.com/mohamed-12-tarek)

---

<p align="center">
  <b>SentinelAI — Making Network Traffic Intelligence Smarter.</b>
</p>
