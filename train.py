"""
train.py – Build and save model, columns, options, and test_results.

Run this script whenever the model needs to be rebuilt (e.g. after a Python
version change that makes the existing .pkl files unloadable).

Usage:
    python train.py
"""

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

BASE_DIR = Path(__file__).parent
MODEL_DIR = BASE_DIR / "model"
DATA_DIR = BASE_DIR / "data" / "raw"

TEXT_COLUMNS = ["protocol_type", "service", "flag"]

# NSL-KDD has 43 columns; the last two are label and difficulty score.
ALL_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]

FEATURE_COLUMNS = [c for c in ALL_COLUMNS if c not in ("label", "difficulty")]

# NSL-KDD attack-category mapping
ATTACK_MAP = {
    "normal": "Normal",
    # DOS
    "back": "DOS", "land": "DOS", "neptune": "DOS", "pod": "DOS",
    "smurf": "DOS", "teardrop": "DOS", "apache2": "DOS", "udpstorm": "DOS",
    "processtable": "DOS", "worm": "DOS", "mailbomb": "DOS",
    # PROBE
    "satan": "PROBE", "ipsweep": "PROBE", "nmap": "PROBE",
    "portsweep": "PROBE", "mscan": "PROBE", "saint": "PROBE",
    # R2L
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L",
    "phf": "R2L", "multihop": "R2L", "warezmaster": "R2L",
    "warezclient": "R2L", "spy": "R2L", "xlock": "R2L", "xsnoop": "R2L",
    "snmpguess": "R2L", "snmpgetattack": "R2L", "httptunnel": "R2L",
    "sendmail": "R2L", "named": "R2L",
    # U2R
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R",
    "perl": "U2R", "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
}

CLASSES = ["Normal", "DOS", "PROBE", "R2L", "U2R"]


def load_kdd(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=ALL_COLUMNS)
    df["label"] = df["label"].str.rstrip(".").str.lower().map(ATTACK_MAP)
    df = df.dropna(subset=["label"])
    return df


def build_pipeline(feature_columns):
    num_cols = [c for c in feature_columns if c not in TEXT_COLUMNS]
    pre = ColumnTransformer(transformers=[
        ("text", OneHotEncoder(handle_unknown="ignore"), TEXT_COLUMNS),
        ("num", StandardScaler(), num_cols),
    ])
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    return Pipeline(steps=[("pre", pre), ("model", clf)])


def main():
    print("Loading training data …")
    train_df = load_kdd(DATA_DIR / "KDDTrain+.txt")
    test_df = load_kdd(DATA_DIR / "KDDTest+.txt")

    X_train = train_df[FEATURE_COLUMNS]
    y_train = train_df["label"]
    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["label"]

    print(f"  Train rows: {len(X_train):,}  |  Test rows: {len(X_test):,}")

    print("Training model …")
    pipeline = build_pipeline(FEATURE_COLUMNS)
    pipeline.fit(X_train, y_train)

    # Evaluate on test set
    train_labels = set(y_train.unique())
    seen_mask = X_test["service"].isin(
        X_train["service"].unique()
    ) & X_test["flag"].isin(X_train["flag"].unique())

    y_pred = pipeline.predict(X_test)
    cm = confusion_matrix(y_test, y_pred, labels=CLASSES).tolist()

    seen_correct = (y_pred[seen_mask] == y_test[seen_mask]).mean()
    unseen_correct = (y_pred[~seen_mask] == y_test[~seen_mask]).mean() if (~seen_mask).any() else 0.0

    test_results = {
        "classes": CLASSES,
        "confusion_matrix": cm,
        "seen_vs_unseen": {
            "Seen in training": {
                "rows": int(seen_mask.sum()),
                "correct_rate": round(float(seen_correct), 3),
            },
            "Never seen in training": {
                "rows": int((~seen_mask).sum()),
                "correct_rate": round(float(unseen_correct), 3),
            },
        },
    }

    # Build options dict for dropdowns
    options = {col: sorted(train_df[col].unique().tolist()) for col in TEXT_COLUMNS}

    # Save artefacts
    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR / "model.pkl", "wb") as f:
        pickle.dump(pipeline, f)
    with open(MODEL_DIR / "columns.pkl", "wb") as f:
        pickle.dump(FEATURE_COLUMNS, f)
    with open(MODEL_DIR / "options.json", "w") as f:
        json.dump(options, f)
    with open(MODEL_DIR / "test_results.json", "w") as f:
        json.dump(test_results, f, indent=2)

    print("Saved model/model.pkl, model/columns.pkl, model/options.json, model/test_results.json")
    acc = (np.array(y_pred) == np.array(y_test)).mean()
    print(f"Overall test accuracy: {acc:.3%}")


if __name__ == "__main__":
    main()
