import json
import pickle
import subprocess
import sys
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).parent
TEXT_COLUMNS = ["protocol_type", "service", "flag"]
MAX_ROWS = 5000

CLASS_INFO = {
    "Normal": {
        "meaning": "Looks like ordinary network traffic.",
        "severity": "None",
        "action": "No action needed, but this does not guarantee the traffic is safe.",
    },
    "DOS": {
        "meaning": "Denial of service: flooding a machine or network so real users cannot use it.",
        "severity": "High",
        "action": "Look for a sudden spike of traffic from one source and consider rate limiting or blocking it.",
    },
    "PROBE": {
        "meaning": "Scanning: someone is checking the network for open ports and weak spots, often before an attack.",
        "severity": "Medium",
        "action": "Find out which addresses are scanning and watch for follow-up attempts.",
    },
    "R2L": {
        "meaning": "Remote to local: an outsider trying to get access to a machine, for example by guessing passwords.",
        "severity": "High",
        "action": "Check failed login attempts and lock or reset the accounts involved.",
    },
    "U2R": {
        "meaning": "User to root: an ordinary user trying to gain administrator (root) powers.",
        "severity": "Critical",
        "action": "Investigate the account and the machine right away.",
    },
}

LIMITATION_NOTICE = (
    "'Normal' does not mean safe. On the official NSL-KDD test file, about 39% of "
    "attacks were labeled Normal, and the model almost never caught R2L and U2R "
    "attacks or attack types it had not seen in training. This is a learning "
    "project, not a security monitor."
)

    # Return the trained pipeline, the list of 40 feature names and the dropdown options.
    # If the saved .pkl files cannot be loaded (e.g. Python version mismatch after a
    # Streamlit Cloud upgrade), the model is rebuilt from the raw training data on the fly.
def load_model():
    try:
        with open(BASE_DIR / "model" / "model.pkl", "rb") as f:
            model = pickle.load(f)
        with open(BASE_DIR / "model" / "columns.pkl", "rb") as f:
            columns = pickle.load(f)
        with open(BASE_DIR / "model" / "options.json") as f:
            options = json.load(f)
        return model, columns, options
    except Exception:
        # Pickle incompatible with current Python - rebuild model from raw data.
        _rebuild_model()
        with open(BASE_DIR / "model" / "model.pkl", "rb") as f:
            model = pickle.load(f)
        with open(BASE_DIR / "model" / "columns.pkl", "rb") as f:
            columns = pickle.load(f)
        with open(BASE_DIR / "model" / "options.json") as f:
            options = json.load(f)
        return model, columns, options


def _rebuild_model():
    """Run train.py in a subprocess to regenerate model artefacts."""
    train_script = BASE_DIR / "train.py"
    subprocess.run(
        [sys.executable, str(train_script)],
        check=True,
        cwd=str(BASE_DIR),
    )

    # Return a list of problems. An empty list means the input is fine
def validate_input(values, columns, options):

    errors = []

    for col in columns:
        if col not in values:
            errors.append(f"Missing value for '{col}'.")
    if errors:
        return errors

    for col in TEXT_COLUMNS:
        if values[col] not in options[col]:
            errors.append(f"'{values[col]}' is not a known value for '{col}'.")

    for col in columns:
        if col in TEXT_COLUMNS:
            continue
        if values[col] < 0:
            errors.append(f"'{col}' cannot be negative.")
        elif col.endswith("_rate") and values[col] > 1:
            errors.append(f"'{col}' must be between 0 and 1.")

    return errors

    # Predict one connection. Returns (class name, dictionary of vote shares).

def predict_one(model, columns, values):
    row = pd.DataFrame([values], columns=columns)
    predicted = model.predict(row)[0]
    shares = model.predict_proba(row)[0]
    class_names = model.named_steps["model"].classes_
    probabilities = {str(c): float(p) for c, p in zip(class_names, shares)}
    return str(predicted), probabilities

    # Return the meaning, severity and suggested action for a class.

def explain(class_name):
    """Return the meaning, severity and suggested action for a class."""
    return CLASS_INFO[class_name]

def validate_table(df, columns, options):
    """Check a whole uploaded table. Returns a list of problems (empty = fine)."""
    missing = [c for c in columns if c not in df.columns]
    if missing:
        return ["Missing columns: " + ", ".join(missing)]
    if len(df) == 0:
        return ["The file has no rows."]
    if len(df) > MAX_ROWS:
        return [f"Please upload at most {MAX_ROWS} rows."]

    data = df[columns].copy()
    errors = []
    for col in columns:
        if col not in TEXT_COLUMNS:
            data[col] = pd.to_numeric(data[col], errors="coerce")
            if data[col].isna().any():
                errors.append(f"'{col}' must contain only numbers (no empty cells).")
    if errors:
        return errors

    for i, row in data.iterrows():
        for problem in validate_input(row.to_dict(), columns, options):
            errors.append(f"Row {i + 1}: {problem}")
    return errors[:20]


def predict_many(model, columns, df):
    """Predict every row. Returns a table: row, prediction, severity, top vote share."""
    data = df[columns].reset_index(drop=True).copy()
    for col in columns:
        if col not in TEXT_COLUMNS:
            data[col] = pd.to_numeric(data[col])

    predicted = model.predict(data)
    shares = model.predict_proba(data)

    return pd.DataFrame({
        "row": range(1, len(data) + 1),
        "prediction": predicted,
        "severity": [CLASS_INFO[c]["severity"] for c in predicted],
        "top_vote_share": shares.max(axis=1).round(2),
    })


    # Return the saved results of the one-time evaluation on the official test file.
def load_test_results():
    with open(BASE_DIR / "model" / "test_results.json") as f:
        return json.load(f)


    # Importance of each original feature (one-hot columns are added back together).
def feature_importance(model, columns):
    encoded_names = model.named_steps["pre"].get_feature_names_out()
    importances = model.named_steps["model"].feature_importances_

    totals = {}
    for col in columns:
        if col in TEXT_COLUMNS:
            prefix = f"text__{col}_"
            parts = [imp for name, imp in zip(encoded_names, importances)
                     if name.startswith(prefix)]
        else:
            parts = [imp for name, imp in zip(encoded_names, importances)
                     if name == f"num__{col}"]
        totals[col] = float(sum(parts))
    return pd.Series(totals).sort_values(ascending=False)