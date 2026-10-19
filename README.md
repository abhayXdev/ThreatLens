# Thread Lens

Network intrusion detection on the NSL-KDD dataset. Thread Lens takes the 40 measurements of a network connection and classifies it as **Normal**, **DOS**, **PROBE**, **R2L** or **U2R**, with a short explanation, a severity level and a suggested action. It runs as a Streamlit app.

**Live demo:** _add the link after deployment_

> **Important:** "Normal" does not mean safe. On the official test file the model labeled about 39% of attacks as Normal. This is a learning project, not a security monitor. See [Results and limitations](#results-and-limitations).

## What the app does

- **Example connections:** pick one of 10 real rows from the NSL-KDD test file and see the prediction next to the actual class.
- **Enter your own values:** a form with all 40 fields, prefilled from an example, with input checks.
- **Upload a CSV:** predict up to 5,000 connections at once, with a downloadable template and downloadable results.

## Data

NSL-KDD: a cleaned version of the KDD'99 intrusion data without duplicate records (Tavallaee et al., 2009, University of New Brunswick). The official page no longer hosts the files, so the copies in `data/raw/` come from the backup at [jmnwong/NSL-KDD-Dataset](https://github.com/jmnwong/NSL-KDD-Dataset).

| File | Rows | Used for |
|---|---|---|
| `KDDTrain+.txt` | 125,973 | training and validation |
| `KDDTest+.txt` | 22,544 | one final test |

Class counts (training / test):

| Class | Train | Test |
|---|---|---|
| Normal | 67,343 | 9,711 |
| DOS | 45,927 | 7,458 |
| PROBE | 11,656 | 2,421 |
| R2L | 995 | 2,754 |
| U2R | 52 | 200 |

Attack names were grouped into the four standard families. The test file contains 17 attack types (3,750 rows) that never appear in training.

## How it was built

1. **Explore:** no missing values or duplicates; very skewed byte columns; strongly redundant column groups (for example `num_compromised` and `num_root`, correlation 0.9988); `protocol_type`, `flag` and `service` all separate the classes to different degrees.
2. **Clean:** dropped `difficulty` (not a real measurement, and derived from the labels) and `num_outbound_cmds` (0 in every row).
3. **Split:** 80/20 stratified split of the training file (100,778 / 25,195 rows, `random_state=42`). The official test file stayed untouched until the end.
4. **Preprocess:** one-hot encoding for the 3 text columns and standard scaling for the 37 numeric ones, inside one scikit-learn pipeline fitted on the training part only.
5. **Compare:** Logistic Regression (baseline), Decision Tree and Random Forest on the same validation rows.
6. **Iterate:** tried class weights on the Random Forest; macro F1 did not improve (0.9505 against 0.9515), so the simpler model was kept.
7. **Test once:** the chosen Random Forest was scored on `KDDTest+.txt` a single time.
8. **Ship:** saved the whole pipeline to `model/model.pkl`, put the logic in `nids_logic.py`, and covered it with 12 automated tests.

## Results and limitations

Validation (rows cut from the training file, so every attack type was seen in training):

| Model | Accuracy (5 classes) | Macro F1 | Normal vs Attack: missed attacks / false alarms |
|---|---|---|---|
| Logistic Regression | 98.90% | 0.8561 | 415 / 251 |
| Decision Tree | 99.81% | 0.9320 | 16 / 23 |
| **Random Forest** | **99.88%** | **0.9515** | 23 / 7 |

Official test file (`KDDTest+.txt`), Random Forest:

| Class | Precision | Recall | Rows |
|---|---|---|---|
| Normal | 0.65 | 0.97 | 9,711 |
| DOS | 0.96 | 0.82 | 7,458 |
| PROBE | 0.86 | 0.59 | 2,421 |
| R2L | 0.97 | 0.02 | 2,754 |
| U2R | 0.40 | 0.01 | 200 |

Overall test accuracy is **75.67%** with a macro F1 of **0.4861**. The large drop from validation is expected on this dataset, and the analysis shows where it comes from:

- 5,007 of the 12,833 attacks in the test file (about 39%) were labeled Normal.
- Attack names never seen in training were classified correctly 19.8% of the time (3,750 rows); names seen in training, 75.5% (9,083 rows).
- Seen attacks that are rare in training still fail: `guess_passwd` (53 training rows, 1,231 test rows) was never classified correctly, and `warezmaster` (20 training rows, 944 test rows) only 6% of the time. Together they make up most of the R2L test rows.
- Well-represented attacks such as `neptune`, `smurf`, `satan`, `back` and `nmap` are detected at 99-100%.
- The vote share shown in the app is the share of trees agreeing, not a calibrated confidence: one wrongly classified R2L example received a vote share of 1.0 for Normal.

## Run it locally

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS / Linux:      source .venv/bin/activate
pip install -r requirements.txt
python -m streamlit run app.py
```

The model was saved with scikit-learn 1.6.1, so `requirements.txt` pins that version.

Run the tests:

```bash
pip install pytest
python -m pytest -v
```

## Project structure

```
app.py                # Streamlit screen (three tabs)
nids_logic.py         # loading, validation, prediction, explanations
requirements.txt
model/                # model.pkl, columns.pkl, options.json
data/
  examples.csv        # 10 real test-file rows used by the app
  raw/                # KDDTrain+.txt, KDDTest+.txt
  ThreadLens_files.zip  # backup copy of the app files
tests/test_logic.py   # 12 tests
notebooks/ThreatLensMLproject.ipynb   # training and evaluation
```

## Possible next steps

- More training examples for rare attacks (R2L, U2R) and a newer dataset with modern attack types.
- Anomaly detection methods to catch attack types the classifier has never seen.
- Retrain the final model on training plus validation data before a production-style release.

## Notes

`.pkl` files can run code when loaded, so only load model files from a source you trust.