import pandas as pd
import streamlit as st
from pathlib import Path

from nids_logic import (
    LIMITATION_NOTICE, TEXT_COLUMNS, explain, load_model, predict_many,
    predict_one, validate_input, validate_table)

BASE_DIR = Path(__file__).parent

st.set_page_config(page_title="Thread Lens")


@st.cache_resource
def get_model():
    return load_model()


@st.cache_data
def get_examples():
    return pd.read_csv(BASE_DIR / "data" / "examples.csv")


model, columns, options = get_model()
examples = get_examples()


def show_result(values, actual_class=None):
    """Validate the values, predict, and draw the result on the page."""
    problems = validate_input(values, columns, options)
    if problems:
        for p in problems:
            st.error(p)
        return

    predicted, shares = predict_one(model, columns, values)
    info = explain(predicted)

    st.subheader(f"Prediction: {predicted}")
    left, right = st.columns(2)
    left.metric("Severity", info["severity"])
    if actual_class is not None:
        right.metric("Actual class in the dataset", actual_class)

    st.write(info["meaning"])
    st.write("Suggested action: " + info["action"])

    if actual_class is not None and predicted != actual_class:
        st.warning("The model got this one wrong. This is a real "
                   "limitation of the model, not a bug in the app.")

    st.write("Tree vote share per class (not a guarantee of confidence):")
    st.bar_chart(pd.Series(shares))


st.title("Thread Lens")
st.write("Network intrusion detection: classify a network connection as "
         "Normal, DOS, PROBE, R2L or U2R.")
st.warning(LIMITATION_NOTICE)

tab_examples, tab_own, tab_csv = st.tabs(
    ["Example connections", "Enter your own values", "Upload a CSV"])

# ---------- Tab 1: stored examples ----------
with tab_examples:
    choice = st.selectbox("Choose an example", range(len(examples)),
                          format_func=lambda i: f"Example {i + 1}",
                          key="example_choice")
    row = examples.iloc[choice].to_dict()
    actual_class = row.pop("true_class")

    with st.expander("Show the 40 values of this connection"):
        st.dataframe(pd.Series(row).astype(str).rename("value"))

    if st.button("Predict", key="predict_example"):
        show_result(row, actual_class)

# ---------- Tab 2: your own values ----------
with tab_own:
    st.write("Start from an example, then change any values you like.")
    base = st.selectbox("Start from", range(len(examples)),
                        format_func=lambda i: f"Example {i + 1}",
                        key="base_choice")
    base_row = examples.iloc[base].to_dict()
    base_row.pop("true_class")

    with st.form("own_values"):
        values = {}
        grid = st.columns(3)
        for i, col in enumerate(columns):
            box = grid[i % 3]
            key = f"{col}_{base}"
            if col in TEXT_COLUMNS:
                choices = options[col]
                values[col] = box.selectbox(
                    col, choices, index=choices.index(base_row[col]), key=key)
            elif col.endswith("_rate"):
                values[col] = box.number_input(
                    col, min_value=0.0, max_value=1.0,
                    value=float(base_row[col]), step=0.01, key=key)
            else:
                values[col] = box.number_input(
                    col, min_value=0, value=int(base_row[col]),
                    step=1, key=key)
        submitted = st.form_submit_button("Predict")

    if submitted:
        show_result(values)

# ---------- Tab 3: upload a CSV ----------
with tab_csv:
    st.write("Upload a CSV file with one connection per row. It needs the 40 "
             "column names (any order). Extra columns are ignored.")

    template = examples[columns].to_csv(index=False)
    st.download_button("Download a template (10 example rows)", template,
                       file_name="thread_lens_template.csv", mime="text/csv")

    uploaded = st.file_uploader("Upload your CSV", type="csv")
    if uploaded is not None:
        try:
            table = pd.read_csv(uploaded)
        except Exception:
            st.error("Could not read this file as a CSV.")
        else:
            problems = validate_table(table, columns, options)
            if problems:
                for p in problems:
                    st.error(p)
            else:
                results = predict_many(model, columns, table)
                st.subheader(f"Predictions for {len(results)} rows")
                st.write(results["prediction"].value_counts())
                st.dataframe(results, hide_index=True)
                st.download_button("Download results", results.to_csv(index=False),
                                   file_name="thread_lens_results.csv",
                                   mime="text/csv")