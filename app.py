import altair as alt
import pandas as pd
import streamlit as st
from pathlib import Path

from nids_logic import (
    LIMITATION_NOTICE, TEXT_COLUMNS, explain, feature_importance, load_model,
    load_test_results, predict_many, predict_one, validate_input, validate_table)

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

tab_examples, tab_own, tab_csv, tab_insights = st.tabs(
    ["Example connections", "Enter your own values", "Upload a CSV",
     "Model insights"])

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


# ---------- Tab 4: model insights ----------
with tab_insights:
    results = load_test_results()
    classes = results["classes"]

    st.subheader("The algorithm: Random Forest")
    st.write(
        "Thread Lens uses a Random Forest of 100 decision trees. Each tree is "
        "trained on a random sample of the training rows and asks a series of "
        "yes/no questions about the 40 measurements. For a new connection every "
        "tree gives its answer, the answers are averaged, and the class with the "
        "highest average wins.")
    st.write("Accuracy was 99.88% on validation rows cut from the training file, "
             "but 75.67% on the official test file, which contains attack types "
             "the model never saw in training.")

    # --- Top 10 features ---
    st.subheader("Which measurements the model relies on")
    imp_df = feature_importance(model, columns).head(10).rename("Importance")
    imp_df = imp_df.reset_index()
    imp_df.columns = ["Feature", "Importance"]
    st.altair_chart(
        alt.Chart(imp_df).mark_bar().encode(
            x=alt.X("Importance:Q"),
            y=alt.Y("Feature:N", sort="-x", title=None)))
    st.caption("Impurity-based importance from the trained forest. It shows what "
               "the model relied on, not what causes an attack.")

    # --- Confusion matrix heatmap ---
    st.subheader("Official test file: what the model predicted")
    st.write("Rows are the real class and columns are the prediction. Colors show "
             "the share of each real class; the numbers are row counts.")
    cm = pd.DataFrame(results["confusion_matrix"], index=classes, columns=classes)
    share = cm.div(cm.sum(axis=1), axis=0)
    counts = cm.reset_index(names="Actual").melt(
        id_vars="Actual", var_name="Predicted", value_name="Rows")
    shares = share.reset_index(names="Actual").melt(
        id_vars="Actual", var_name="Predicted", value_name="Share")
    cells = counts.merge(shares, on=["Actual", "Predicted"])

    base = alt.Chart(cells).encode(
        x=alt.X("Predicted:N", sort=classes),
        y=alt.Y("Actual:N", sort=classes))
    heat = base.mark_rect().encode(
        color=alt.Color("Share:Q", scale=alt.Scale(scheme="blues", domain=[0, 1])))
    numbers = base.mark_text().encode(
        text="Rows:Q",
        color=alt.condition(alt.datum.Share > 0.5,
                            alt.value("white"), alt.value("black")))
    st.altair_chart(heat + numbers)

    # --- Recall per class ---
    st.subheader("Share of each real class the model got right (recall)")
    recall = pd.DataFrame({
        "Class": classes,
        "Recall": [cm.loc[c, c] / cm.loc[c].sum() for c in classes]})
    st.altair_chart(
        alt.Chart(recall).mark_bar().encode(
            x=alt.X("Class:N", sort=classes),
            y=alt.Y("Recall:Q", scale=alt.Scale(domain=[0, 1]))))

    # --- Seen vs never seen ---
    st.subheader("Attack names seen vs never seen in training")
    seen = pd.DataFrame(results["seen_vs_unseen"]).T.reset_index()
    seen.columns = ["Attack names", "Rows", "Correct"]
    st.altair_chart(
        alt.Chart(seen).mark_bar().encode(
            x=alt.X("Attack names:N", sort=None),
            y=alt.Y("Correct:Q", scale=alt.Scale(domain=[0, 1]))))
    st.caption("Seen attacks still fail when they are rare in training: "
               "guess_passwd (53 training rows) was never classified correctly "
               "in the test file.")