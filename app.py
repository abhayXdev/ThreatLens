import html
 
import altair as alt
import pandas as pd
import streamlit as st
from pathlib import Path
 
from nids_logic import (
    LIMITATION_NOTICE, TEXT_COLUMNS, explain, feature_importance, load_model,
    load_test_results, predict_many, predict_one, validate_input, validate_table)
 
BASE_DIR = Path(__file__).parent
CLASS_ORDER = ["Normal", "DOS", "PROBE", "R2L", "U2R"]
CLASS_COLORS = ["#2e7d5b", "#c0552b", "#b7791f", "#5b6fd6", "#a61e3d"]
SEVERITY_COLOR = {"None": "#2e7d5b", "Medium": "#b7791f",
                  "High": "#c0552b", "Critical": "#a61e3d"}
 
st.set_page_config(page_title="Thread Lens", page_icon="🔍", layout="wide")
 
# ---------------------------------------------------------------- 3D look (CSS)
st.markdown(
    """
    <style>
    /* Background glow */
    .stApp {
        background:
            radial-gradient(circle at 12% 0%, rgba(91,111,214,0.16), transparent 45%),
            radial-gradient(circle at 92% 8%, rgba(46,125,91,0.14), transparent 40%);
    }
    /* Hide default Streamlit header so the custom title is never covered */
    header[data-testid="stHeader"] {display: none !important;}
    #MainMenu {display: none !important;}
    footer {display: none !important;}
    .block-container {max-width: 1200px; padding-top: 2.5rem; padding-bottom: 2rem;}
 
    /* 3D extruded title */
    .title3d {
        font-size: 3.2rem; font-weight: 800; letter-spacing: -0.02em; margin: 0;
        color: #7b8cf0;
        text-shadow: 1px 1px 0 #6475e0, 2px 2px 0 #5463cc, 3px 3px 0 #4553b5,
                     4px 4px 0 #38449c, 5px 5px 12px rgba(0,0,0,0.45);
    }
    .subtitle {opacity: 0.8; margin: 0.4rem 0 1rem 0;}
 
    /* Raised 3D push buttons */
    .stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
        background: linear-gradient(180deg, #7b8cf0 0%, #4a5bb8 100%);
        border: none; border-radius: 12px; padding: 0.55rem 1.4rem;
        box-shadow: 0 6px 0 #34438f, 0 12px 20px rgba(0,0,0,0.35),
                    inset 0 1px 0 rgba(255,255,255,0.35);
        transition: transform 0.12s ease, box-shadow 0.12s ease;
        margin-bottom: 8px;
    }
    .stButton > button p, .stFormSubmitButton > button p,
    .stDownloadButton > button p {color: #ffffff !important; font-weight: 600;}
    .stButton > button:hover, .stFormSubmitButton > button:hover,
    .stDownloadButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 0 #34438f, 0 16px 26px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.35);
    }
    .stButton > button:active, .stFormSubmitButton > button:active,
    .stDownloadButton > button:active {
        transform: translateY(5px);
        box-shadow: 0 1px 0 #34438f, 0 4px 8px rgba(0,0,0,0.3);
    }
 
    /* 3D tabs */
    .stTabs [data-baseweb="tab-list"] {gap: 10px;}
    .stTabs [data-baseweb="tab"] {
        border-radius: 12px 12px 0 0; padding: 10px 18px;
        background: rgba(127,127,127,0.10);
        box-shadow: 0 -3px 8px rgba(0,0,0,0.12), inset 0 1px 0 rgba(255,255,255,0.12);
        transition: transform 0.15s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {transform: translateY(-3px);}
    .stTabs [aria-selected="true"] {
        background: rgba(91,111,214,0.28);
        box-shadow: 0 -4px 12px rgba(91,111,214,0.35);
    }
 
    /* Floating metric cards */
    [data-testid="stMetric"] {
        background: rgba(127,127,127,0.09); padding: 14px 18px; border-radius: 16px;
        box-shadow: 0 10px 24px rgba(0,0,0,0.22), inset 0 1px 0 rgba(255,255,255,0.15);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-5px);
        box-shadow: 0 16px 32px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.2);
    }
 
    /* Charts and tables as raised panels */
    [data-testid="stVegaLiteChart"], [data-testid="stArrowVegaLiteChart"] {
        background: rgba(127,127,127,0.07); border-radius: 16px; padding: 12px;
        box-shadow: 0 10px 26px rgba(0,0,0,0.2), inset 0 1px 0 rgba(255,255,255,0.12);
    }
    [data-testid="stDataFrame"] {
        border-radius: 14px; overflow: hidden;
        box-shadow: 0 8px 22px rgba(0,0,0,0.2);
    }
    [data-testid="stExpander"] {
        border-radius: 14px; box-shadow: 0 6px 18px rgba(0,0,0,0.15);
    }
 
    /* 3D result card (tilts back, lifts on hover) */
    .result-wrap {perspective: 1000px; margin: 0.6rem 0 1.2rem 0;}
    .result {
        border-left: 8px solid var(--c); padding: 1.1rem 1.4rem; border-radius: 16px;
        background: linear-gradient(145deg, rgba(127,127,127,0.16), rgba(127,127,127,0.05));
        box-shadow: 0 18px 36px rgba(0,0,0,0.3), 0 4px 0 var(--c),
                    inset 0 1px 0 rgba(255,255,255,0.2);
        transform: rotateX(4deg); transform-origin: center bottom;
        transition: transform 0.25s ease, box-shadow 0.25s ease;
    }
    .result:hover {
        transform: rotateX(0deg) translateY(-6px);
        box-shadow: 0 26px 46px rgba(0,0,0,0.38), 0 6px 0 var(--c),
                    inset 0 1px 0 rgba(255,255,255,0.25);
    }
    .result .cls {font-size: 2rem; font-weight: 800; margin: 0;
                  text-shadow: 2px 2px 0 rgba(0,0,0,0.25);}
    .result .sev {color: var(--c); font-weight: 700;}
    </style>
    """,
    unsafe_allow_html=True,
)
 
 
@st.cache_resource
def get_model():
    return load_model()
 
 
@st.cache_data
def get_examples():
    return pd.read_csv(BASE_DIR / "data" / "examples.csv")
 
 
model, columns, options = get_model()
examples = get_examples()
 
 
def class_bar_chart(series, value_name, title=None):
    """Colored bar chart with rounded, outlined bars. `series` is indexed by class."""
    df = series.rename_axis("Class").reset_index(name=value_name)
    order = [c for c in CLASS_ORDER if c in set(df["Class"])]
    order += [c for c in df["Class"] if c not in order]
    colors = [CLASS_COLORS[CLASS_ORDER.index(c)] if c in CLASS_ORDER else "#777777"
              for c in order]
    chart = alt.Chart(df).mark_bar(
        cornerRadiusTopLeft=8, cornerRadiusTopRight=8,
        stroke="rgba(0,0,0,0.35)", strokeWidth=1.5, opacity=0.95
    ).encode(
        x=alt.X("Class:N", sort=order, title=None),
        y=alt.Y(f"{value_name}:Q"),
        color=alt.Color("Class:N", scale=alt.Scale(domain=order, range=colors),
                        legend=None),
        tooltip=["Class", value_name])
    if title:
        chart = chart.properties(title=title)
    return chart
 
 
# Validate the values, predict, and draw the result on the page.
def show_result(values, actual_class=None):
    problems = validate_input(values, columns, options)
    if problems:
        for p in problems:
            st.error(p)
        return
 
    predicted, shares = predict_one(model, columns, values)
    info = explain(predicted)
 
    sev = info["severity"]
    color = SEVERITY_COLOR.get(sev, "#555555")
    st.markdown(
        f'<div class="result-wrap"><div class="result" style="--c:{color}">'
        f'<p class="cls">{html.escape(str(predicted))}</p>'
        f'<span class="sev">Severity: {html.escape(str(sev))}</span><br>'
        f'{html.escape(str(info["meaning"]))}</div></div>',
        unsafe_allow_html=True)
 
    share_series = pd.Series(shares).astype(float)
    top_share = float(share_series.max())
    c1, c2, c3 = st.columns(3)
    c1.metric("Prediction", predicted)
    c2.metric("Tree vote share", f"{top_share:.0%}")
    if actual_class is not None:
        c3.metric("Actual class", actual_class,
                  delta="match" if actual_class == predicted else "mismatch",
                  delta_color="normal" if actual_class == predicted else "inverse")
 
    st.write("**Suggested action:** " + info["action"])
 
    if actual_class is not None and predicted != actual_class:
        st.warning("The model got this one wrong. This is a real "
                   "limitation of the model, not a bug in the app.")
 
    st.write("Tree vote share per class (not a guarantee of confidence):")
    st.altair_chart(class_bar_chart(share_series, "Vote share"),
                    use_container_width=True)
    ordered = share_series.sort_values(ascending=False)
    st.dataframe(ordered.map(lambda v: f"{v:.1%}").rename("Vote share"))
 
 
st.markdown('<p class="title3d">Thread Lens</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Network intrusion detection: classify a network '
            'connection as Normal, DOS, PROBE, R2L or U2R.</p>',
            unsafe_allow_html=True)
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
                choices = list(options[col])
                default = choices.index(base_row[col]) if base_row[col] in choices else 0
                values[col] = box.selectbox(col, choices, index=default, key=key)
            elif col.endswith("_rate"):
                values[col] = box.number_input(
                    col, min_value=0.0, max_value=1.0,
                    value=min(max(float(base_row[col]), 0.0), 1.0),
                    step=0.01, key=key)
            else:
                values[col] = box.number_input(
                    col, min_value=0, value=max(0, int(float(base_row[col]))),
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
                pred_table = predict_many(model, columns, table)
                st.subheader(f"Predictions for {len(pred_table)} rows")
 
                counts = pred_table["prediction"].value_counts()
                left, right = st.columns([1, 2])
                with left:
                    st.dataframe(counts.rename("Rows"))
                with right:
                    st.altair_chart(
                        class_bar_chart(counts, "Rows",
                                        title="Classification summary"),
                        use_container_width=True)
 
                st.dataframe(pred_table, hide_index=True)
                st.download_button("Download results",
                                   pred_table.to_csv(index=False),
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
    imp = feature_importance(model, columns)
    imp_df = pd.Series(imp).head(10).reset_index()
    imp_df.columns = ["Feature", "Importance"]
    st.altair_chart(
        alt.Chart(imp_df).mark_bar(
            cornerRadiusTopRight=8, cornerRadiusBottomRight=8,
            stroke="rgba(0,0,0,0.35)", strokeWidth=1.5, color="#5b6fd6"
        ).encode(
            x=alt.X("Importance:Q"),
            y=alt.Y("Feature:N", sort="-x", title=None)),
        use_container_width=True)
    st.caption("Impurity-based importance from the trained forest. It shows what "
               "the model relied on, not what causes an attack.")
 
    # --- Confusion matrix heatmap ---
    st.subheader("Official test file: what the model predicted")
    st.write("Rows are the real class and columns are the prediction. Colors show "
             "the share of each real class; the numbers are row counts.")
    cm = pd.DataFrame(results["confusion_matrix"], index=classes, columns=classes)
    share = cm.div(cm.sum(axis=1), axis=0)
    counts_long = cm.rename_axis("Actual").reset_index().melt(
        id_vars="Actual", var_name="Predicted", value_name="Rows")
    shares_long = share.rename_axis("Actual").reset_index().melt(
        id_vars="Actual", var_name="Predicted", value_name="Share")
    cells = counts_long.merge(shares_long, on=["Actual", "Predicted"])
 
    cm_base = alt.Chart(cells).encode(
        x=alt.X("Predicted:N", sort=classes),
        y=alt.Y("Actual:N", sort=classes))
    heat = cm_base.mark_rect(
        stroke="rgba(0,0,0,0.35)", strokeWidth=2, cornerRadius=6
    ).encode(
        color=alt.Color("Share:Q", scale=alt.Scale(scheme="blues", domain=[0, 1])))
    numbers = cm_base.mark_text().encode(
        text="Rows:Q",
        color=alt.condition(alt.datum.Share > 0.5,
                            alt.value("white"), alt.value("black")))
    st.altair_chart(heat + numbers, use_container_width=True)
 
    # --- Recall per class ---
    st.subheader("Share of each real class the model got right (recall)")
    recall = pd.Series(
        {c: (cm.loc[c, c] / cm.loc[c].sum()) if cm.loc[c].sum() else 0.0
         for c in classes})
    st.altair_chart(
        class_bar_chart(recall, "Recall").encode(
            y=alt.Y("Recall:Q", scale=alt.Scale(domain=[0, 1]))),
        use_container_width=True)
 
    # --- Seen vs never seen ---
    st.subheader("Attack names seen vs never seen in training")
    seen = pd.DataFrame(results["seen_vs_unseen"]).T.reset_index()
    seen = seen.rename(columns={seen.columns[0]: "Attack names"})
    value_col = "Correct" if "Correct" in seen.columns else seen.columns[-1]
    st.altair_chart(
        alt.Chart(seen).mark_bar(
            cornerRadiusTopLeft=8, cornerRadiusTopRight=8,
            stroke="rgba(0,0,0,0.35)", strokeWidth=1.5, color="#2e7d5b"
        ).encode(
            x=alt.X("Attack names:N", sort=None),
            y=alt.Y(f"{value_col}:Q", scale=alt.Scale(domain=[0, 1]))),
        use_container_width=True)
    st.caption("Seen attacks still fail when they are rare in training: "
               "guess_passwd (53 training rows) was never classified correctly "
               "in the test file.")