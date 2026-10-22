import html
import math
import random
from pathlib import Path
from urllib.parse import quote

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from nids_logic import (
    LIMITATION_NOTICE, TEXT_COLUMNS, explain, feature_importance, load_model,
    load_test_results, predict_many, predict_one, validate_input, validate_table)

BASE_DIR = Path(__file__).parent
CLASS_ORDER = ["Normal", "DOS", "PROBE", "R2L", "U2R"]
# Bright colours so they stay visible on the dark background
CLASS_COLORS = ["#34d399", "#ff7a45", "#fbbf24", "#7c8cff", "#ff4d6d"]
SEVERITY_COLOR = {"None": "#34d399", "Medium": "#fbbf24",
                  "High": "#ff7a45", "Critical": "#ff4d6d"}
TEXT = "#e8f7ff"      # main text colour
ACCENT = "#49d6e8"    # cyan accent used for borders, selections, highlights

st.set_page_config(page_title="Threat Lens", page_icon="🔍", layout="wide")


# ------------------------------------------------- BACKGROUND (generated code)
# Dark navy-teal scene with a glowing network of nodes and soft bokeh circles,
# drawn as an SVG by this function. No image file is needed.
def network_background_svg(w=1600, h=900, seed=7):
    rnd = random.Random(seed)

    def centre(t):
        """Centre line of the network band: lower-left up to upper-right."""
        x = t * w
        y = h * (0.90 - 0.66 * t) + math.sin(t * 9.0) * h * 0.04
        return x, y

    # nodes scattered around the band (denser near the middle of the band)
    nodes = []
    for _ in range(170):
        t = rnd.random()
        cx, cy = centre(t)
        spread = h * (0.035 + 0.05 * math.sin(t * math.pi))
        nodes.append((cx + rnd.gauss(0, spread * 0.6),
                      cy + rnd.gauss(0, spread)))

    # connect every node to its closest neighbours
    lines = set()
    for i, (x1, y1) in enumerate(nodes):
        near = sorted(((x1 - x2) ** 2 + (y1 - y2) ** 2, j)
                      for j, (x2, y2) in enumerate(nodes) if j != i)[:3]
        for d2, j in near:
            if d2 < (w * 0.11) ** 2:
                lines.add((min(i, j), max(i, j)))
    line_svg = "".join(
        f'<line x1="{nodes[a][0]:.1f}" y1="{nodes[a][1]:.1f}" '
        f'x2="{nodes[b][0]:.1f}" y2="{nodes[b][1]:.1f}"/>'
        for a, b in lines)

    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rnd.uniform(0.9, 1.9):.1f}"/>'
                   for x, y in nodes)
    bright = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rnd.uniform(2.4, 4.0):.1f}"/>'
        for x, y in rnd.sample(nodes, 26))

    # soft out-of-focus circles (bokeh)
    bokeh = ""
    for _ in range(34):
        t = rnd.random()
        cx, cy = centre(t)
        x = cx + rnd.gauss(0, w * 0.12)
        y = cy + rnd.gauss(0, h * 0.18)
        r = rnd.uniform(10, 46)
        o = rnd.uniform(0.10, 0.26)
        bokeh += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill-opacity="{o:.2f}"/>'
    blobs = "".join(
        f'<circle cx="{w * fx:.0f}" cy="{h * fy:.0f}" r="{r}" fill-opacity="{o}"/>'
        for fx, fy, r, o in [(0.16, 0.20, 150, 0.10), (0.90, 0.86, 120, 0.12),
                             (0.55, 0.50, 190, 0.07), (0.30, 0.78, 110, 0.08)])

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" preserveAspectRatio="xMidYMid slice">'
        '<defs>'
        '<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#020a14"/>'
        '<stop offset="0.55" stop-color="#04182b"/>'
        '<stop offset="1" stop-color="#031221"/></linearGradient>'
        '<radialGradient id="glow" cx="0.6" cy="0.5" r="0.6">'
        '<stop offset="0" stop-color="#0d5a86" stop-opacity="0.42"/>'
        '<stop offset="1" stop-color="#0d5a86" stop-opacity="0"/></radialGradient>'
        '<filter id="b3" x="-20%" y="-20%" width="140%" height="140%">'
        '<feGaussianBlur stdDeviation="3"/></filter>'
        '<filter id="b14" x="-50%" y="-50%" width="200%" height="200%">'
        '<feGaussianBlur stdDeviation="14"/></filter>'
        '<filter id="g2" x="-300%" y="-300%" width="700%" height="700%">'
        '<feGaussianBlur stdDeviation="2.4" result="b"/>'
        '<feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>'
        '</filter></defs>'
        f'<rect width="{w}" height="{h}" fill="url(#bg)"/>'
        f'<rect width="{w}" height="{h}" fill="url(#glow)"/>'
        f'<text x="{w / 2:.0f}" y="{h * 0.5:.0f}" text-anchor="middle" '
        'dominant-baseline="middle" font-family="Arial Black, Segoe UI, Helvetica, Arial, sans-serif" '
        f'font-weight="900" font-size="{int(w * 0.13)}" textLength="{int(w * 0.84)}" '
        'lengthAdjust="spacingAndGlyphs" fill="#49d6e8" fill-opacity="0.30" '
        'filter="url(#b14)">THREAT LENS</text>'
        f'<text x="{w / 2:.0f}" y="{h * 0.5:.0f}" text-anchor="middle" '
        'dominant-baseline="middle" font-family="Arial Black, Segoe UI, Helvetica, Arial, sans-serif" '
        f'font-weight="900" font-size="{int(w * 0.13)}" textLength="{int(w * 0.84)}" '
        'lengthAdjust="spacingAndGlyphs" fill="#49d6e8" fill-opacity="0.09" '
        'stroke="#7df9ff" stroke-opacity="0.28" stroke-width="2">THREAT LENS</text>'
        f'<g fill="#1f7fb8" filter="url(#b14)">{blobs}</g>'
        f'<g fill="#2aa3d6" filter="url(#b3)">{bokeh}</g>'
        f'<g stroke="#49d6e8" stroke-opacity="0.30" stroke-width="0.8">{line_svg}</g>'
        f'<g fill="#7fe3f0" fill-opacity="0.85">{dots}</g>'
        f'<g fill="#9cf0ff" filter="url(#g2)">{bright}</g>'
        '</svg>')
    return svg


@st.cache_data
def background_css():
    uri = "data:image/svg+xml;utf8," + quote(network_background_svg())
    return (
        "<style>.stApp{"
        "background-image: linear-gradient(rgba(2,10,22,0.25), rgba(2,10,22,0.45)),"
        f" url(\"{uri}\");"
        "background-size: cover; background-position: center;"
        "background-repeat: no-repeat; background-attachment: fixed;}</style>")


st.markdown(background_css(), unsafe_allow_html=True)

# ------------------------------------------------------------------ STYLE (CSS)
# One palette everywhere: navy-teal glass panels, cyan accent, light text.
st.markdown(
    """
    <style>
    .stApp {background-color: #020a14; color: #e8f7ff;}

    header[data-testid="stHeader"] {display: none !important;}
    #MainMenu {display: none !important;}
    footer {display: none !important;}
    .block-container {max-width: 1200px; padding-top: 2.5rem; padding-bottom: 2rem;}

    /* Hide the empty box that holds the cursor script */
    [data-testid="stElementContainer"]:has(iframe[height="0"]),
    .element-container:has(iframe[height="0"]) {
        position: absolute; height: 0; margin: 0; overflow: hidden;
    }

    /* ===== TEXT COLOURS ===== */
    h1, h2, h3, h4, h5, h6,
    [data-testid="stHeading"] *,
    [data-testid="stMarkdownContainer"] *,
    [data-testid="stCaptionContainer"] *,
    [data-testid="stWidgetLabel"] *,
    .stTabs [data-baseweb="tab"] *,
    [data-testid="stExpander"] summary *,
    [data-testid="stMetricLabel"] *,
    [data-testid="stMetricValue"] * {
        color: #e8f7ff !important;
    }
    [data-testid="stCaptionContainer"] * {color: #a9cbe0 !important;}
    h2, h3 {text-shadow: 0 2px 10px rgba(0,0,0,0.6);}

    /* ===== INPUTS, DROPDOWNS (+ clear "selected" look) ===== */
    [data-baseweb="select"] > div,
    [data-baseweb="input"] > div,
    .stNumberInput input, .stNumberInput button {
        background: rgba(4,24,44,0.88) !important;
        border: 1px solid rgba(73,214,232,0.35) !important;
        color: #ffffff !important;
        border-radius: 10px !important;
    }
    [data-baseweb="select"] *, [data-baseweb="input"] input {color: #ffffff !important;}
    [data-baseweb="select"] > div:hover, [data-baseweb="input"] > div:hover {
        border-color: rgba(73,214,232,0.75) !important;
    }
    [data-baseweb="select"] > div:focus-within, [data-baseweb="input"]:focus-within > div {
        border-color: #49d6e8 !important;
        box-shadow: 0 0 0 2px rgba(73,214,232,0.35), 0 0 16px rgba(73,214,232,0.35) !important;
    }
    /* open dropdown list */
    [data-baseweb="popover"] > div {
        background: #04182b !important;
        border: 1px solid rgba(73,214,232,0.45) !important;
        border-radius: 12px !important;
        box-shadow: 0 14px 34px rgba(0,0,0,0.6), 0 0 22px rgba(73,214,232,0.18) !important;
    }
    [data-baseweb="popover"] ul {background: transparent !important;}
    [data-baseweb="popover"] li {color: #e8f7ff !important; transition: background 0.12s;}
    [data-baseweb="popover"] li:hover {
        background: rgba(73,214,232,0.18) !important;
    }
    [data-baseweb="popover"] li[aria-selected="true"] {
        background: linear-gradient(90deg, rgba(73,214,232,0.38), rgba(31,127,184,0.30)) !important;
        box-shadow: inset 3px 0 0 #49d6e8;
        font-weight: 700;
    }
    [data-baseweb="popover"] * {color: #e8f7ff !important;}

    /* ===== SELECT BOXES: animated flowing background + electric border ===== */
    @keyframes tl-flow {
        0%   {background-position: 0% 50%;}
        100% {background-position: 200% 50%;}
    }
    [data-testid="stSelectbox"] [data-baseweb="select"] {
        position: relative; border-radius: 12px;
    }
    [data-testid="stSelectbox"] [data-baseweb="select"] > div {
        background: linear-gradient(110deg, rgba(4,24,44,0.94) 0%,
                    rgba(14,78,116,0.94) 50%, rgba(4,24,44,0.94) 100%) !important;
        background-size: 200% 100% !important;
        animation: tl-flow 6s linear infinite;
        border: 1px solid rgba(73,214,232,0.45) !important;
        box-shadow: 0 0 14px rgba(73,214,232,0.22), inset 0 1px 0 rgba(125,249,255,0.20);
    }
    [data-testid="stSelectbox"] [data-baseweb="select"]::before {
        content: ""; position: absolute; inset: -2px; border-radius: 13px;
        padding: 1.5px; pointer-events: none; z-index: 1;
        background: conic-gradient(from var(--angle),
            transparent 0%, transparent 50%,
            #7df9ff 72%, #ffffff 77%, #7df9ff 82%,
            transparent 93%, transparent 100%);
        -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
        mask-composite: exclude;
        filter: drop-shadow(0 0 4px #7df9ff);
        animation: electric-spin 3.5s linear infinite;
    }
    /* Nothing inside the select box or its dropdown may stay white */
    [data-testid="stSelectbox"] [data-baseweb="select"] > div * {
        background: transparent !important;
        background-color: transparent !important;
        color: #ffffff !important;
    }
    [data-testid="stSelectbox"] [data-baseweb="select"] svg {fill: #7df9ff !important;}
    [data-baseweb="popover"], [data-baseweb="popover"] > div,
    [data-baseweb="popover"] > div > div, [data-baseweb="popover"] [data-baseweb="menu"],
    [data-testid="stSelectboxVirtualDropdown"], ul[role="listbox"] {
        background: #04182b !important;
        background-color: #04182b !important;
    }
    [data-baseweb="popover"] li, [data-testid="stSelectboxVirtualDropdown"] li,
    [role="option"] {
        background: transparent !important;
        color: #e8f7ff !important;
    }
    [data-baseweb="menu"], [data-baseweb="menu"] ul {
        background: transparent !important;
    }

    /* ===== Alerts and file uploader ===== */
    [data-testid="stAlert"] {
        background: rgba(4,24,44,0.85) !important;
        border: 1px solid rgba(73,214,232,0.40);
        border-radius: 14px;
    }
    [data-testid="stAlert"] * {color: #e8f7ff !important;}
    [data-testid="stFileUploaderDropzone"] {
        background: rgba(4,24,44,0.80) !important;
        border: 1px dashed rgba(73,214,232,0.60);
        border-radius: 14px;
    }
    [data-testid="stFileUploaderDropzone"] * {color: #e8f7ff !important;}

    /* ===== HEADER (plain title, no animation or effects) ===== */
    .hero {
        display: flex; flex-direction: column; align-items: center;
        justify-content: center; text-align: center;
        padding: 0.4rem 1rem 1rem 1rem; margin-bottom: 0.6rem;
    }
    .hero-title {
        font-size: 26px; font-weight: 700; letter-spacing: 0.12em; line-height: 1.2;
        margin: 0; color: #7df9ff !important;   /* cyan of the background network */
        text-decoration: underline; text-decoration-color: #7df9ff;
        text-decoration-thickness: 2px; text-underline-offset: 6px;
    }
    .hero-sub {
        font-size: 14px; max-width: 820px;
        margin: 0.5rem auto 0 auto; color: #b9d8ec !important;
    }

    /* ===== Raised 3D push buttons (teal) ===== */
    .stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {
        background: linear-gradient(180deg, #2fb8d4 0%, #14708f 100%);
        border: none; border-radius: 12px; padding: 0.55rem 1.4rem;
        box-shadow: 0 6px 0 #0b4660, 0 12px 20px rgba(0,0,0,0.45),
                    0 0 18px rgba(73,214,232,0.40),
                    inset 0 1px 0 rgba(255,255,255,0.35);
        transition: transform 0.12s ease, box-shadow 0.12s ease;
        margin-bottom: 8px;
    }
    .stButton > button p, .stFormSubmitButton > button p,
    .stDownloadButton > button p {color: #ffffff !important; font-weight: 600;}
    .stButton > button:hover, .stFormSubmitButton > button:hover,
    .stDownloadButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 0 #0b4660, 0 16px 26px rgba(0,0,0,0.5),
                    0 0 28px rgba(125,249,255,0.65),
                    inset 0 1px 0 rgba(255,255,255,0.35);
    }
    .stButton > button:active, .stFormSubmitButton > button:active,
    .stDownloadButton > button:active {
        transform: translateY(5px);
        box-shadow: 0 1px 0 #0b4660, 0 4px 8px rgba(0,0,0,0.3);
    }

    /* ===== 3D tabs (selected tab clearly highlighted) ===== */
    .stTabs [data-baseweb="tab-list"] {gap: 10px;}
    .stTabs [data-baseweb="tab"] {
        border-radius: 12px 12px 0 0; padding: 10px 18px;
        background: rgba(4,24,44,0.70);
        box-shadow: 0 -3px 8px rgba(0,0,0,0.25), inset 0 1px 0 rgba(73,214,232,0.20);
        transition: transform 0.15s ease, background 0.15s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {
        transform: translateY(-3px); background: rgba(73,214,232,0.16);
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(180deg, rgba(73,214,232,0.40), rgba(20,112,143,0.40));
        box-shadow: 0 -4px 16px rgba(73,214,232,0.50), inset 0 1px 0 rgba(255,255,255,0.25);
    }
    .stTabs [data-baseweb="tab-highlight"] {
        background: #7df9ff !important; height: 3px !important;
        box-shadow: 0 0 12px #7df9ff;
    }
    .stTabs [data-baseweb="tab-border"] {background: rgba(73,214,232,0.25) !important;}

    /* ===== ELECTRIC BORDER (rotating neon edge) ===== */
    @property --angle {syntax: '<angle>'; initial-value: 0deg; inherits: false;}
    @keyframes electric-spin {to {--angle: 360deg;}}
    @keyframes electric-flicker {
        0%, 100% {opacity: 1;}
        45% {opacity: 0.85;}
        50% {opacity: 1;}
        78% {opacity: 0.9;}
    }
    [data-testid="stMetric"], .result {position: relative;}
    [data-testid="stMetric"]::before, .result::before {
        content: ""; position: absolute; inset: -2px; border-radius: inherit;
        padding: 1.5px; pointer-events: none;
        background: conic-gradient(from var(--angle),
            transparent 0%, transparent 45%,
            #7df9ff 70%, #ffffff 76%, #7df9ff 82%,
            transparent 92%, transparent 100%);
        -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
        mask-composite: exclude;
        filter: drop-shadow(0 0 5px #7df9ff) drop-shadow(0 0 12px rgba(125,249,255,0.6));
        animation: electric-spin 3s linear infinite,
                   electric-flicker 1.6s steps(1) infinite;
    }

    /* ===== Glass panels (cards, charts, expanders) ===== */
    [data-testid="stMetric"] {
        background: rgba(4,24,44,0.72); padding: 14px 18px; border-radius: 16px;
        backdrop-filter: blur(6px);
        box-shadow: 0 10px 24px rgba(0,0,0,0.40), inset 0 1px 0 rgba(73,214,232,0.22);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    [data-testid="stMetric"]:hover {
        transform: translateY(-5px);
        box-shadow: 0 16px 32px rgba(0,0,0,0.50), inset 0 1px 0 rgba(73,214,232,0.35);
    }
    [data-testid="stVegaLiteChart"], [data-testid="stArrowVegaLiteChart"] {
        background: rgba(4,24,44,0.68); border-radius: 16px; padding: 12px;
        border: 1px solid rgba(73,214,232,0.22);
        backdrop-filter: blur(6px);
        box-shadow: 0 10px 26px rgba(0,0,0,0.35), inset 0 1px 0 rgba(73,214,232,0.18);
    }
    [data-testid="stExpander"] {
        border-radius: 14px; background: rgba(4,24,44,0.68);
        border: 1px solid rgba(73,214,232,0.22);
        box-shadow: 0 6px 18px rgba(0,0,0,0.30);
    }

    /* ===== THEMED TABLES (replace the default grey dataframes) ===== */
    .tl-table-wrap {
        max-height: 420px; overflow: auto; border-radius: 14px;
        background: rgba(4,24,44,0.72); backdrop-filter: blur(6px);
        border: 1px solid rgba(73,214,232,0.30);
        box-shadow: 0 10px 26px rgba(0,0,0,0.38), inset 0 1px 0 rgba(73,214,232,0.18);
        margin: 0.3rem 0 1rem 0;
    }
    .tl-table {width: 100%; border-collapse: collapse; font-size: 0.92rem;}
    .tl-table thead th {
        position: sticky; top: 0; z-index: 1; text-align: left;
        padding: 10px 14px; color: #7df9ff; font-weight: 700;
        background: rgba(6,48,78,0.97);
        border-bottom: 2px solid rgba(73,214,232,0.55);
        letter-spacing: 0.02em; white-space: nowrap;
    }
    .tl-table tbody th, .tl-table tbody td {
        padding: 8px 14px; color: #e8f7ff; text-align: left;
        border-bottom: 1px solid rgba(73,214,232,0.12);
        white-space: nowrap;
    }
    .tl-table tbody th {color: #a9cbe0; font-weight: 600;}
    .tl-table tbody tr:nth-child(even) {background: rgba(73,214,232,0.05);}
    .tl-table tbody tr {transition: background 0.12s ease;}
    .tl-table tbody tr:hover {
        background: rgba(73,214,232,0.17);
        box-shadow: inset 3px 0 0 #49d6e8;
    }
    .tl-badge {
        display: inline-block; padding: 2px 12px; border-radius: 999px;
        font-weight: 700; color: #04121f; background: var(--b);
        box-shadow: 0 0 12px var(--b);
    }
    .tl-wrap-note {color: #a9cbe0; font-size: 0.85rem; margin: -0.6rem 0 1rem 0;}

    /* ===== 3D result card ===== */
    .result-wrap {perspective: 1000px; margin: 0.6rem 0 1.2rem 0;}
    .result {
        border-radius: 24px; padding: 1.1rem 1.4rem; color: #e8f7ff;
        background: linear-gradient(145deg, rgba(8,60,100,0.80), rgba(4,22,40,0.88));
        backdrop-filter: blur(6px);
        box-shadow: 0 18px 36px rgba(0,0,0,0.45), 0 4px 0 var(--c),
                    inset 0 1px 0 rgba(73,214,232,0.28);
        transform: rotateX(4deg); transform-origin: center bottom;
        transition: transform 0.25s ease, box-shadow 0.25s ease;
    }
    .result:hover {
        transform: rotateX(0deg) translateY(-6px);
        box-shadow: 0 26px 46px rgba(0,0,0,0.55), 0 6px 0 var(--c),
                    inset 0 1px 0 rgba(73,214,232,0.35);
    }
    .result .cls {font-size: 2rem; font-weight: 800; margin: 0; color: #ffffff;
                  text-shadow: 2px 2px 0 rgba(0,0,0,0.45);}
    .result .sev {color: var(--c); font-weight: 700;}
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------- SPLASH CURSOR (JS)
# Streamlit cannot run React components, so SplashCursor is written in plain
# JavaScript (a WebGL fluid simulation). It draws on a full-screen, click-through
# canvas added to the main page, so it works over every tab.
# Settings below match your SplashCursor props (change them here).
SPLASH_CURSOR_JS = r"""
<script>
(function () {
  try {
    const CFG = {
      rainbow: false,      // rainbow
      size: 2,             // size          -> splat radius
      force: 2,            // force         -> splat force
      swirl: 17.5,         // swirl         -> curl / vorticity
      trail: 2.9,          // trail         -> dye fade rate (higher = shorter trail)
      clickSplash: true,   // clickSplash
      colorSpeed: 1,       // colorSpeed
      intensity: 1.95,     // intensity     -> colour brightness
      momentum: 1,         // momentum      -> velocity lifetime
      shading: 1,          // shading       -> lighting on the fluid
      glow: 0,             // glow          -> 0 = no bloom
      quality: "high",     // quality
      intro: true          // intro         -> splashes when the page loads
    };

    const P = window.parent, D = P.document;
    if (P.__splashCursorCleanup) P.__splashCursorCleanup();   // no duplicates on rerun

    const canvas = D.createElement("canvas");
    canvas.id = "splash-cursor-canvas";
    canvas.style.cssText = "position:fixed;top:0;left:0;width:100vw;height:100vh;" +
                           "pointer-events:none;z-index:2147483647;";
    D.body.appendChild(canvas);

    const Q = {low: {sim: 64, dye: 512}, medium: {sim: 96, dye: 768},
               high: {sim: 128, dye: 1024}}[CFG.quality] || {sim: 128, dye: 1024};
    const config = {
      SIM_RESOLUTION: Q.sim,
      DYE_RESOLUTION: Q.dye,
      DENSITY_DISSIPATION: CFG.trail,
      VELOCITY_DISSIPATION: 2 / Math.max(CFG.momentum, 0.01),
      PRESSURE: 0.1,
      PRESSURE_ITERATIONS: 20,
      CURL: CFG.swirl,
      SPLAT_RADIUS: 0.1 * CFG.size,
      SPLAT_FORCE: 3000 * CFG.force,
      SHADING: CFG.shading > 0,
      COLOR_UPDATE_SPEED: 10 * CFG.colorSpeed
    };

    // ---------- WebGL setup ----------
    const params = {alpha: true, depth: false, stencil: false,
                    antialias: false, preserveDrawingBuffer: false};
    let gl = canvas.getContext("webgl2", params);
    const isWebGL2 = !!gl;
    if (!isWebGL2) {
      gl = canvas.getContext("webgl", params) || canvas.getContext("experimental-webgl", params);
    }
    if (!gl) { console.warn("Splash cursor: WebGL is not available"); canvas.remove(); return; }

    let halfFloat, linearOK;
    if (isWebGL2) {
      gl.getExtension("EXT_color_buffer_float");
      linearOK = gl.getExtension("OES_texture_float_linear");
    } else {
      halfFloat = gl.getExtension("OES_texture_half_float");
      linearOK = gl.getExtension("OES_texture_half_float_linear");
    }
    gl.clearColor(0, 0, 0, 0);
    const texType = isWebGL2 ? gl.HALF_FLOAT : (halfFloat && halfFloat.HALF_FLOAT_OES);

    function renderable(internalFormat, format, type) {
      const tex = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.texImage2D(gl.TEXTURE_2D, 0, internalFormat, 4, 4, 0, format, type, null);
      const fb = gl.createFramebuffer();
      gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
      return gl.checkFramebufferStatus(gl.FRAMEBUFFER) === gl.FRAMEBUFFER_COMPLETE;
    }
    function supportedFormat(internalFormat, format, type) {
      if (!renderable(internalFormat, format, type)) {
        if (isWebGL2 && internalFormat === gl.R16F) return supportedFormat(gl.RG16F, gl.RG, type);
        if (isWebGL2 && internalFormat === gl.RG16F) return supportedFormat(gl.RGBA16F, gl.RGBA, type);
        return null;
      }
      return {internalFormat: internalFormat, format: format};
    }
    let fmtRGBA, fmtRG, fmtR;
    if (isWebGL2) {
      fmtRGBA = supportedFormat(gl.RGBA16F, gl.RGBA, texType);
      fmtRG = supportedFormat(gl.RG16F, gl.RG, texType);
      fmtR = supportedFormat(gl.R16F, gl.RED, texType);
    } else {
      fmtRGBA = fmtRG = fmtR = supportedFormat(gl.RGBA, gl.RGBA, texType);
    }
    if (!fmtRGBA || !fmtRG || !fmtR) {
      console.warn("Splash cursor: float textures are not supported");
      canvas.remove(); return;
    }

    // ---------- Shaders ----------
    function compile(type, src, defs) {
      if (defs) src = defs.map(function (d) { return "#define " + d + "\n"; }).join("") + src;
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) console.warn(gl.getShaderInfoLog(s));
      return s;
    }
    const vs = compile(gl.VERTEX_SHADER, `
      precision highp float;
      attribute vec2 aPosition;
      varying vec2 vUv; varying vec2 vL; varying vec2 vR; varying vec2 vT; varying vec2 vB;
      uniform vec2 texelSize;
      void main () {
        vUv = aPosition * 0.5 + 0.5;
        vL = vUv - vec2(texelSize.x, 0.0);
        vR = vUv + vec2(texelSize.x, 0.0);
        vT = vUv + vec2(0.0, texelSize.y);
        vB = vUv - vec2(0.0, texelSize.y);
        gl_Position = vec4(aPosition, 0.0, 1.0);
      }`);
    function makeProgram(fsSrc, defs) {
      const p = gl.createProgram();
      gl.attachShader(p, vs);
      gl.attachShader(p, compile(gl.FRAGMENT_SHADER, fsSrc, defs));
      gl.bindAttribLocation(p, 0, "aPosition");
      gl.linkProgram(p);
      if (!gl.getProgramParameter(p, gl.LINK_STATUS)) console.warn(gl.getProgramInfoLog(p));
      const u = {};
      const n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
      for (let i = 0; i < n; i++) {
        const name = gl.getActiveUniform(p, i).name;
        u[name] = gl.getUniformLocation(p, name);
      }
      return {u: u, use: function () { gl.useProgram(p); }};
    }
    const HEAD = "precision highp float; precision highp sampler2D; " +
                 "varying vec2 vUv; varying vec2 vL; varying vec2 vR; " +
                 "varying vec2 vT; varying vec2 vB;\n";

    const clearProg = makeProgram(HEAD + `
      uniform sampler2D uTexture; uniform float value;
      void main () { gl_FragColor = value * texture2D(uTexture, vUv); }`);

    const displayProg = makeProgram(HEAD + `
      uniform sampler2D uTexture; uniform vec2 texelSize;
      void main () {
        vec3 c = texture2D(uTexture, vUv).rgb;
        #ifdef SHADING
          vec3 lc = texture2D(uTexture, vL).rgb;
          vec3 rc = texture2D(uTexture, vR).rgb;
          vec3 tc = texture2D(uTexture, vT).rgb;
          vec3 bc = texture2D(uTexture, vB).rgb;
          float dx = length(rc) - length(lc);
          float dy = length(tc) - length(bc);
          vec3 n = normalize(vec3(dx, dy, length(texelSize)));
          vec3 l = vec3(0.0, 0.0, 1.0);
          float diffuse = clamp(dot(n, l) + 0.7, 0.7, 1.0);
          c *= diffuse;
        #endif
        float a = max(c.r, max(c.g, c.b));
        gl_FragColor = vec4(c, a);
      }`, config.SHADING ? ["SHADING"] : null);

    const splatProg = makeProgram(HEAD + `
      uniform sampler2D uTarget; uniform float aspectRatio;
      uniform vec3 color; uniform vec2 point; uniform float radius;
      void main () {
        vec2 p = vUv - point.xy;
        p.x *= aspectRatio;
        vec3 splat = exp(-dot(p, p) / radius) * color;
        vec3 base = texture2D(uTarget, vUv).xyz;
        gl_FragColor = vec4(base + splat, 1.0);
      }`);

    const advectionProg = makeProgram(HEAD + `
      uniform sampler2D uVelocity; uniform sampler2D uSource;
      uniform vec2 texelSize; uniform vec2 dyeTexelSize;
      uniform float dt; uniform float dissipation;
      vec4 bilerp (sampler2D sam, vec2 uv, vec2 tsize) {
        vec2 st = uv / tsize - 0.5;
        vec2 iuv = floor(st); vec2 fuv = fract(st);
        vec4 a = texture2D(sam, (iuv + vec2(0.5, 0.5)) * tsize);
        vec4 b = texture2D(sam, (iuv + vec2(1.5, 0.5)) * tsize);
        vec4 c = texture2D(sam, (iuv + vec2(0.5, 1.5)) * tsize);
        vec4 d = texture2D(sam, (iuv + vec2(1.5, 1.5)) * tsize);
        return mix(mix(a, b, fuv.x), mix(c, d, fuv.x), fuv.y);
      }
      void main () {
        #ifdef MANUAL_FILTERING
          vec2 coord = vUv - dt * bilerp(uVelocity, vUv, texelSize).xy * texelSize;
          vec4 result = bilerp(uSource, coord, dyeTexelSize);
        #else
          vec2 coord = vUv - dt * texture2D(uVelocity, vUv).xy * texelSize;
          vec4 result = texture2D(uSource, coord);
        #endif
        float decay = 1.0 + dissipation * dt;
        gl_FragColor = result / decay;
      }`, linearOK ? null : ["MANUAL_FILTERING"]);

    const divergenceProg = makeProgram(HEAD + `
      uniform sampler2D uVelocity;
      void main () {
        float L = texture2D(uVelocity, vL).x;
        float R = texture2D(uVelocity, vR).x;
        float T = texture2D(uVelocity, vT).y;
        float B = texture2D(uVelocity, vB).y;
        vec2 C = texture2D(uVelocity, vUv).xy;
        if (vL.x < 0.0) { L = -C.x; }
        if (vR.x > 1.0) { R = -C.x; }
        if (vT.y > 1.0) { T = -C.y; }
        if (vB.y < 0.0) { B = -C.y; }
        float div = 0.5 * (R - L + T - B);
        gl_FragColor = vec4(div, 0.0, 0.0, 1.0);
      }`);

    const curlProg = makeProgram(HEAD + `
      uniform sampler2D uVelocity;
      void main () {
        float L = texture2D(uVelocity, vL).y;
        float R = texture2D(uVelocity, vR).y;
        float T = texture2D(uVelocity, vT).x;
        float B = texture2D(uVelocity, vB).x;
        float vorticity = R - L - T + B;
        gl_FragColor = vec4(0.5 * vorticity, 0.0, 0.0, 1.0);
      }`);

    const vorticityProg = makeProgram(HEAD + `
      uniform sampler2D uVelocity; uniform sampler2D uCurl;
      uniform float curl; uniform float dt;
      void main () {
        float L = texture2D(uCurl, vL).x;
        float R = texture2D(uCurl, vR).x;
        float T = texture2D(uCurl, vT).x;
        float B = texture2D(uCurl, vB).x;
        float C = texture2D(uCurl, vUv).x;
        vec2 force = 0.5 * vec2(abs(T) - abs(B), abs(R) - abs(L));
        force /= length(force) + 0.0001;
        force *= curl * C;
        force.y *= -1.0;
        vec2 velocity = texture2D(uVelocity, vUv).xy;
        velocity += force * dt;
        velocity = min(max(velocity, -1000.0), 1000.0);
        gl_FragColor = vec4(velocity, 0.0, 1.0);
      }`);

    const pressureProg = makeProgram(HEAD + `
      uniform sampler2D uPressure; uniform sampler2D uDivergence;
      void main () {
        float L = texture2D(uPressure, vL).x;
        float R = texture2D(uPressure, vR).x;
        float T = texture2D(uPressure, vT).x;
        float B = texture2D(uPressure, vB).x;
        float divergence = texture2D(uDivergence, vUv).x;
        float pressure = (L + R + B + T - divergence) * 0.25;
        gl_FragColor = vec4(pressure, 0.0, 0.0, 1.0);
      }`);

    const gradientProg = makeProgram(HEAD + `
      uniform sampler2D uPressure; uniform sampler2D uVelocity;
      void main () {
        float L = texture2D(uPressure, vL).x;
        float R = texture2D(uPressure, vR).x;
        float T = texture2D(uPressure, vT).x;
        float B = texture2D(uPressure, vB).x;
        vec2 velocity = texture2D(uVelocity, vUv).xy;
        velocity.xy -= vec2(R - L, T - B);
        gl_FragColor = vec4(velocity, 0.0, 1.0);
      }`);

    // ---------- Full-screen quad ----------
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, -1, 1, 1, 1, 1, -1]), gl.STATIC_DRAW);
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint16Array([0, 1, 2, 0, 2, 3]), gl.STATIC_DRAW);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    gl.enableVertexAttribArray(0);

    function blit(target) {
      if (target == null) {
        gl.viewport(0, 0, gl.drawingBufferWidth, gl.drawingBufferHeight);
        gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      } else {
        gl.viewport(0, 0, target.width, target.height);
        gl.bindFramebuffer(gl.FRAMEBUFFER, target.fbo);
      }
      gl.drawElements(gl.TRIANGLES, 6, gl.UNSIGNED_SHORT, 0);
    }

    // ---------- Framebuffers ----------
    function createFBO(w, h, internalFormat, format, type, filter) {
      gl.activeTexture(gl.TEXTURE0);
      const texture = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, filter);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, filter);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.texImage2D(gl.TEXTURE_2D, 0, internalFormat, w, h, 0, format, type, null);
      const fbo = gl.createFramebuffer();
      gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0);
      gl.viewport(0, 0, w, h);
      gl.clear(gl.COLOR_BUFFER_BIT);
      return {
        texture: texture, fbo: fbo, width: w, height: h,
        texelSizeX: 1 / w, texelSizeY: 1 / h,
        attach: function (id) {
          gl.activeTexture(gl.TEXTURE0 + id);
          gl.bindTexture(gl.TEXTURE_2D, texture);
          return id;
        }
      };
    }
    function createDoubleFBO(w, h, internalFormat, format, type, filter) {
      let a = createFBO(w, h, internalFormat, format, type, filter);
      let b = createFBO(w, h, internalFormat, format, type, filter);
      return {
        width: w, height: h, texelSizeX: a.texelSizeX, texelSizeY: a.texelSizeY,
        get read() { return a; }, set read(v) { a = v; },
        get write() { return b; }, set write(v) { b = v; },
        swap: function () { const t = a; a = b; b = t; }
      };
    }
    function getResolution(res) {
      let aspect = gl.drawingBufferWidth / gl.drawingBufferHeight;
      if (aspect < 1) aspect = 1 / aspect;
      const min = Math.round(res), max = Math.round(res * aspect);
      return gl.drawingBufferWidth > gl.drawingBufferHeight
        ? {width: max, height: min} : {width: min, height: max};
    }

    let dye, velocity, divergence, curl, pressure;
    function initFramebuffers() {
      const simRes = getResolution(config.SIM_RESOLUTION);
      const dyeRes = getResolution(config.DYE_RESOLUTION);
      const filtering = linearOK ? gl.LINEAR : gl.NEAREST;
      gl.disable(gl.BLEND);
      dye = createDoubleFBO(dyeRes.width, dyeRes.height, fmtRGBA.internalFormat, fmtRGBA.format, texType, filtering);
      velocity = createDoubleFBO(simRes.width, simRes.height, fmtRG.internalFormat, fmtRG.format, texType, filtering);
      divergence = createFBO(simRes.width, simRes.height, fmtR.internalFormat, fmtR.format, texType, gl.NEAREST);
      curl = createFBO(simRes.width, simRes.height, fmtR.internalFormat, fmtR.format, texType, gl.NEAREST);
      pressure = createDoubleFBO(simRes.width, simRes.height, fmtR.internalFormat, fmtR.format, texType, gl.NEAREST);
    }

    // ---------- Colours ----------
    function HSVtoRGB(h, s, v) {
      const i = Math.floor(h * 6), f = h * 6 - i;
      const p = v * (1 - s), q = v * (1 - f * s), t = v * (1 - (1 - f) * s);
      let r, g, b;
      switch (i % 6) {
        case 0: r = v; g = t; b = p; break;
        case 1: r = q; g = v; b = p; break;
        case 2: r = p; g = v; b = t; break;
        case 3: r = p; g = q; b = v; break;
        case 4: r = t; g = p; b = v; break;
        default: r = v; g = p; b = q;
      }
      return {r: r, g: g, b: b};
    }
    function generateColor() {
      // rainbow=false keeps the splashes in the cyan-to-blue range of the theme
      const h = CFG.rainbow ? Math.random() : 0.48 + Math.random() * 0.16;
      const c = HSVtoRGB(h, 1.0, 1.0);
      const k = 0.15 * CFG.intensity;
      c.r *= k; c.g *= k; c.b *= k;
      return c;
    }
    function wrap(v, min, max) {
      const range = max - min;
      return range === 0 ? min : ((v - min) % range) + min;
    }

    // ---------- Pointer ----------
    const pointer = {texcoordX: 0, texcoordY: 0, prevTexcoordX: 0, prevTexcoordY: 0,
                     deltaX: 0, deltaY: 0, moved: false, ready: false, color: generateColor()};
    function correctDeltaX(d) { const a = canvas.width / canvas.height; return a < 1 ? d * a : d; }
    function correctDeltaY(d) { const a = canvas.width / canvas.height; return a > 1 ? d / a : d; }
    function correctRadius(r) { const a = canvas.width / canvas.height; return a > 1 ? r * a : r; }

    function moveTo(clientX, clientY) {
      const x = clientX / P.innerWidth, y = 1 - clientY / P.innerHeight;
      if (!pointer.ready) {                      // first move: no giant jump
        pointer.texcoordX = x; pointer.texcoordY = y; pointer.ready = true; return;
      }
      pointer.prevTexcoordX = pointer.texcoordX;
      pointer.prevTexcoordY = pointer.texcoordY;
      pointer.texcoordX = x; pointer.texcoordY = y;
      pointer.deltaX = correctDeltaX(pointer.texcoordX - pointer.prevTexcoordX);
      pointer.deltaY = correctDeltaY(pointer.texcoordY - pointer.prevTexcoordY);
      pointer.moved = Math.abs(pointer.deltaX) > 0 || Math.abs(pointer.deltaY) > 0;
    }
    function onMouseMove(e) { moveTo(e.clientX, e.clientY); }
    function onTouchMove(e) {
      const t = e.targetTouches[0]; if (t) moveTo(t.clientX, t.clientY);
    }
    function onDown(e) {
      if (!CFG.clickSplash) return;
      const t = (e.targetTouches && e.targetTouches[0]) || e;
      const c = generateColor();
      c.r *= 10; c.g *= 10; c.b *= 10;
      splat(t.clientX / P.innerWidth, 1 - t.clientY / P.innerHeight,
            10 * (Math.random() - 0.5), 30 * (Math.random() - 0.5), c);
    }

    // ---------- Simulation ----------
    function splat(x, y, dx, dy, color) {
      splatProg.use();
      gl.uniform1i(splatProg.u.uTarget, velocity.read.attach(0));
      gl.uniform1f(splatProg.u.aspectRatio, canvas.width / canvas.height);
      gl.uniform2f(splatProg.u.point, x, y);
      gl.uniform3f(splatProg.u.color, dx, dy, 0.0);
      gl.uniform1f(splatProg.u.radius, correctRadius(config.SPLAT_RADIUS / 100));
      blit(velocity.write); velocity.swap();
      gl.uniform1i(splatProg.u.uTarget, dye.read.attach(0));
      gl.uniform3f(splatProg.u.color, color.r, color.g, color.b);
      blit(dye.write); dye.swap();
    }

    function step(dt) {
      gl.disable(gl.BLEND);

      curlProg.use();
      gl.uniform2f(curlProg.u.texelSize, velocity.texelSizeX, velocity.texelSizeY);
      gl.uniform1i(curlProg.u.uVelocity, velocity.read.attach(0));
      blit(curl);

      vorticityProg.use();
      gl.uniform2f(vorticityProg.u.texelSize, velocity.texelSizeX, velocity.texelSizeY);
      gl.uniform1i(vorticityProg.u.uVelocity, velocity.read.attach(0));
      gl.uniform1i(vorticityProg.u.uCurl, curl.attach(1));
      gl.uniform1f(vorticityProg.u.curl, config.CURL);
      gl.uniform1f(vorticityProg.u.dt, dt);
      blit(velocity.write); velocity.swap();

      divergenceProg.use();
      gl.uniform2f(divergenceProg.u.texelSize, velocity.texelSizeX, velocity.texelSizeY);
      gl.uniform1i(divergenceProg.u.uVelocity, velocity.read.attach(0));
      blit(divergence);

      clearProg.use();
      gl.uniform1i(clearProg.u.uTexture, pressure.read.attach(0));
      gl.uniform1f(clearProg.u.value, config.PRESSURE);
      blit(pressure.write); pressure.swap();

      pressureProg.use();
      gl.uniform2f(pressureProg.u.texelSize, velocity.texelSizeX, velocity.texelSizeY);
      gl.uniform1i(pressureProg.u.uDivergence, divergence.attach(0));
      for (let i = 0; i < config.PRESSURE_ITERATIONS; i++) {
        gl.uniform1i(pressureProg.u.uPressure, pressure.read.attach(1));
        blit(pressure.write); pressure.swap();
      }

      gradientProg.use();
      gl.uniform2f(gradientProg.u.texelSize, velocity.texelSizeX, velocity.texelSizeY);
      gl.uniform1i(gradientProg.u.uPressure, pressure.read.attach(0));
      gl.uniform1i(gradientProg.u.uVelocity, velocity.read.attach(1));
      blit(velocity.write); velocity.swap();

      advectionProg.use();
      gl.uniform2f(advectionProg.u.texelSize, velocity.texelSizeX, velocity.texelSizeY);
      if (!linearOK) gl.uniform2f(advectionProg.u.dyeTexelSize, velocity.texelSizeX, velocity.texelSizeY);
      const vId = velocity.read.attach(0);
      gl.uniform1i(advectionProg.u.uVelocity, vId);
      gl.uniform1i(advectionProg.u.uSource, vId);
      gl.uniform1f(advectionProg.u.dt, dt);
      gl.uniform1f(advectionProg.u.dissipation, config.VELOCITY_DISSIPATION);
      blit(velocity.write); velocity.swap();

      if (!linearOK) gl.uniform2f(advectionProg.u.dyeTexelSize, dye.texelSizeX, dye.texelSizeY);
      gl.uniform1i(advectionProg.u.uVelocity, velocity.read.attach(0));
      gl.uniform1i(advectionProg.u.uSource, dye.read.attach(1));
      gl.uniform1f(advectionProg.u.dissipation, config.DENSITY_DISSIPATION);
      blit(dye.write); dye.swap();
    }

    function render() {
      gl.disable(gl.BLEND);
      displayProg.use();
      gl.uniform2f(displayProg.u.texelSize, 1 / gl.drawingBufferWidth, 1 / gl.drawingBufferHeight);
      gl.uniform1i(displayProg.u.uTexture, dye.read.attach(0));
      blit(null);
    }

    function resizeCanvas() {
      const d = Math.min(P.devicePixelRatio || 1, 2);
      const w = Math.floor(P.innerWidth * d), h = Math.floor(P.innerHeight * d);
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w; canvas.height = h; return true;
      }
      return false;
    }

    // ---------- Main loop ----------
    let lastTime = Date.now(), colorTimer = 0, raf;
    resizeCanvas();
    initFramebuffers();

    if (CFG.intro) {                              // intro splashes
      const n = Math.floor(Math.random() * 4) + 4;
      for (let i = 0; i < n; i++) {
        const c = generateColor();
        c.r *= 10; c.g *= 10; c.b *= 10;
        splat(Math.random(), Math.random(),
              1000 * (Math.random() - 0.5), 1000 * (Math.random() - 0.5), c);
      }
    }

    function update() {
      const now = Date.now();
      const dt = Math.min((now - lastTime) / 1000, 0.016666);
      lastTime = now;
      if (resizeCanvas()) initFramebuffers();

      colorTimer += dt * config.COLOR_UPDATE_SPEED;
      if (colorTimer >= 1) { colorTimer = wrap(colorTimer, 0, 1); pointer.color = generateColor(); }

      if (pointer.moved) {
        pointer.moved = false;
        splat(pointer.texcoordX, pointer.texcoordY,
              pointer.deltaX * config.SPLAT_FORCE, pointer.deltaY * config.SPLAT_FORCE,
              pointer.color);
      }
      step(dt);
      render();
      raf = P.requestAnimationFrame(update);
    }
    raf = P.requestAnimationFrame(update);

    P.addEventListener("mousemove", onMouseMove, {passive: true});
    P.addEventListener("touchmove", onTouchMove, {passive: true});
    P.addEventListener("mousedown", onDown);
    P.addEventListener("touchstart", onDown, {passive: true});

    P.__splashCursorCleanup = function () {
      P.cancelAnimationFrame(raf);
      P.removeEventListener("mousemove", onMouseMove);
      P.removeEventListener("touchmove", onTouchMove);
      P.removeEventListener("mousedown", onDown);
      P.removeEventListener("touchstart", onDown);
      canvas.remove();
    };
  } catch (err) {
    console.warn("Splash cursor could not start:", err);
  }
})();
</script>
"""
components.html(SPLASH_CURSOR_JS, height=0)


# ------------------------------------------------------------- MODEL + HELPERS
@st.cache_resource
def get_model():
    return load_model()


@st.cache_data
def get_examples():
    return pd.read_csv(BASE_DIR / "data" / "examples.csv")


model, columns, options = get_model()
examples = get_examples()


def _cell(value):
    """HTML-safe text; class names (Normal, DOS, ...) become coloured badges."""
    text = html.escape(str(value))
    if text in CLASS_ORDER:
        color = CLASS_COLORS[CLASS_ORDER.index(text)]
        return f'<span class="tl-badge" style="--b:{color}">{text}</span>'
    return text


def show_table(data, index=True, max_rows=500):
    """Themed table that matches the background (replaces st.dataframe)."""
    df = data.to_frame() if isinstance(data, pd.Series) else data.copy()
    truncated = len(df) > max_rows
    if truncated:
        df = df.head(max_rows)
    df = df.apply(lambda col: col.map(_cell))
    df.columns = [html.escape(str(c)) for c in df.columns]
    if index:
        df.index = [_cell(i) for i in df.index]
    table = df.to_html(index=index, border=0, classes="tl-table", escape=False)
    table = table.replace("\n", "")
    st.markdown(f'<div class="tl-table-wrap">{table}</div>', unsafe_allow_html=True)
    if truncated:
        st.markdown(f'<p class="tl-wrap-note">Showing the first {max_rows} rows. '
                    'Download the results to get every row.</p>',
                    unsafe_allow_html=True)


def show_chart(chart):
    """Draw an Altair chart with light axis text so it is readable on dark."""
    chart = (chart
             .configure(background="transparent")
             .configure_axis(labelColor=TEXT, titleColor=TEXT,
                             gridColor="rgba(255,255,255,0.12)",
                             domainColor="rgba(255,255,255,0.40)",
                             tickColor="rgba(255,255,255,0.40)")
             .configure_title(color=TEXT)
             .configure_legend(labelColor=TEXT, titleColor=TEXT)
             .configure_view(strokeWidth=0))
    try:                                   # newer Streamlit versions
        st.altair_chart(chart, width="stretch", theme=None)
    except TypeError:                      # older Streamlit versions
        st.altair_chart(chart, use_container_width=True, theme=None)


def class_bar_chart(series, value_name, title=None):
    """Colored bar chart with rounded, outlined bars. `series` is indexed by class."""
    df = series.rename_axis("Class").reset_index(name=value_name)
    order = [c for c in CLASS_ORDER if c in set(df["Class"])]
    order += [c for c in df["Class"] if c not in order]
    colors = [CLASS_COLORS[CLASS_ORDER.index(c)] if c in CLASS_ORDER else "#9aa7bd"
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
    color = SEVERITY_COLOR.get(sev, "#9aa7bd")
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
    show_chart(class_bar_chart(share_series, "Vote share"))
    ordered = share_series.sort_values(ascending=False)
    show_table(ordered.map(lambda v: f"{v:.1%}").rename("Vote share"))


st.markdown(
    '<div class="hero">'
    '<div class="hero-title">Threat Lens</div>'
    '<div class="hero-sub">Network intrusion detection: classify a network '
    'connection as Normal, DOS, PROBE, R2L or U2R.</div>'
    '</div>',
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
        show_table(pd.Series(row).astype(str).rename("value"))

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
                       file_name="threat_lens_template.csv", mime="text/csv")

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
                    show_table(counts.rename("Rows"))
                with right:
                    show_chart(class_bar_chart(counts, "Rows",
                                               title="Classification summary"))

                show_table(pred_table, index=False)
                st.download_button("Download results",
                                   pred_table.to_csv(index=False),
                                   file_name="threat_lens_results.csv",
                                   mime="text/csv")

# ---------- Tab 4: model insights ----------
with tab_insights:
    results = load_test_results()
    classes = results["classes"]

    st.subheader("The algorithm: Random Forest")
    st.write(
        "Threat Lens uses a Random Forest of 100 decision trees. Each tree is "
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
    show_chart(
        alt.Chart(imp_df).mark_bar(
            cornerRadiusTopRight=8, cornerRadiusBottomRight=8,
            stroke="rgba(0,0,0,0.35)", strokeWidth=1.5, color=ACCENT
        ).encode(
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
        color=alt.Color("Share:Q", scale=alt.Scale(scheme="tealblues", domain=[0, 1])))
    numbers = cm_base.mark_text().encode(
        text="Rows:Q",
        color=alt.condition(alt.datum.Share > 0.5,
                            alt.value("white"), alt.value("black")))
    show_chart(heat + numbers)

    # --- Recall per class ---
    st.subheader("Share of each real class the model got right (recall)")
    recall = pd.Series(
        {c: (cm.loc[c, c] / cm.loc[c].sum()) if cm.loc[c].sum() else 0.0
         for c in classes})
    show_chart(
        class_bar_chart(recall, "Recall").encode(
            y=alt.Y("Recall:Q", scale=alt.Scale(domain=[0, 1]))))

    # --- Seen vs never seen ---
    st.subheader("Attack names seen vs never seen in training")
    seen = pd.DataFrame(results["seen_vs_unseen"]).T.reset_index()
    seen = seen.rename(columns={seen.columns[0]: "Attack names"})
    value_col = "Correct" if "Correct" in seen.columns else seen.columns[-1]
    show_chart(
        alt.Chart(seen).mark_bar(
            cornerRadiusTopLeft=8, cornerRadiusTopRight=8,
            stroke="rgba(0,0,0,0.35)", strokeWidth=1.5, color="#34d399"
        ).encode(
            x=alt.X("Attack names:N", sort=None),
            y=alt.Y(f"{value_col}:Q", scale=alt.Scale(domain=[0, 1]))))
    st.caption("Seen attacks still fail when they are rare in training: "
               "guess_passwd (53 training rows) was never classified correctly "
               "in the test file.")