import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DATABASE = Path("data/processed/soc_alerts.db")

st.set_page_config(
    page_title="Mini SOC Dashboard",
    page_icon="shield",
    layout="wide",
)

st.title("Honeypot-Driven SOC Dashboard")
st.caption("Defensive demonstration using synthetic security events.")

if not DATABASE.exists():
    st.warning("No alert database found.")
    st.code("python -m src.pipeline")
    st.stop()

with sqlite3.connect(DATABASE) as connection:
    alerts = pd.read_sql_query(
        "SELECT * FROM alerts ORDER BY id DESC",
        connection,
    )

col1, col2, col3 = st.columns(3)
col1.metric("Total Alerts", len(alerts))
col2.metric("High Severity", int((alerts["severity"] == "High").sum()))
col3.metric("Unique Source IPs", alerts["src_ip"].nunique())

st.divider()
st.subheader("Security Alerts")
st.dataframe(alerts, use_container_width=True, hide_index=True)

st.subheader("Alerts by Type")
st.bar_chart(alerts["alert_type"].value_counts())

st.subheader("Threat Indicators")
for ip in sorted(alerts["src_ip"].unique()):
    st.code(ip)
