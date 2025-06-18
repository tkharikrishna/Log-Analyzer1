
import os
import re
import streamlit as st
import pandas as pd
from collections import Counter
from datetime import datetime

st.set_page_config(layout="wide")
st.title("📡 AI-Powered Log Anomaly Detector (Upload & Query Enabled)")

# Tabs: Upload + Anomalies, Query by Time
tab1, tab2 = st.tabs(["📂 Upload Logs & Detect Anomalies", "⏱️ Query Logs by Time"])

log_lines = []

with tab1:
    uploaded_files = st.file_uploader("Upload your .txt log files", type="txt", accept_multiple_files=True)
    if uploaded_files:
        for uploaded_file in uploaded_files:
            lines = uploaded_file.read().decode("utf-8", errors="ignore").splitlines()
            log_lines.extend([line.strip() for line in lines])
    else:
        st.warning("Please upload at least one log file to continue.")

    # Keywords and patterns
    keywords = ["timeout", "reset", "down", "error", "alarm", "unreachable", "fail", "reject"]
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    rp_pattern = r"RP\s*\d+"

    # Detect anomalies
    anomalies = []
    ip_counts = Counter()
    rp_counts = Counter()

    for i, line in enumerate(log_lines):
        if any(k in line.lower() for k in keywords):
            timestamp = ""
            if i >= 3:
                for offset in range(1, 4):
                    if "AP time:" in log_lines[i - offset]:
                        timestamp_match = re.search(r"AP time:\s*(\d{8}_\d{6})", log_lines[i - offset])
                        if timestamp_match:
                            timestamp = timestamp_match.group(1)
                            break
            ip_matches = re.findall(ip_pattern, line)
            rp_matches = re.findall(rp_pattern, line, re.IGNORECASE)
            for ip in ip_matches:
                ip_counts[ip] += 1
            for rp in rp_matches:
                rp_counts[rp.upper()] += 1
            anomalies.append({
                "timestamp": timestamp,
                "log": line
            })

    if uploaded_files and st.button("🔍 Show Anomalies"):
        st.subheader("📄 Detected Anomalies")
        st.write(f"Total anomalies found: {len(anomalies)}")
        st.dataframe(pd.DataFrame(anomalies), use_container_width=True)
        st.subheader("📈 Summary Insights")
        if ip_counts:
            top_ip = ip_counts.most_common(1)[0]
            st.write(f"🔹 IP with most anomalies: `{top_ip[0]}` occurred `{top_ip[1]}` times")
        if rp_counts:
            top_rp = rp_counts.most_common(1)[0]
            st.write(f"🔹 RP/Link with most fluctuations: `{top_rp[0]}` occurred `{top_rp[1]}` times")
        if not ip_counts and not rp_counts:
            st.info("No IPs or RPs matched anomaly patterns.")

with tab2:
    if log_lines:
        start_time = st.text_input("Start time (YYYYMMDD_HHMMSS)", value="20240510_000000")
        end_time = st.text_input("End time (YYYYMMDD_HHMMSS)", value="20240510_235959")
        if st.button("🔎 Search Events in Time Range"):
            try:
                start_dt = datetime.strptime(start_time, "%Y%m%d_%H%M%S")
                end_dt = datetime.strptime(end_time, "%Y%m%d_%H%M%S")
                matching_logs = []
                for line in log_lines:
                    match = re.search(r"time:\s*(\d{8}_\d{6})", line)
                    if match:
                        log_time = datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
                        if start_dt <= log_time <= end_dt:
                            matching_logs.append(line)
                st.write(f"Found {len(matching_logs)} log lines between {start_time} and {end_time}")
                for line in matching_logs:
                    st.text(line)
            except ValueError:
                st.error("Invalid date format. Please use YYYYMMDD_HHMMSS.")
    else:
        st.info("Please upload logs in the first tab.")
