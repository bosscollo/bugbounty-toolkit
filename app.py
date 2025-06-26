# app.py

import streamlit as st
import json
from recon_modules import run_full_recon

st.set_page_config(page_title="BugBounty Toolkit", layout="wide")
st.title("Bug Bounty Recon Toolkit")

domain = st.text_input("Enter a domain (e.g., example.com)")

if st.button("Run Full Recon") and domain:
    st.info("Running reconnaissance. Please wait...")

    report = run_full_recon(domain)

    st.success("Reconnaissance complete.")

    st.subheader("Recon Report")

    for section, content in report.items():
        with st.expander(section):
            if isinstance(content, dict):
                st.json(content)
            elif isinstance(content, list):
                st.code("\n".join(content))
            else:
                st.write(content)

    st.download_button(
        "Download Report (JSON)",
        json.dumps(report, indent=2),
        file_name=f"{domain}_recon.json"
    )
