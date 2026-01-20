import streamlit as st
import json
from io import BytesIO
from fpdf import FPDF
from recon_modules import run_full_recon

# Page Config
st.set_page_config(page_title="Bug Bounty Recon Toolkit", layout="wide")

# Dark mode styling
st.markdown("""
<style>
body, .main, .block-container {
    background-color: #121212;
    color: #E0E0E0;
    font-family: 'Segoe UI', sans-serif;
}
h1, h2, h3 { color: #FFFFFF !important; }
.stTextInput input {
    background-color: #1E1E1E;
    color: #FFFFFF;
    border: 1px solid #555555;
}
.stButton>button {
    background-color: #333333;
    color: #FFFFFF;
    border: 1px solid #888888;
    padding: 0.5rem 1rem;
}
.stButton>button:hover { background-color: #555555; }
.st-expander {
    background-color: #1C1C1C !important;
    border: 1px solid #444444;
    color: #FFFFFF !important;
}
.stCodeBlock, .stCode, pre {
    background-color: #1E1E1E !important;
    color: #CFCFCF !important;
}
.stDownloadButton>button {
    background-color: #222;
    color: #FFFFFF;
    border: 1px solid #888888;
}
header, footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# App layout
st.title("Bug Bounty Recon Toolkit")

domain = st.text_input("Enter a domain (e.g. example.com)")
report = {}

if st.button("Run Full Recon") and domain:
    st.info("Running recon... Please wait...")
    report = run_full_recon(domain)
    st.success("Recon complete!")

    st.subheader("Recon Report")
    for section, content in report.items():
        with st.expander(section):
            if isinstance(content, dict):
                st.json(content)
            elif isinstance(content, list):
                st.code("\n".join(content))
            else:
                st.write(content or "No data.")

    # PDF Export
    def generate_pdf(domain, data):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.multi_cell(0, 10, f"Recon Report for {domain}\n\n")

        pdf.set_font("Arial", '', 12)
        for section, content in data.items():
            pdf.set_font("Arial", 'B', 14)
            pdf.multi_cell(0, 8, section)
            pdf.set_font("Arial", '', 12)
            if isinstance(content, dict):
                pdf.multi_cell(0, 6, json.dumps(content, indent=2))
            elif isinstance(content, list):
                pdf.multi_cell(0, 6, "\n".join(content))
            else:
                pdf.multi_cell(0, 6, str(content or "No data."))
            pdf.ln(4)
        pdf_buffer = BytesIO()
        pdf.output(pdf_buffer)
        pdf_buffer.seek(0)
        return pdf_buffer

    pdf_file = generate_pdf(domain, report)
    st.download_button(
        "Download PDF Report",
        data=pdf_file,
        file_name=f"{domain}_recon_report.pdf",
        mime="application/pdf"
    )

    st.download_button(
        "Download JSON Report",
        data=json.dumps(report, indent=2),
        file_name=f"{domain}_recon.json",
        mime="application/json"
    )

else:
    st.info("Enter a domain and click **Run Full Recon** to begin.")
