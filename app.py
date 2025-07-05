import streamlit as st
import json
from io import BytesIO
from xhtml2pdf import pisa
from recon_modules import run_full_recon

st.set_page_config(page_title="Bug Bounty Recon Toolkit", layout="wide")

# --- Dark Theme Styling ---
st.markdown("""
<style>
    body, .main, .block-container {
        background-color: #121212;
        color: #E0E0E0;
        font-family: 'Segoe UI', sans-serif;
    }
    h1, h2, h3 { color: #FFFFFF !important; }
    .stTextInput input, .stDownloadButton>button {
        background-color: #1E1E1E;
        color: #FFFFFF;
        border: 1px solid #888888;
    }
    .stButton>button {
        background-color: #333333;
        color: #FFFFFF;
        border: 1px solid #666666;
    }
    .st-expander {
        background-color: #1C1C1C !important;
        border: 1px solid #444444;
    }
    .stCodeBlock, .stCode, pre {
        background-color: #1E1E1E !important;
        color: #CFCFCF !important;
    }
</style>
""", unsafe_allow_html=True)

st.title("Bug Bounty Recon Toolkit")

domain = st.text_input("Enter a domain (e.g., example.com)")
email = st.text_input("Enter an email (for breach check - optional)")

if st.button("Run Full Recon") and domain:
    st.info("Running recon... please wait.")
    report = run_full_recon(domain, email)
    st.success("Recon complete!")
    st.subheader("🔍 Recon Report")

    # Display
    for section, content in report.items():
        with st.expander(section):
            if isinstance(content, dict):
                st.json(content)
            elif isinstance(content, list):
                st.code("\n".join(content))
            else:
                st.write(content)

    # --- JSON Download ---
    st.download_button("Download JSON", json.dumps(report, indent=2), file_name=f"{domain}_report.json", mime="application/json")

    # --- PDF Download ---
    def generate_pdf(domain, data):
        html = f"<h1>Recon Report for {domain}</h1><hr>"
        for section, content in data.items():
            html += f"<h2>{section}</h2><pre>{json.dumps(content, indent=2) if isinstance(content, (list, dict)) else str(content)}</pre><hr>"
        pdf_file = BytesIO()
        pisa.CreatePDF(html, dest=pdf_file)
        pdf_file.seek(0)
        return pdf_file

    pdf_bytes = generate_pdf(domain, report)
    st.download_button("Download PDF", data=pdf_bytes, file_name=f"{domain}_report.pdf", mime="application/pdf")

else:
    st.info("Enter a domain and click **Run Full Recon**.")