import streamlit as st
import json
from io import BytesIO
from xhtml2pdf import pisa
from recon_modules import run_full_recon, summarize_text

st.set_page_config(page_title="Bug Bounty Recon Toolkit", layout="wide")

# ---------- Dark Theme Styling ----------
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

# ---------- UI ----------
st.title("Bug Bounty Recon Toolkit")
domain = st.text_input("🔍 Enter a domain (e.g. example.com)")
report = {}

if st.button("Run Full Recon") and domain:
    st.info("Running recon... Please wait.")
    report = run_full_recon(domain)
    st.success("✅ Recon complete!")
    st.subheader("📊 Recon Report")

    # Display sections
    for section, content in report.items():
        with st.expander(section):
            if isinstance(content, dict):
                st.json(content)
            elif isinstance(content, list):
                st.code("\n".join(content))
            else:
                st.write(content or "No data.")

    # --- JSON Download Button ---
    st.download_button(
        "📁 Download JSON Report",
        data=json.dumps(report, indent=2),
        file_name=f"{domain}_recon.json",
        mime="application/json"
    )

    # --- PDF Report Button ---
    def generate_pdf(domain, data):
        html = f"<h1>Recon Report for {domain}</h1><hr>"
        for section, content in data.items():
            html += f"<h2>{section}</h2><pre>{json.dumps(content, indent=2)}</pre><hr>"
        pdf = BytesIO()
        pisa.CreatePDF(html, dest=pdf)
        pdf.seek(0)
        return pdf

    pdf_file = generate_pdf(domain, report)
    st.download_button(
        "📄 Download PDF Report",
        data=pdf_file,
        file_name=f"{domain}_report.pdf",
        mime="application/pdf"
    )

    # --- Hugging Face Summary (AI) ---
    if st.checkbox("🧠 Summarize This Report Using AI"):
        summary_input = json.dumps(report, indent=2)[:3000]
        summary = summarize_text(summary_input)
        st.markdown("### 📝 AI Summary")
        st.write(summary)

else:
    st.info("Enter a domain above and click **Run Full Recon** to begin.")