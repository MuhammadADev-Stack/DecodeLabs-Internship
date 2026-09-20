import streamlit as st
import json
import sys
import os

# Ensure engine modules are in path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from engine import PhishingTriageEngine

# Page Config
st.set_page_config(
    page_title="Phishing Threat Triage Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Initialize Theme State
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'

# Top Header Bar with Theme Switcher Toggle
col_title, col_theme = st.columns([4, 1])

with col_theme:
    st.write("") # Spacing alignment
    is_dark = st.toggle("🌙 Dark Mode", value=(st.session_state.theme == 'dark'))
    st.session_state.theme = 'dark' if is_dark else 'light'

with col_title:
    st.title("🛡️ Phishing Threat Triage Engine")
    st.caption("DecodeLabs Cyber Security Project 3 — Automated Threat Inspection")

# Dynamic Theme CSS Styles
if st.session_state.theme == 'dark':
    theme_css = """
    <style>
    .stApp {
        background-color: #0B0F19;
        color: #F3F4F6;
    }
    .metric-card {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 20px;
        backdrop-filter: blur(10px);
        color: #F3F4F6;
    }
    .badge-safe {
        color: #10B981;
        background: rgba(16, 185, 129, 0.15);
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-suspicious {
        color: #F59E0B;
        background: rgba(245, 158, 11, 0.15);
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-malicious {
        color: #EF4444;
        background: rgba(239, 68, 68, 0.15);
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
    }
    </style>
    """
else:
    theme_css = """
    <style>
    .stApp {
        background-color: #F8FAFC;
        color: #0F172A;
    }
    .metric-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        color: #0F172A;
    }
    .badge-safe {
        color: #047857;
        background: #D1FAE5;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-suspicious {
        color: #B45309;
        background: #FEF3C7;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-malicious {
        color: #B91C1C;
        background: #FEE2E2;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: bold;
        display: inline-block;
    }
    </style>
    """

st.markdown(theme_css, unsafe_allow_html=True)
st.divider()

# Input Layout
col_input1, col_input2 = st.columns([1, 1])

with col_input1:
    st.subheader("1. Email Headers & Identifiers")
    from_header = st.text_input("From Header", "DecodeLabs Security <login-admin@decodelabs.tech.secure-update.com>")
    reply_to = st.text_input("Reply-To", "hacker-collect@gmail.com")
    return_path = st.text_input("Return-Path", "bounce@secure-update.com")
    auth_results = st.text_input("Authentication-Results", "spf=fail dmarc=fail")

    st.subheader("2. Target URLs")
    raw_urls = st.text_area(
        "Enter links (one per line)",
        "https://www.decodelabs.tech.login-update.com/verify-account\nhttp://amaz0n-security.xyz/login",
        height=100
    )

with col_input2:
    st.subheader("3. Message Body & Attachments")
    body_text = st.text_area(
        "Email / Message Content",
        "URGENT: Your account password will expire in 2 hours. Click the link above or scan the QR code to verify immediately.",
        height=180
    )
    raw_attachments = st.text_input("Attachments (comma-separated)", "Invoice_March2026.iso")

st.divider()

if st.button("🚀 Run Threat Analysis", type="primary", use_container_width=True):
    engine = PhishingTriageEngine()

    headers = {
        "From": from_header,
        "Reply-To": reply_to,
        "Return-Path": return_path,
        "Authentication-Results": auth_results
    }
    urls = [u.strip() for u in raw_urls.split("\n") if u.strip()]
    attachments = [a.strip() for a in raw_attachments.split(",") if a.strip()]

    report = engine.evaluate(headers=headers, urls=urls, body=body_text, attachments=attachments)

    # Output Section
    res_col1, res_col2 = st.columns([1, 2])

    with res_col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown("### Threat Classification")
        if report.threat_level == "MALICIOUS":
            st.markdown(f'<div class="badge-malicious">🚨 MALICIOUS</div>', unsafe_allow_html=True)
        elif report.threat_level == "SUSPICIOUS":
            st.markdown(f'<div class="badge-suspicious">⚠️ SUSPICIOUS</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="badge-safe">✅ SAFE</div>', unsafe_allow_html=True)

        st.metric("Risk Score", f"{report.risk_score} / 100")
        st.progress(report.risk_score / 100)
        st.markdown('</div>', unsafe_allow_html=True)

    with res_col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown("### Recommended SOC Action")
        st.info(report.recommended_action)
        st.markdown('</div>', unsafe_allow_html=True)

    st.divider()

    # Detailed Findings Tabs
    tab1, tab2, tab3 = st.tabs(["📧 Header Findings", "🔗 URL Findings", "📄 Content Findings"])

    with tab1:
        if report.header_findings:
            for item in report.header_findings:
                st.error(f"• {item}")
        else:
            st.success("No header anomalies detected.")

    with tab2:
        if report.url_findings:
            for item in report.url_findings:
                st.warning(f"• {item}")
        else:
            st.success("No URL anomalies detected.")

    with tab3:
        if report.content_findings:
            for item in report.content_findings:
                st.error(f"• {item}")
        else:
            st.success("No content indicators flagged.")