"""ThreatLens — ML-Powered Phishing Detection Dashboard by Rudransh Sharma.
Synapse design system: Vantablack base, Instrument Serif, violet/cyan glows.
"""
from __future__ import annotations
import html as _html
import os
import re
import time
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")

# ---------------------------------------------------------------------------
# Example payloads
# ---------------------------------------------------------------------------
EXAMPLES = {
    "Phishing Email": {
        "ct": "email", "brand": "", "sender": "alerts.secure-verify.net",
        "content": "Dear Customer, verify immediately. Your account will be suspended.\n\nUnusual activity was detected. Please confirm your password at [Account Support](https://secure-login-verify.evil.com/login) to avoid restrictions.",
    },
    "Credential Theft": {
        "ct": "email", "brand": "", "sender": "no-reply.account-secure.com",
        "content": "Dear User, unauthorized login attempt detected. Action required: verify your login credentials and confirm your OTP immediately or your account will be locked.",
    },
    "Smishing SMS": {
        "ct": "sms", "brand": "", "sender": "sms-alert.net",
        "content": "ALERT: Your payment was declined. Update your billing address and credit card details at https://bit.ly/z3k9 or your subscription will be cancelled.",
    },
    "Delivery Scam": {
        "ct": "sms", "brand": "", "sender": "sms-notify.net",
        "content": "Dear Account Holder, your delivery is on hold. Provide OTP and confirm PIN to release: https://delivery-pending-fee.com/confirm",
    },
    "Phishing URL": {
        "ct": "url", "brand": "", "sender": "",
        "content": "https://secure-login-verify.evil.com/account/confirm?redirect=@wallet&session=active",
    },
    "Typosquat URL": {
        "ct": "url", "brand": "", "sender": "",
        "content": "https://paypa1.com/login/verify?session=active",
    },
    "Safe Email": {
        "ct": "email", "brand": "", "sender": "support.example.com",
        "content": "Hi Alex,\n\nThis is a routine update from our support team. You can review your ticket at https://www.example.com/support. No password or payment details are required.\n\nBest regards,\nThe Support Team.",
    },
    "Safe URL": {
        "ct": "url", "brand": "", "sender": "",
        "content": "https://www.example.com/billing/history",
    },
}

PLACEHOLDERS = {
    "email": "Paste a suspicious email here…",
    "sms":   "Paste a suspicious SMS message here…",
    "url":   "https://suspicious-domain.com/login/verify",
}

st.set_page_config(
    page_title="ThreatLens",
    page_icon="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡</text></svg>",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ===========================================================================
# SYNAPSE CSS
# ===========================================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');

/* ── tokens ── */
:root {
  --black:#000000;
  --surface:#0a0a0a;
  --surface2:#0f0f0f;
  --border:rgba(255,32,32,0.08);
  --border2:rgba(255,32,32,0.15);
  --violet:#ff2020;
  --cyan:#ff6060;
  --emerald:#10B981;
  --warn:#F59E0B;
  --danger:#EF4444;
  --text:#ffffff;
  --text2:rgba(255,255,255,0.55);
  --text3:rgba(255,255,255,0.25);
  --glass:rgba(5,5,5,0.85);
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{
  font-family:'Inter',-apple-system,sans-serif!important;
  background:#000000!important;
  color:var(--text)!important;
}
.stApp, [data-testid="stAppViewContainer"], [data-testid="stReportArea"], .main, .block-container, [class*="css"], [data-testid="stVerticalBlock"], [data-testid="stVerticalBlockBorderWrapper"] {
  background: transparent !important;
}

/* ── Lock sidebar open — hide every Streamlit collapse/toggle button ── */
/* The «» collapse button (data-testid covers all Streamlit versions)   */
[data-testid="stSidebarCollapseButton"],
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"],
button[aria-label="Close sidebar"],
button[aria-label="Open sidebar"],
button[aria-label="Collapse sidebar"],
section[data-testid="stSidebar"] > div > div > div > button,
.st-emotion-cache-collapsed,
[data-testid="stSidebarCollapseButton"] { display:none!important; visibility:hidden!important; }

/* Keep sidebar permanently visible and never let it shrink away */
[data-testid="stSidebar"]{
  min-width:240px!important;
  max-width:280px!important;
  transform:none!important;
  transition:none!important;
}
[data-testid="stSidebar"][aria-expanded="false"]{
  display:block!important;
  min-width:240px!important;
  transform:none!important;
}
.main .block-container{padding:0 2rem 4rem!important;max-width:1440px!important}
.stApp>header,#MainMenu,footer,header,[data-testid="stDecoration"],.stDeployButton{
  display:none!important;visibility:hidden!important
}

/* ── MOBILE — hide sidebar entirely, full-width layout ── */
@media (max-width: 768px) {
  [data-testid="stSidebar"],
  [data-testid="stSidebarCollapseButton"],
  [data-testid="collapsedControl"] {
    display:none!important;
    visibility:hidden!important;
    width:0!important;
    min-width:0!important;
  }
  .main .block-container {
    padding:0 1rem 6rem!important;
    max-width:100%!important;
    margin-left:0!important;
  }
  [data-testid="stAppViewContainer"] > .main {
    margin-left:0!important;
    padding-left:0!important;
  }
  .syn-hero { padding:1.5rem 1rem 1.2rem!important; }
  .syn-hero-title { font-size:clamp(2rem,10vw,3rem)!important; }
  .syn-stat-grid { grid-template-columns:repeat(2,1fr)!important; }
  .arch-row { grid-template-columns:1fr!important; }
  .dgrid { grid-template-columns:1fr!important; }
  /* mobile bottom nav bar */
  .mob-nav {
    position:fixed;bottom:0;left:0;right:0;z-index:9999;
    background:rgba(5,0,0,0.97);
    backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
    border-top:1px solid rgba(255,32,32,0.15);
    display:flex!important;justify-content:space-around;align-items:center;
    padding:.6rem 0 .8rem;
  }
  .mob-nav-btn {
    display:flex;flex-direction:column;align-items:center;gap:.2rem;
    background:none;border:none;cursor:pointer;
    font-size:.6rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
    color:rgba(255,255,255,0.4);padding:.3rem .8rem;border-radius:8px;
    transition:color .15s;
  }
  .mob-nav-btn.active { color:#ff6060!important; }
  .mob-nav-icon { font-size:1.1rem;line-height:1; }
}
/* hide mob-nav on desktop */
@media (min-width: 769px) {
  .mob-nav { display:none!important; }
  .mob-about { display:none!important; }
}

/* ── ambient orbs ── */
.stApp::before{
  content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(ellipse 700px 500px at 20% 10%, rgba(255,32,32,0.05) 0%, transparent 70%),
    radial-gradient(ellipse 500px 400px at 80% 80%, rgba(255,96,96,0.03) 0%, transparent 70%),
    radial-gradient(ellipse 400px 300px at 60% 20%, rgba(255,32,32,0.02) 0%, transparent 60%);
}
.stApp::after{
  content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:
    repeating-linear-gradient(135deg,rgba(255,32,32,0.01) 0,rgba(255,32,32,0.01) 1px,transparent 1px,transparent 80px),
    repeating-linear-gradient(45deg,rgba(255,96,96,0.006) 0,rgba(255,96,96,0.006) 1px,transparent 1px,transparent 80px);
}
.main{position:relative;z-index:1}

/* ── sidebar ── */
[data-testid="stSidebar"]{
  background:rgba(10,0,0,0.95)!important;
  backdrop-filter:blur(24px)!important;
  border-right:1px solid var(--border)!important;
}
[data-testid="stSidebar"]>div{padding:0!important}
section[data-testid="stSidebar"] .block-container{padding:1rem!important}
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] div{color:var(--text2)!important}
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3{color:var(--text)!important}

[data-testid="stSidebar"] .stButton>button{
  background:rgba(255,255,255,0.03)!important;
  border:1px solid var(--border)!important;
  color:var(--text2)!important;
  border-radius:8px!important;
  font-size:.78rem!important;font-weight:500!important;
  padding:.45rem .9rem!important;width:100%!important;
  text-align:left!important;
  transition:all .18s cubic-bezier(0.23,1,0.32,1)!important;
  margin-bottom:3px!important;
}
[data-testid="stSidebar"] .stButton>button:hover{
  background:rgba(255,32,32,0.06)!important;
  border-color:rgba(255,32,32,0.3)!important;
  color:var(--text)!important;transform:translateX(3px)!important;
}

/* ── radio ── */
.stRadio>div{gap:.35rem!important}
.stRadio label{
  background:rgba(255,255,255,0.03)!important;
  border:1px solid var(--border)!important;
  border-radius:8px!important;padding:.4rem 1rem!important;
  color:var(--text2)!important;font-size:.83rem!important;font-weight:500!important;
  cursor:pointer!important;transition:all .18s cubic-bezier(0.23,1,0.32,1)!important;
}
.stRadio label:hover{border-color:rgba(255,32,32,0.3)!important;color:var(--text)!important}
.stRadio label[data-checked="true"]{
  background:rgba(255,32,32,0.08)!important;
  border-color:rgba(255,32,32,0.4)!important;
  color:#ff8080!important;
}

/* ── inputs ── */
.stTextArea textarea{
  background:rgba(255,255,255,0.03)!important;
  border:1px solid var(--border)!important;
  border-radius:12px!important;color:var(--text)!important;
  font-family:'JetBrains Mono',monospace!important;
  font-size:.82rem!important;padding:.9rem!important;
  transition:border-color .2s,box-shadow .2s!important;
}
.stTextArea textarea:focus{
  border-color:rgba(255,32,32,0.6)!important;
  box-shadow:0 0 0 3px rgba(255,32,32,0.15),0 0 20px -10px rgba(255,32,32,0.3)!important;
}
.stTextArea label,.stTextInput label{
  color:var(--text3)!important;font-size:.68rem!important;
  font-weight:700!important;letter-spacing:.12em!important;text-transform:uppercase!important;
}
.stTextInput input{
  background:rgba(255,255,255,0.03)!important;
  border:1px solid var(--border)!important;
  border-radius:8px!important;color:var(--text)!important;font-size:.83rem!important;
  transition:border-color .2s,box-shadow .2s!important;
}
.stTextInput input:focus{
  border-color:rgba(255,32,32,0.6)!important;
  box-shadow:0 0 0 3px rgba(255,32,32,0.12)!important;
}

/* ── primary button (shiny border) ── */
div[data-testid="stButton"]>button[kind="primary"]{
  position:relative!important;overflow:hidden!important;
  background:#0a0a0a!important;border:none!important;
  border-radius:9999px!important;
  color:#fff!important;font-family:'Inter',sans-serif!important;
  font-size:.9rem!important;font-weight:600!important;letter-spacing:.03em!important;
  padding:.85rem 2.2rem!important;
  box-shadow:0 0 20px -8px rgba(255,32,32,0.4)!important;
  transition:transform .18s cubic-bezier(0.23,1,0.32,1),box-shadow .18s!important;
  z-index:1!important;
}
div[data-testid="stButton"]>button[kind="primary"]::before{
  content:''!important;position:absolute!important;
  inset:-1px!important;border-radius:9999px!important;
  background:conic-gradient(from 0deg,transparent 0%,#ff2020 40%,#ff6060 50%,transparent 60%)!important;
  z-index:-1!important;
  animation:spin-border 4s linear infinite!important;
}
div[data-testid="stButton"]>button[kind="primary"]::after{
  content:''!important;position:absolute!important;
  inset:1px!important;border-radius:9999px!important;
  background:#0a0a0a!important;z-index:-1!important;
}
div[data-testid="stButton"]>button[kind="primary"]:hover{
  transform:translateY(-2px)!important;
  box-shadow:0 0 32px -6px rgba(255,32,32,0.6)!important;
}
@keyframes spin-border{to{transform:rotate(360deg)}}

/* ── expander ── */
.streamlit-expanderHeader{
  background:rgba(255,255,255,0.03)!important;
  border:1px solid var(--border)!important;border-radius:10px!important;
  color:var(--text2)!important;font-size:.8rem!important;
}
.streamlit-expanderContent{
  background:rgba(0,0,0,0.4)!important;
  border:1px solid var(--border)!important;border-top:none!important;
}
.stSpinner>div{border-top-color:#ff2020!important}
hr{border-color:var(--border)!important;margin:1rem 0!important}
.stMarkdown p{color:var(--text2);line-height:1.6}
.stMarkdown a{color:#ff6060}
</style>""", unsafe_allow_html=True)

# component CSS — cards, stats, verdicts, bars, timeline, etc.
st.markdown("""
<style>
/* ── keyframes ── */
@keyframes shimmer{0%{background-position:200% center}100%{background-position:-200% center}}
@keyframes float-a{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-18px) scale(1.04)}}
@keyframes float-b{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-12px) scale(1.03)}}
@keyframes fade-up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse-dot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
@keyframes scan-line{0%{top:0}100%{top:100%}}

/* ── glass card ── */
.syn-card{
  background:var(--glass)!important;
  background:var(--glass);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border:1px solid var(--border);border-radius:20px;
  padding:1.4rem 1.5rem;margin-bottom:.9rem;
  transition:border-color .22s cubic-bezier(0.23,1,0.32,1),
             box-shadow .22s cubic-bezier(0.23,1,0.32,1),
             transform .22s cubic-bezier(0.23,1,0.32,1);
  animation:fade-up .4s cubic-bezier(0.23,1,0.32,1) both;
}
.syn-card:hover{
  border-color:rgba(255,32,32,0.2);
  box-shadow:0 0 30px -12px rgba(255,32,32,0.25);
  transform:translateY(-2px);
}
.syn-card-lbl{
  font-size:.6rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;
  color:var(--text3);margin-bottom:.85rem;
}

/* ── stat grid ── */
.syn-stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;margin-bottom:.9rem}
.syn-stat{
  background:var(--glass)!important;
  background:var(--glass);backdrop-filter:blur(16px);
  border:1px solid var(--border);border-radius:16px;
  padding:1.1rem 1.25rem;position:relative;overflow:hidden;
  transition:transform .2s cubic-bezier(0.23,1,0.32,1),box-shadow .2s;
  animation:fade-up .4s cubic-bezier(0.23,1,0.32,1) both;
}
.syn-stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;border-radius:16px 16px 0 0}
.ss-v::before{background:linear-gradient(90deg,#ff2020,#b91c1c)}
.ss-c::before{background:linear-gradient(90deg,#ff6060,#d97706)}
.ss-w::before{background:linear-gradient(90deg,#D97706,#F59E0B)}
.ss-r::before{background:linear-gradient(90deg,#B91C1C,#EF4444)}
.ss-g::before{background:linear-gradient(90deg,#059669,#10B981)}
.syn-stat:hover{transform:translateY(-3px);box-shadow:0 12px 30px rgba(0,0,0,0.5)}
.syn-stat .s-lbl{font-size:.58rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--text3);margin-bottom:.5rem}
.syn-stat .s-val{font-size:2rem;font-weight:800;font-family:'JetBrains Mono',monospace;line-height:1}
.syn-stat .s-sub{font-size:.7rem;color:var(--text2);margin-top:.3rem}
.cv{color:#ff6060}.cc{color:#ffa0a0}.cw{color:#fbbf24}.cr{color:#f87171}.cg{color:#34d399}

/* ── verdict badge ── */
.vbadge{display:inline-flex;align-items:center;gap:.35rem;padding:.28rem .85rem;border-radius:9999px;font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.vb-safe{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.3)}
.vb-suspicious{background:rgba(245,158,11,.1);color:#fbbf24;border:1px solid rgba(245,158,11,.3)}
.vb-dangerous{background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.3)}

/* ── category badge ── */
.cbadge{display:inline-flex;align-items:center;gap:.3rem;background:rgba(255,32,32,.1);border:1px solid rgba(255,32,32,.25);border-radius:6px;padding:.26rem .7rem;font-size:.68rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#ff8080}

/* ── bars ── */
.bwrap{margin-bottom:.65rem}
.bhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:.28rem}
.blbl{font-size:.77rem;color:var(--text2);font-weight:500}
.bval{font-size:.73rem;font-family:'JetBrains Mono',monospace;font-weight:600}
.btrack{background:rgba(255,32,32,0.08);border-radius:9999px;height:5px;overflow:hidden}
.bfill{height:5px;border-radius:9999px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bf-v{background:linear-gradient(90deg,#b91c1c,#ff2020)}
.bf-c{background:linear-gradient(90deg,#d97706,#ff6060)}
.bf-g{background:linear-gradient(90deg,#059669,#10B981)}
.bf-w{background:linear-gradient(90deg,#D97706,#F59E0B)}
.bf-r{background:linear-gradient(90deg,#B91C1C,#EF4444)}

/* ── feature bar ── */
.frow{display:flex;align-items:center;gap:.65rem;margin-bottom:.5rem}
.flbl{font-size:.75rem;color:var(--text2);min-width:175px;font-weight:500}
.ftrack{flex:1;background:rgba(255,32,32,0.08);border-radius:9999px;height:6px}
.ffill{height:6px;border-radius:9999px;background:linear-gradient(90deg,#ff2020,#ff6060)}
.fpct{font-size:.72rem;font-family:'JetBrains Mono',monospace;color:#ff6060;min-width:34px;text-align:right}

/* ── scorecard ── */
.scrow{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem}
.sclbl{font-size:.75rem;color:var(--text2);font-weight:500;min-width:155px}
.sctrack{flex:1;background:rgba(255,32,32,0.08);border-radius:9999px;height:4px}
.scfill{height:4px;border-radius:9999px}
.scscore{font-size:.7rem;font-family:'JetBrains Mono',monospace;color:var(--text3);min-width:40px;text-align:right}

/* ── timeline ── */
.tline{position:relative;padding-left:1.8rem}
.tline::before{content:'';position:absolute;left:.42rem;top:.4rem;bottom:.4rem;width:1px;background:var(--border)}
.tstep{position:relative;padding-bottom:1rem}
.tstep:last-child{padding-bottom:0}
.tdot{position:absolute;left:-1.45rem;top:.18rem;width:10px;height:10px;border-radius:50%;border:1.5px solid;display:flex;align-items:center;justify-content:center}
.tdot-inner{width:4px;height:4px;border-radius:50%}
.dp{border-color:#ff2020}.dp .tdot-inner{background:#ff2020}
.dc{border-color:#ff6060}.dc .tdot-inner{background:#ff6060}
.dg{border-color:#10B981}.dg .tdot-inner{background:#10B981}
.dw{border-color:#F59E0B}.dw .tdot-inner{background:#F59E0B}
.dr{border-color:#EF4444}.dr .tdot-inner{background:#EF4444}
.ttitle{font-size:.8rem;font-weight:600;color:var(--text)}
.tdetail{font-size:.72rem;color:var(--text3);margin-top:.08rem;line-height:1.45}

/* ── domain grid ── */
.dgrid{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}
.dcell{background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:10px;padding:.55rem .75rem}
.dclbl{font-size:.58rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--text3);margin-bottom:.18rem}
.dcval{font-size:.78rem;font-family:'JetBrains Mono',monospace;color:rgba(255,255,255,.75);word-break:break-all}

/* ── heatmap ── */
.hw{display:inline;border-radius:3px;padding:1px 3px}
.hw-r{background:rgba(239,68,68,.2);color:#fca5a5}
.hw-o{background:rgba(245,158,11,.2);color:#fde68a}
.hw-b{background:rgba(255,32,32,.2);color:#ff8080}

/* ── typosquat box ── */
.typo-box{background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.2);border-radius:12px;padding:.85rem 1.1rem;margin-top:.6rem}
.typo-t{font-size:.78rem;font-weight:700;color:#fbbf24;margin-bottom:.3rem}

/* ── analyst actions ── */
.aaction{background:rgba(255,255,255,.02);border-left:2px solid;border-radius:0 8px 8px 0;padding:.42rem .85rem;margin-bottom:.35rem;font-size:.77rem;color:var(--text2);line-height:1.4}
.aa-r{border-left-color:#EF4444}.aa-w{border-left-color:#F59E0B}
.aa-g{border-left-color:#10B981}.aa-v{border-left-color:#ff2020}

/* ── scan steps ── */
.sstep{display:flex;align-items:center;gap:.55rem;padding:.3rem 0;font-size:.79rem;color:var(--text3)}
.sdot{width:7px;height:7px;border-radius:50%;background:#ff2020;flex-shrink:0;animation:pulse-dot 1s infinite}
.sstep-done{color:var(--emerald)}.sstep-done .sdot{background:var(--emerald);animation:none}

/* ── divider ── */
.sdiv{display:flex;align-items:center;gap:.75rem;margin:1.3rem 0 1rem}
.sdiv-line{flex:1;height:1px;background:var(--border)}
.sdiv-lbl{font-size:.58rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:var(--text3);white-space:nowrap}

/* ── hero ── */
.syn-hero{padding:3rem 2rem 2rem;border-bottom:1px solid var(--border);margin-bottom:1.5rem;position:relative;overflow:hidden}
.syn-hero-eyebrow{
  font-size:.65rem;font-weight:700;letter-spacing:.22em;text-transform:uppercase;
  margin-bottom:.6rem;
  background:linear-gradient(90deg,#ff2020,#ff6060);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}
.syn-hero-title{
  font-family:'Instrument Serif',serif;
  font-size:clamp(2.8rem,6vw,4.5rem);
  font-weight:400;line-height:.95;
  letter-spacing:-0.03em;margin-bottom:.5rem;color:#fff;
}
.syn-hero-shimmer{
  font-family:'Instrument Serif',serif;font-style:italic;
  background:linear-gradient(90deg,#ff6060 0%,#fff 40%,#fff 60%,#ffa0a0 100%);
  background-size:200% auto;
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
  animation:shimmer 4s linear infinite;
}
.syn-hero-sub{font-size:.93rem;color:var(--text2);line-height:1.65;max-width:560px;margin-top:.6rem;font-weight:300}
.syn-hero-chips{display:flex;gap:.65rem;margin-top:1.1rem;flex-wrap:wrap}
.syn-chip{
  display:inline-flex;align-items:center;gap:.38rem;
  background:rgba(255,255,255,0.04);
  border:1px solid var(--border);border-radius:9999px;
  padding:.25rem .75rem;font-size:.68rem;font-weight:500;color:var(--text2);
}
.syn-chip-dot{width:5px;height:5px;border-radius:50%}

/* ── sidebar elements ── */
.sb-sec{font-size:.55rem;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:var(--text3)!important;padding:.65rem 0 .3rem;border-top:1px solid var(--border);margin-top:.5rem}
.rsitem{display:flex;justify-content:space-between;align-items:center;padding:.35rem 0;border-bottom:1px solid var(--border)}
.rsl{font-size:.71rem;color:var(--text2)}.rst{font-size:.62rem;color:var(--text3);font-family:'JetBrains Mono',monospace}

/* ── input section ── */
.isec{background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:20px;padding:1.6rem;margin-bottom:1.4rem}
.isec-t{font-size:.62rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;color:var(--text3);margin-bottom:1rem}

/* ── about / engineering ── */
.about-card{
  background:var(--glass)!important;background:var(--glass);backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:20px;padding:1.5rem 1.6rem;margin-bottom:.9rem}
.arch-row{display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:.9rem}
.arch-cell{
  background:rgba(255,255,255,0.02)!important;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:12px;padding:1rem 1.1rem}
.arch-cell-t{font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:var(--text3);margin-bottom:.5rem}
.arch-cell-v{font-size:.8rem;color:var(--text2);line-height:1.65}
.roadmap-item{display:flex;gap:.75rem;padding:.55rem 0;border-bottom:1px solid var(--border)}
.rm-tag{font-size:.62rem;font-weight:700;padding:.18rem .5rem;border-radius:5px;white-space:nowrap;flex-shrink:0;align-self:flex-start;margin-top:.1rem}
.rm-done{background:rgba(16,185,129,.15);color:#34d399}
.rm-wip{background:rgba(255,32,32,.12);color:#ff6060}
.rm-plan{background:rgba(255,255,255,.06);color:var(--text3)}
.rm-text{font-size:.79rem;color:var(--text2)}

/* ── footer ── */
.pgfooter{border-top:1px solid var(--border);margin-top:2.5rem;padding-top:1.2rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.75rem}
.pgfooter-l{font-size:.7rem;color:var(--text3)}
.pgfooter-chips{display:flex;gap:.4rem;flex-wrap:wrap}
.pgfooter-chip{background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:9999px;padding:.15rem .6rem;font-size:.64rem;color:var(--text3)}
</style>""", unsafe_allow_html=True)

# ===========================================================================
# HELPERS
# ===========================================================================
def _vcss(v):
    return {"Safe":"safe","Suspicious":"suspicious","Dangerous":"dangerous"}.get(v,"safe")
def _vb(v):
    return {"Safe":"vb-safe","Suspicious":"vb-suspicious","Dangerous":"vb-dangerous"}.get(v,"vb-safe")
def _hx(p):
    return ("#f87171" if p>=70 else ("#fbbf24" if p>=40 else "#34d399"))
def _bc(p):
    return ("bf-r" if p>=70 else ("bf-w" if p>=40 else "bf-g"))
def _dc(sev):
    return {"info":"dp","safe":"dg","suspicious":"dw","dangerous":"dr"}.get(sev,"dp")
def _dcfill(sev):
    return {"info":"#ff2020","safe":"#10B981","suspicious":"#F59E0B","dangerous":"#EF4444"}.get(sev,"#ff2020")

def bar(label, value, max_val=100, fc=None):
    pct = round(value / max_val * 100) if max_val else 0
    cls = fc if fc else _bc(pct)
    return (f'<div class="bwrap"><div class="bhead">'
            f'<span class="blbl">{label}</span>'
            f'<span class="bval" style="color:{_hx(pct)}">{value}'
            f'<span style="color:var(--text3)">/{max_val}</span></span></div>'
            f'<div class="btrack"><div class="bfill {cls}" style="width:{pct}%"></div></div></div>')

def fbar(label, pf):
    pct = round(pf * 100)
    return (f'<div class="frow"><span class="flbl">{label}</span>'
            f'<div class="ftrack"><div class="ffill" style="width:{pct}%"></div></div>'
            f'<span class="fpct">{pct}%</span></div>')

def set_ex(ex):
    st.session_state.content_type  = ex["ct"]
    st.session_state.ex_content    = ex["content"]
    st.session_state.claimed_brand = ex.get("brand", "")
    st.session_state.sender_domain = ex.get("sender", "")

def call_backend(payload):
    try:
        r = requests.post(f"{BACKEND_URL}/analyze", json=payload, timeout=15)
    except requests.exceptions.ConnectionError:
        st.error("Backend offline — run `python run.py`.")
        return None
    except requests.exceptions.Timeout:
        st.error("Request timed out.")
        return None
    if r.status_code == 422:
        st.error(r.json().get("detail", "Invalid input."))
        return None
    if not r.ok:
        st.error("Analysis failed.")
        return None
    return r.json()

# session defaults
for k, v in [
    ("content_type", "email"), ("ex_content", ""), ("claimed_brand", ""),
    ("sender_domain", ""), ("last_result", None), ("last_content", ""),
    ("last_content_type", "email"), ("scan_history", []), ("page", "Scanner"),
]:
    if k not in st.session_state:
        st.session_state[k] = v

# ===========================================================================
# SIDEBAR
# ===========================================================================
with st.sidebar:
    st.markdown("""
<div style="padding:1.4rem 1rem 1rem;border-bottom:1px solid var(--border);margin-bottom:.6rem">
  <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.25rem">
    <div style="width:28px;height:28px;border-radius:8px;
      background:linear-gradient(135deg,#ff2020,#ff6060);
      display:flex;align-items:center;justify-content:center;
      font-size:.65rem;font-weight:900;color:#fff;flex-shrink:0">TL</div>
    <div style="font-family:'Instrument Serif',serif;font-size:1.15rem;color:#fff;letter-spacing:-.01em">ThreatLens</div>
  </div>
  <div style="font-size:.58rem;letter-spacing:.2em;text-transform:uppercase;color:var(--text3);padding-left:38px">
    ML Phishing Detection
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown('<div class="sb-sec">Navigation</div>', unsafe_allow_html=True)
    for pg in ["Scanner", "About", "Engineering"]:
        active = st.session_state.page == pg
        if st.button(pg, key=f"nav_{pg}", use_container_width=True):
            st.session_state.page = pg
            st.rerun()

    st.markdown('<div class="sb-sec">Example Inputs</div>', unsafe_allow_html=True)
    for name in EXAMPLES:
        if st.button(name, key=f"ex_{name}", use_container_width=True):
            set_ex(EXAMPLES[name])
            st.session_state.page = "Scanner"
            st.rerun()

    st.markdown('<div class="sb-sec">Recent Scans</div>', unsafe_allow_html=True)
    history = st.session_state.scan_history[-6:][::-1]
    if history:
        vc = {"Safe": "cg", "Suspicious": "cw", "Dangerous": "cr"}
        for h in history:
            c = vc.get(h["verdict"], "cv")
            st.markdown(
                f'<div class="rsitem"><span class="rsl">{h["label"]}</span>'
                f'<span><span class="{c}" style="font-size:.68rem">{h["verdict"]}</span>'
                f' <span class="rst">{h["time"]}</span></span></div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown('<div style="font-size:.7rem;color:var(--text3);padding:.3rem 0">No scans yet.</div>', unsafe_allow_html=True)

    st.markdown('<div class="sb-sec">Live Threat Feed</div>', unsafe_allow_html=True)
    feed = [
        ("Credential harvesting active", "#f87171"),
        ("Delivery fee smishing wave",   "#fbbf24"),
        ("Account lockout phishing",     "#f87171"),
        ("Crypto wallet drain attempts", "#fbbf24"),
        ("Subscription renewal scam",    "var(--text3)"),
    ]
    for t, c in feed:
        st.markdown(
            f'<div style="font-size:.68rem;color:{c};padding:.2rem 0;'
            f'border-bottom:1px solid var(--border)">{t}</div>',
            unsafe_allow_html=True,
        )

# ===========================================================================
# PAGE ROUTING
# ===========================================================================
page = st.session_state.page

# ===========================================================================
# ABOUT PAGE
# ===========================================================================
if page == "About":
    st.markdown("""
<div class="syn-hero">
  <div class="syn-hero-eyebrow">About the Developer</div>
  <div class="syn-hero-title">Rudransh <span class="syn-hero-shimmer">Sharma</span></div>
  <div class="syn-hero-sub">Designed, trained, and shipped ThreatLens from scratch.</div>
</div>""", unsafe_allow_html=True)

    c1, c2 = st.columns([1.4, 1], gap="large")
    with c1:
        st.markdown("""
<div class="about-card">
  <div style="font-family:'Instrument Serif',serif;font-size:1.6rem;letter-spacing:-.02em;
    background:linear-gradient(135deg,#ff6060,#ffa0a0);
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
    margin-bottom:.2rem">Rudransh Sharma</div>
  <div style="font-size:.8rem;color:var(--text2);margin-bottom:.12rem">
    ML Engineer &nbsp;&middot;&nbsp; Full-Stack Developer &nbsp;&middot;&nbsp; Software Engineering Enthusiast
  </div>
  <div style="font-size:.75rem;color:var(--text3);margin-bottom:1.1rem">
    Vellore Institute of Technology (VIT) &nbsp;&middot;&nbsp; 3rd Year &nbsp;&middot;&nbsp; Graduating 2028
  </div>
  <p style="font-size:.84rem;color:var(--text2);line-height:1.75;margin-bottom:1.1rem">
    I'm an ML Engineering student at VIT Chennai with a strong interest in machine learning,
    cybersecurity, full-stack development, and scalable software engineering. I enjoy building
    intelligent, production-ready applications that combine ML, modern web technologies, and
    intuitive UX — with a focus on explainability and real-world impact.
  </p>
  <div style="display:flex;gap:.5rem;flex-wrap:wrap">
    <a style="display:inline-flex;align-items:center;gap:.35rem;background:rgba(255,255,255,0.04);
      border:1px solid var(--border);border-radius:8px;padding:.38rem .8rem;
      font-size:.76rem;color:#ff6060;text-decoration:none;
      transition:border-color .18s;" href="https://github.com/rudransh27sharma" target="_blank">GitHub</a>
    <a style="display:inline-flex;align-items:center;gap:.35rem;background:rgba(255,255,255,0.04);
      border:1px solid var(--border);border-radius:8px;padding:.38rem .8rem;
      font-size:.76rem;color:#ff6060;text-decoration:none;" href="https://www.linkedin.com/in/rudransh-sharma-/" target="_blank">LinkedIn</a>
    <a style="display:inline-flex;align-items:center;gap:.35rem;background:rgba(255,255,255,0.04);
      border:1px solid var(--border);border-radius:8px;padding:.38rem .8rem;
      font-size:.76rem;color:#ff6060;text-decoration:none;" href="mailto:contact.rudranshsharma@gmail.com">Email</a>
  </div>
</div>""", unsafe_allow_html=True)

    with c2:
        st.markdown("""
<div class="about-card" style="height:100%">
  <div class="syn-card-lbl">About ThreatLens</div>
  <p style="font-size:.82rem;color:var(--text2);line-height:1.72;margin-bottom:.85rem">
    ThreatLens is a phishing detection system built with two separate
    Random Forest classifiers — one for URLs (14 features) and one for
    email/SMS text (11 features). Every verdict comes with traceable,
    feature-level reasoning.
  </p>
  <p style="font-size:.82rem;color:var(--text2);line-height:1.72;margin-bottom:1rem">
    Everything runs locally. No data leaves your machine.
    No third-party APIs. Full inference pipeline under 50 ms.
  </p>
  <div class="syn-card-lbl">Stack</div>
  <div style="display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.3rem">
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff2020"></span>scikit-learn</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff6060"></span>FastAPI</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff6060"></span>Streamlit</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ffa0a0"></span>pandas / numpy</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#10B981"></span>Python 3.12</span>
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown("""
<div class="pgfooter">
  <div class="pgfooter-l">Designed &amp; Developed by Rudransh Sharma &copy; 2026</div>
  <div class="pgfooter-chips">
    <span class="pgfooter-chip">FastAPI</span><span class="pgfooter-chip">Streamlit</span>
    <span class="pgfooter-chip">Random Forest</span><span class="pgfooter-chip">scikit-learn</span>
  </div>
</div>""", unsafe_allow_html=True)

# ===========================================================================
# ENGINEERING PAGE
# ===========================================================================
elif page == "Engineering":
    st.markdown("""
<div class="syn-hero">
  <div class="syn-hero-eyebrow">Under the Hood</div>
  <div class="syn-hero-title">Engineering <span class="syn-hero-shimmer">Internals</span></div>
  <div class="syn-hero-sub">Architecture, model design decisions, performance metrics, and what comes next.</div>
</div>""", unsafe_allow_html=True)

    st.markdown('<div class="sdiv"><div class="sdiv-line"></div><div class="sdiv-lbl">Architecture</div><div class="sdiv-line"></div></div>', unsafe_allow_html=True)
    st.markdown("""
<div class="arch-row">
  <div class="arch-cell">
    <div class="arch-cell-t">System Design</div>
    <div class="arch-cell-v">
      Synthetic dataset &rarr; feature extraction per content type<br>
      &rarr; URL model (14 features)<br>
      &rarr; Text model (11 features)<br>
      &rarr; FastAPI <code style="color:#ff6060">/analyze</code> endpoint<br>
      &rarr; Streamlit dashboard
    </div>
  </div>
  <div class="arch-cell">
    <div class="arch-cell-t">URL Model Features (14)</div>
    <div class="arch-cell-v">
      url_length, num_subdomains, has_ip_address,<br>
      uses_url_shortener, has_https, count_special_chars,<br>
      has_suspicious_keywords, has_at_symbol,<br>
      path_depth, query_param_count, tld_suspicious,<br>
      <span style="color:#ff6060">domain_entropy, digit_ratio_in_domain,<br>
      hyphen_count_in_domain</span>
    </div>
  </div>
  <div class="arch-cell">
    <div class="arch-cell-t">Text Model Features (11)</div>
    <div class="arch-cell-v">
      urgency_score, requests_sensitive_info,<br>
      generic_greeting, link_text_mismatch,<br>
      grammar_error_density, sender_domain_mismatch,<br>
      <span style="color:#ff6060">uppercase_ratio, exclamation_count,<br>
      url_count_in_text, keyword_density,<br>
      suspicious_tld_in_body</span>
    </div>
  </div>
  <div class="arch-cell">
    <div class="arch-cell-t">Training Data</div>
    <div class="arch-cell-v">
      14,970 synthetic samples — 7,570 phishing / 7,400 safe<br>
      URL: 6,970 &nbsp; Email: 6,000 &nbsp; SMS: 2,000<br>
      Stratified 80/20 split &nbsp;&middot;&nbsp; 5-fold CV<br>
      RandomizedSearchCV (30 iters)
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown('<div class="sdiv"><div class="sdiv-line"></div><div class="sdiv-lbl">Model Performance (v4)</div><div class="sdiv-line"></div></div>', unsafe_allow_html=True)
    st.markdown("""
<div class="about-card">
  <div class="syn-card-lbl" style="margin-bottom:.9rem">
    Random Forest vs Logistic Regression &mdash; 80/20 stratified split &bull; 14,970 samples
  </div>
  <div style="display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr 1fr 1fr;gap:0;margin-bottom:.4rem">
    <div style="font-size:.58rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--text3)">Model</div>
    <div style="font-size:.58rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--text3);text-align:right">Acc</div>
    <div style="font-size:.58rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--text3);text-align:right">Prec</div>
    <div style="font-size:.58rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--text3);text-align:right">Recall</div>
    <div style="font-size:.58rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--text3);text-align:right">F1</div>
    <div style="font-size:.58rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--text3);text-align:right">AUC</div>
  </div>
  <!-- URL RF -->
  <div style="display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr 1fr 1fr;gap:0;
    background:rgba(255,32,32,.04);border:1px solid rgba(255,32,32,.18);border-radius:10px;
    padding:.5rem .7rem;margin-bottom:.3rem;align-items:center">
    <div>
      <div style="font-size:.75rem;font-weight:700;color:#ff6060">URL — Random Forest</div>
      <div style="font-size:.63rem;color:var(--text3);margin-top:.08rem">14 features &bull; n_estimators=600 &bull; max_depth=10</div>
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">0.9964</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">0.9972</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">0.9958</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;font-weight:700;text-align:right">0.9965</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">1.0000</div>
  </div>
  <!-- URL LR -->
  <div style="display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr 1fr 1fr;gap:0;
    background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;
    padding:.5rem .7rem;margin-bottom:.75rem;align-items:center">
    <div>
      <div style="font-size:.75rem;font-weight:600;color:var(--text2)">URL — Logistic Regression</div>
      <div style="font-size:.63rem;color:var(--text3);margin-top:.08rem">baseline</div>
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9935</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">1.0000</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9874</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9937</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9997</div>
  </div>
  <!-- Text RF -->
  <div style="display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr 1fr 1fr;gap:0;
    background:rgba(6,182,212,.05);border:1px solid rgba(6,182,212,.18);border-radius:10px;
    padding:.5rem .7rem;margin-bottom:.3rem;align-items:center">
    <div>
      <div style="font-size:.75rem;font-weight:700;color:#ffa0a0">Text — Random Forest</div>
      <div style="font-size:.63rem;color:var(--text3);margin-top:.08rem">11 features &bull; n_estimators=400 &bull; max_depth=20 &bull; class_weight=balanced</div>
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">0.9919</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">0.9925</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">0.9912</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;font-weight:700;text-align:right">0.9919</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:#34d399;text-align:right">0.9996</div>
  </div>
  <!-- Text LR -->
  <div style="display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr 1fr 1fr;gap:0;
    background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;
    padding:.5rem .7rem;margin-bottom:.9rem;align-items:center">
    <div>
      <div style="font-size:.75rem;font-weight:600;color:var(--text2)">Text — Logistic Regression</div>
      <div style="font-size:.63rem;color:var(--text3);margin-top:.08rem">baseline</div>
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9800</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9910</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9688</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9798</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:.76rem;color:var(--text2);text-align:right">0.9981</div>
  </div>
  <!-- CV + confusion -->
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:.6rem">
    <div style="background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;padding:.65rem .85rem">
      <div style="font-size:.58rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--text3);margin-bottom:.4rem">URL 5-fold CV</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:#34d399;line-height:1.8">
        Mean F1 &nbsp;<span style="font-weight:700">0.9972</span><br>
        Std &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:var(--text3)">±0.0004</span>
      </div>
    </div>
    <div style="background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;padding:.65rem .85rem">
      <div style="font-size:.58rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--text3);margin-bottom:.4rem">Text 5-fold CV</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:#34d399;line-height:1.8">
        Mean F1 &nbsp;<span style="font-weight:700">0.9893</span><br>
        Std &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:var(--text3)">±0.0023</span>
      </div>
    </div>
    <div style="background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;padding:.65rem .85rem">
      <div style="font-size:.58rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--text3);margin-bottom:.4rem">URL Confusion</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--text2);line-height:1.8">
        TN <span style="color:#34d399">678</span> &nbsp;FP <span style="color:#fbbf24">2</span><br>
        FN <span style="color:#fbbf24">3</span> &nbsp;&nbsp;TP <span style="color:#34d399">711</span>
      </div>
    </div>
    <div style="background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;padding:.65rem .85rem">
      <div style="font-size:.58rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--text3);margin-bottom:.4rem">Text Confusion</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--text2);line-height:1.8">
        TN <span style="color:#34d399">794</span> &nbsp;FP <span style="color:#fbbf24">6</span><br>
        FN <span style="color:#fbbf24">7</span> &nbsp;&nbsp;TP <span style="color:#34d399">793</span>
      </div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown('<div class="sdiv"><div class="sdiv-line"></div><div class="sdiv-lbl">Why Random Forest</div><div class="sdiv-line"></div></div>', unsafe_allow_html=True)
    st.markdown("""
<div class="about-card">
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.1rem">
    <div>
      <div style="font-size:.72rem;font-weight:700;color:#ff6060;margin-bottom:.4rem;letter-spacing:.04em">Interpretability</div>
      <div style="font-size:.79rem;color:var(--text2);line-height:1.65">Feature importances expose exactly which signals drove the prediction — essential for a security tool where every verdict needs a traceable reason.</div>
    </div>
    <div>
      <div style="font-size:.72rem;font-weight:700;color:#ffa0a0;margin-bottom:.4rem;letter-spacing:.04em">No Scaling Required</div>
      <div style="font-size:.79rem;color:var(--text2);line-height:1.65">Tree-based models handle mixed feature scales natively. URL length (0–300) and boolean flags (0/1) coexist without normalisation tricks.</div>
    </div>
    <div>
      <div style="font-size:.72rem;font-weight:700;color:#34d399;margin-bottom:.4rem;letter-spacing:.04em">Strong on Tabular Data</div>
      <div style="font-size:.79rem;color:var(--text2);line-height:1.65">14,970 engineered samples, 14 URL and 11 text features. Ensembling hundreds of trees with bootstrap sampling delivers &gt;99% F1 without deep learning.</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    st.markdown('<div class="sdiv"><div class="sdiv-line"></div><div class="sdiv-lbl">Roadmap</div><div class="sdiv-line"></div></div>', unsafe_allow_html=True)
    roadmap = [
        ("done",  "Two separate RF models (URL + text) instead of one mixed model"),
        ("done",  "Typosquatting detection via Levenshtein distance"),
        ("done",  "4 new URL features: has_at_symbol, path_depth, query_param_count, tld_suspicious"),
        ("done",  "Risk breakdown, scorecard, and feature-contribution chart"),
        ("done",  "Threat category classification (rule-based)"),
        ("done",  "v4: domain_entropy, digit_ratio_in_domain, hyphen_count_in_domain"),
        ("done",  "v4: uppercase_ratio, exclamation_count, url_count_in_text, keyword_density, suspicious_tld_in_body"),
        ("done",  "v4: Dataset expanded to 14,970 samples with edge cases and borderline examples"),
        ("done",  "v4: RandomizedSearchCV hyperparameter tuning (30 iters, 5-fold CV)"),
        ("done",  "v4: Full metrics — Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix"),
        ("done",  "v4: Calibrated S-curve probability→risk mapping to prevent bimodal scores"),
        ("wip",   "Real phishing corpus integration (PhishTank / OpenPhish)"),
        ("wip",   "WHOIS domain-age lookup toggle"),
        ("plan",  "Gradient-boosted model experiment (XGBoost)"),
        ("plan",  "Browser extension calling the local FastAPI endpoint"),
        ("plan",  "VirusTotal API integration (optional, key-gated)"),
        ("plan",  "SHAP values for per-prediction explanations"),
    ]
    tag_cls = {"done":"rm-done","wip":"rm-wip","plan":"rm-plan"}
    tag_lbl = {"done":"Done","wip":"In Progress","plan":"Planned"}
    rm_html = "".join(
        f'<div class="roadmap-item"><span class="rm-tag {tag_cls[s]}">{tag_lbl[s]}</span>'
        f'<span class="rm-text">{t}</span></div>'
        for s, t in roadmap
    )
    st.markdown(f'<div class="about-card">{rm_html}</div>', unsafe_allow_html=True)

    st.markdown("""
<div class="pgfooter">
  <div class="pgfooter-l">Designed &amp; Developed by Rudransh Sharma &copy; 2026</div>
  <div class="pgfooter-chips">
    <span class="pgfooter-chip">FastAPI</span><span class="pgfooter-chip">Streamlit</span>
    <span class="pgfooter-chip">Random Forest</span><span class="pgfooter-chip">scikit-learn</span>
  </div>
</div>""", unsafe_allow_html=True)

# ===========================================================================
# SCANNER PAGE
# ===========================================================================
else:
    # ── Hero ──────────────────────────────────────────────────────────────
    st.markdown("""
<div class="syn-hero">
  <div style="position:absolute;top:-80px;right:-100px;width:420px;height:420px;border-radius:50%;
    background:radial-gradient(circle,rgba(255,32,32,0.08) 0%,transparent 70%);pointer-events:none;
    animation:float-a 10s ease-in-out infinite"></div>
  <div style="position:absolute;bottom:-60px;left:30%;width:280px;height:280px;border-radius:50%;
    background:radial-gradient(circle,rgba(255,96,96,0.04) 0%,transparent 70%);pointer-events:none;
    animation:float-b 14s ease-in-out infinite"></div>
  <div class="syn-hero-eyebrow">ML-Powered Phishing Detection</div>
  <div class="syn-hero-title">Threat<span class="syn-hero-shimmer">Lens</span></div>
  <div style="font-size:.75rem;color:var(--text3);margin:.1rem 0 .5rem;letter-spacing:.04em">
    Built by Rudransh Sharma
  </div>
  <div class="syn-hero-sub">
    Detect phishing in Email, SMS, and URLs using Random Forest classifiers
    with feature-level explainability. Everything runs locally — zero data egress.
  </div>
  <div class="syn-hero-chips">
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#10B981"></span>Local Inference</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff2020"></span>Random Forest</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff6060"></span>Explainable AI</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff6060"></span>14,970 Training Samples</span>
  </div>
</div>""", unsafe_allow_html=True)

    # ── Disclaimer ────────────────────────────────────────────────────────
    st.markdown("""
<div style="background:rgba(255,32,32,0.04);border:1px solid rgba(255,32,32,0.15);
  border-radius:12px;padding:.75rem 1.1rem;margin-bottom:1.2rem;
  display:flex;align-items:flex-start;gap:.75rem">
  <div style="flex-shrink:0;width:17px;height:17px;border-radius:50%;
    background:rgba(255,32,32,0.15);border:1px solid rgba(255,32,32,0.4);
    display:flex;align-items:center;justify-content:center;
    font-size:.62rem;font-weight:900;color:#ff6060;margin-top:.05rem">!</div>
  <div style="font-size:.77rem;color:var(--text2);line-height:1.6">
    <span style="font-weight:700;color:#ff8080">Disclaimer —</span>
    ThreatLens uses ML heuristics and is
    <strong style="color:#fff">not guaranteed to detect every phishing attempt</strong>.
    False negatives and false positives will occur.
    If you choose to open a flagged or unflagged link,
    <strong style="color:#fff">you do so entirely at your own risk</strong>.
    Always apply independent judgement.
  </div>
</div>""", unsafe_allow_html=True)

    # ── Input section ─────────────────────────────────────────────────────
    st.markdown('<div class="isec"><div class="isec-t">Threat Scanner</div>', unsafe_allow_html=True)
    inp_l, inp_r = st.columns([1.6, 1], gap="large")

    with inp_l:
        ct_labels = ["Email", "SMS", "URL"]
        ct_idx    = ["email", "sms", "url"].index(st.session_state.content_type)
        sel = st.radio("Type", ct_labels, horizontal=True, index=ct_idx, label_visibility="collapsed")
        content_type = sel.lower()
        if content_type != st.session_state.content_type:
            st.session_state.content_type = content_type
            st.session_state.ex_content   = ""
        content = st.text_area(
            "Content", value=st.session_state.ex_content, height=200,
            placeholder=PLACEHOLDERS[content_type], label_visibility="collapsed",
        )
        scan_clicked = st.button("Scan for Threats", type="primary", use_container_width=True)

    with inp_r:
        st.markdown('<div style="font-size:.62rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--text3);margin-bottom:.5rem">Content Type</div>', unsafe_allow_html=True)
        icons = {"email": "E", "sms": "S", "url": "U"}
        for lbl in ct_labels:
            sel_  = lbl.lower() == content_type
            bg    = "rgba(255,32,32,0.08)" if sel_ else "rgba(255,255,255,0.02)"
            bc    = "rgba(255,32,32,0.3)" if sel_ else "var(--border)"
            col   = "#ff8080" if sel_ else "var(--text3)"
            dot   = '<span style="margin-left:auto;width:5px;height:5px;border-radius:50%;background:#ff2020"></span>' if sel_ else ''
            st.markdown(
                f'<div style="background:{bg};border:1px solid {bc};border-radius:10px;'
                f'padding:.5rem .85rem;margin-bottom:.4rem;display:flex;align-items:center;gap:.55rem;'
                f'transition:all .18s cubic-bezier(0.23,1,0.32,1)">'
                f'<div style="width:19px;height:19px;border-radius:5px;background:{bc};'
                f'display:flex;align-items:center;justify-content:center;'
                f'font-size:.6rem;font-weight:700;color:{col}">{icons[lbl.lower()]}</div>'
                f'<span style="font-size:.8rem;font-weight:600;color:{col}">{lbl}</span>{dot}</div>',
                unsafe_allow_html=True,
            )

        claimed_brand = sender_domain_val = None
        if content_type in {"email", "sms"}:
            st.markdown('<div style="font-size:.62rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--text3);margin-top:.8rem;margin-bottom:.4rem">Optional Context</div>', unsafe_allow_html=True)
            claimed_brand     = st.text_input("Claimed Brand",  value=st.session_state.claimed_brand, placeholder="e.g. PayPal")
            sender_domain_val = st.text_input("Sender Domain", value=st.session_state.sender_domain, placeholder="e.g. alerts.example.net")

    st.markdown('</div>', unsafe_allow_html=True)

    # ── Scan logic ────────────────────────────────────────────────────────
    if scan_clicked:
        if not content or not content.strip():
            st.warning("Paste content before scanning.")
        else:
            payload = {
                "content_type": content_type, "content": content,
                "claimed_brand": claimed_brand or None,
                "sender_domain": sender_domain_val or None,
            }
            ph = st.empty()
            steps = [
                "Initializing classifiers", "Extracting features",
                "Checking domain signals", "Analysing content patterns",
                "Running Random Forest", "Computing risk breakdown", "Generating report",
            ]
            ph.markdown(
                '<div class="syn-card">' +
                ''.join(f'<div class="sstep"><div class="sdot"></div>{s}…</div>' for s in steps) +
                '</div>', unsafe_allow_html=True,
            )
            time.sleep(0.05)
            result = call_backend(payload)
            if result:
                done = ''.join(f'<div class="sstep sstep-done"><div class="sdot"></div>{s}</div>' for s in steps)
                done += '<div class="sstep sstep-done" style="margin-top:.4rem;font-weight:700">Assessment complete</div>'
                ph.markdown(f'<div class="syn-card">{done}</div>', unsafe_allow_html=True)
                time.sleep(0.25)
                ph.empty()
                st.session_state.last_result       = result
                st.session_state.last_content      = content
                st.session_state.last_content_type = content_type
                lbl = (content[:28] + "…") if len(content) > 28 else content
                st.session_state.scan_history.append({
                    "label": lbl.replace("\n", " "),
                    "verdict": result["verdict"],
                    "time": time.strftime("%H:%M"),
                })
                st.session_state.scan_history = st.session_state.scan_history[-20:]
            else:
                ph.empty()
    else:
        result       = st.session_state.get("last_result")
        content      = st.session_state.get("last_content", "")
        content_type = st.session_state.get("last_content_type", content_type)

    # ── Results dashboard ─────────────────────────────────────────────────
    if result:
        verdict    = result["verdict"]
        risk_score = result["risk_score"]
        conf_pct   = result.get("confidence_pct", 0)
        conf_level = result.get("confidence", "—")
        signals    = result.get("triggered_features", [])
        breakdown  = result.get("risk_breakdown", {})
        scorecard  = result.get("scorecard", [])
        dom_info   = result.get("domain_info")
        typosquat  = result.get("typosquat")
        all_feats  = result.get("all_features", {})
        threat_cat = result.get("threat_category", "Unknown")
        scan_ms    = result.get("scan_time_ms", 0)
        explanation= result.get("explanation", "")
        v_css      = _vcss(verdict)
        glow_col   = {"Safe":"#10B981","Suspicious":"#F59E0B","Dangerous":"#EF4444"}.get(verdict,"#ff2020")

        st.markdown('<div class="sdiv"><div class="sdiv-line"></div><div class="sdiv-lbl">Threat Assessment Report</div><div class="sdiv-line"></div></div>', unsafe_allow_html=True)

        # ── Stat grid ─────────────────────────────────────────────────────
        sa = {"Safe":"ss-g","Suspicious":"ss-w","Dangerous":"ss-r"}.get(verdict,"ss-v")
        sc = {"Safe":"cg","Suspicious":"cw","Dangerous":"cr"}.get(verdict,"cv")
        st.markdown(f"""
<div class="syn-stat-grid">
  <div class="syn-stat {sa}">
    <div class="s-lbl">Risk Score</div>
    <div class="s-val {sc}">{risk_score}</div>
    <div class="s-sub">out of 100</div>
  </div>
  <div class="syn-stat ss-v">
    <div class="s-lbl">Model Confidence</div>
    <div class="s-val cv">{conf_pct}<span style="font-size:1.1rem;color:var(--text3)">%</span></div>
    <div class="s-sub">{conf_level}</div>
  </div>
  <div class="syn-stat ss-w">
    <div class="s-lbl">Threat Indicators</div>
    <div class="s-val cw">{len(signals)}</div>
    <div class="s-sub">signals triggered</div>
  </div>
  <div class="syn-stat ss-c">
    <div class="s-lbl">Scan Time</div>
    <div class="s-val cc">{scan_ms}</div>
    <div class="s-sub">milliseconds</div>
  </div>
</div>""", unsafe_allow_html=True)

        # Verdict + category row
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem;flex-wrap:wrap">'
            f'<span class="vbadge {_vb(verdict)}">{verdict.upper()}</span>'
            f'<span class="cbadge">{threat_cat}</span>'
            f'<span style="font-size:.7rem;color:var(--text3);font-family:\'JetBrains Mono\',monospace">'
            f'{content_type.upper()} &bull; {time.strftime("%H:%M:%S")}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # ── Confidence boxes ──────────────────────────────────────────────
        conf_accent = {"Low":"#fbbf24","Medium":"#ff6060","High":"#34d399"}.get(conf_level,"#ffa0a0")
        conf_bg     = {"Low":"rgba(245,158,11,.05)","Medium":"rgba(255,32,32,.05)","High":"rgba(16,185,129,.05)"}.get(conf_level,"rgba(6,182,212,.05)")
        conf_br     = {"Low":"rgba(245,158,11,.25)","Medium":"rgba(255,32,32,.25)","High":"rgba(16,185,129,.25)"}.get(conf_level,"rgba(6,182,212,.2)")
        conf_note   = (
            "Close to the decision boundary — treat this result with extra caution and verify independently."
            if conf_level == "Low" else
            "Reasonably certain, but edge cases exist. Cross-check any suspicious signals manually."
            if conf_level == "Medium" else
            "Strongly separated from the 50% boundary. Still, no classifier is infallible — apply judgement."
        )
        st.markdown(f"""
<div style="background:{conf_bg};border:1px solid {conf_br};border-radius:12px;
  padding:.7rem 1.1rem;margin-bottom:.55rem;display:flex;align-items:flex-start;gap:.7rem">
  <div style="flex-shrink:0;width:16px;height:16px;border-radius:50%;background:rgba(0,0,0,.3);
    border:1px solid {conf_accent};display:flex;align-items:center;justify-content:center;
    font-size:.6rem;font-weight:900;color:{conf_accent};margin-top:.05rem">i</div>
  <div style="font-size:.77rem;color:var(--text2);line-height:1.6">
    <span style="font-weight:700;color:{conf_accent}">Confidence: {conf_level} ({conf_pct}%)</span>
    &nbsp;&mdash;&nbsp;{conf_note}
  </div>
</div>
<div style="background:rgba(239,68,68,.04);border:1px solid rgba(239,68,68,.18);border-radius:12px;
  padding:.7rem 1.1rem;margin-bottom:1rem;display:flex;align-items:flex-start;gap:.7rem">
  <div style="flex-shrink:0;width:16px;height:16px;border-radius:50%;background:rgba(239,68,68,.12);
    border:1px solid rgba(239,68,68,.4);display:flex;align-items:center;justify-content:center;
    font-size:.62rem;font-weight:900;color:#fca5a5;margin-top:.05rem">!</div>
  <div style="font-size:.76rem;color:var(--text2);line-height:1.6">
    <span style="font-weight:700;color:#fca5a5">Don't over-rely on model confidence.</span>
    &nbsp;Confidence reflects distance from 50% — not real-world danger.
    A high-confidence Safe verdict can still be a novel phishing attempt this model hasn't seen.
    Trained on 14,970 synthetic samples; real-world adversarial tactics evolve faster.
    <span style="display:block;margin-top:.3rem;color:var(--text3)">
      Always verify senders, hover over links, and never enter credentials on a page reached via
      an unsolicited message — regardless of what this tool says.
    </span>
  </div>
</div>""", unsafe_allow_html=True)

        # ── Row A: Gauge · Analyst · Breakdown ────────────────────────────
        ca1, ca2, ca3 = st.columns([1, 1.4, 1.4], gap="medium")

        with ca1:
            r2, cx, cy = 50, 60, 65
            circ  = 2 * 3.14159 * r2
            dash  = round(circ * risk_score / 100, 1)
            gap2  = round(circ - dash, 1)
            off   = round(circ * .25, 1)
            st.markdown(f"""
<div class="syn-card" style="text-align:center">
  <div class="syn-card-lbl">Risk Meter</div>
  <svg width="120" height="124" viewBox="0 0 120 130" style="overflow:visible">
    <defs>
      <filter id="glow-g"><feGaussianBlur stdDeviation="4" result="b"/>
        <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      <linearGradient id="arc-grad" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style="stop-color:#ff2020"/>
        <stop offset="100%" style="stop-color:{glow_col}"/>
      </linearGradient>
    </defs>
    <circle cx="{cx}" cy="{cy}" r="{r2}" fill="none" stroke="rgba(255,32,32,0.08)" stroke-width="8"/>
    <circle cx="{cx}" cy="{cy}" r="{r2}" fill="none" stroke="url(#arc-grad)" stroke-width="8"
      stroke-dasharray="{dash} {gap2}" stroke-dashoffset="{off}"
      stroke-linecap="round" filter="url(#glow-g)"/>
    <text x="{cx}" y="{cy+7}" text-anchor="middle"
      font-family="JetBrains Mono,monospace" font-size="21" font-weight="800"
      fill="{glow_col}">{risk_score}</text>
    <text x="{cx}" y="{cy+21}" text-anchor="middle"
      font-family="Inter,sans-serif" font-size="7.5" font-weight="600"
      fill="rgba(255,255,255,0.25)" letter-spacing="1">OUT OF 100</text>
  </svg>
  <div style="margin-top:.25rem">
    <span class="vbadge {_vb(verdict)}" style="font-size:.68rem">{verdict}</span>
  </div>
</div>""", unsafe_allow_html=True)

        with ca2:
            if risk_score >= 70:
                risks = [s["detail"] for s in signals[:3]] or ["Multiple indicators triggered"]
                acts  = [("aa-r","Delete — do not interact"),("aa-r","Do not click any links"),("aa-r","Report to your security team")]
                tt, tc = "Do NOT trust this content", "#f87171"
            elif risk_score >= 40:
                risks = [s["detail"] for s in signals[:2]] or ["Suspicious patterns detected"]
                acts  = [("aa-w","Proceed with caution"),("aa-v","Verify sender independently")]
                tt, tc = "Treat with suspicion", "#fbbf24"
            else:
                risks = ["No strong phishing indicators detected"]
                acts  = [("aa-g","Content appears legitimate")]
                tt, tc = "Likely legitimate", "#34d399"
            rh = "".join(f'<div class="aaction aa-v" style="margin-bottom:.28rem">&#x25B8; {r}</div>' for r in risks)
            ah = "".join(f'<div class="aaction {c}">{a}</div>' for c, a in acts)
            st.markdown(f"""
<div class="syn-card">
  <div class="syn-card-lbl">Model Analyst</div>
  <div style="font-size:.62rem;color:var(--text3);margin-bottom:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em">Random Forest Assessment</div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:2.2rem;font-weight:800;color:{glow_col};line-height:1">
    {risk_score}<span style="font-size:.9rem;color:var(--text3)">/100</span>
  </div>
  <div style="font-size:.7rem;font-weight:700;color:{tc};margin:.28rem 0 .7rem;text-transform:uppercase;letter-spacing:.07em">{tt}</div>
  <div style="font-size:.6rem;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.12em;margin-bottom:.38rem">Top Signals</div>
  {rh}
  <div style="font-size:.6rem;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.12em;margin:.5rem 0 .32rem">Recommended Actions</div>
  {ah}
</div>""", unsafe_allow_html=True)

        with ca3:
            dr   = breakdown.get("domain_risk", 0)
            cr_  = breakdown.get("content_risk", 0)
            cth  = breakdown.get("credential_theft", 0)
            se   = breakdown.get("social_engineering", 0)
            st.markdown(f"""
<div class="syn-card">
  <div class="syn-card-lbl">Risk Breakdown</div>
  {bar("Domain Risk", dr)}
  {bar("Content Risk", cr_)}
  {bar("Credential Theft", cth)}
  {bar("Social Engineering", se)}
  <div style="margin-top:.75rem"></div>
  <div class="syn-card-lbl">Prediction Confidence</div>
  {bar("Confidence", conf_pct, fc="bf-v")}
</div>""", unsafe_allow_html=True)

        # ── Row B: Timeline · Feature contributions ───────────────────────
        cb1, cb2 = st.columns([1, 1], gap="medium")

        with cb1:
            tl = [("info", "Scan Initiated", f"{content_type.upper()} content received")]
            for sig in signals:
                sev = "dangerous" if sig["weight"] > .15 else ("suspicious" if sig["weight"] > .05 else "info")
                tl.append((sev, sig["name"].replace("_"," ").title(), sig["detail"]))
            tl.append((v_css, "Verdict Generated", f"Risk score {risk_score}/100 — {verdict}"))
            sh = ""
            for sev, title, detail in tl:
                dc = _dc(sev); df = _dcfill(sev)
                sh += (f'<div class="tstep">'
                       f'<div class="tdot {dc}"><div class="tdot-inner" style="background:{df}"></div></div>'
                       f'<div class="ttitle">{title}</div>'
                       f'<div class="tdetail">{detail}</div></div>')
            st.markdown(f'<div class="syn-card"><div class="syn-card-lbl">Detection Timeline</div><div class="tline">{sh}</div></div>', unsafe_allow_html=True)

        with cb2:
            fw = {s["name"]: s["weight"] for s in signals}
            if fw:
                tw = sum(fw.values()) or 1
                bh = "".join(fbar(n.replace("_"," ").title(), w/tw) for n, w in sorted(fw.items(), key=lambda x: x[1], reverse=True))
            else:
                bh = '<div style="font-size:.77rem;color:var(--text3)">No significant features triggered.</div>'
            sc_r = ""; sc_t = sc_m = 0
            if scorecard:
                sc_t = sum(i["score"] for i in scorecard)
                sc_m = sum(i["max_score"] for i in scorecard)
                for item in scorecard:
                    p2  = round(item["score"] / item["max_score"] * 100) if item["max_score"] else 0
                    fc2 = _hx(100 - p2)
                    sc_r += (f'<div class="scrow">'
                             f'<span class="sclbl">{item["label"]}</span>'
                             f'<div class="sctrack"><div class="scfill" style="width:{p2}%;background:{fc2}"></div></div>'
                             f'<span class="scscore">{item["score"]}/{item["max_score"]}</span></div>')
            st.markdown(f"""
<div class="syn-card">
  <div class="syn-card-lbl">Feature Contribution</div>
  {bh}
  <div style="margin-top:.9rem"></div>
  <div class="syn-card-lbl">Security Scorecard
    <span style="font-family:'JetBrains Mono',monospace;color:#ff6060;font-size:.68rem;margin-left:.4rem">{sc_t}/{sc_m}</span>
  </div>
  {sc_r}
</div>""", unsafe_allow_html=True)

        # ── Row C: Domain info / Explanation · Heatmap ────────────────────
        cc1, cc2 = st.columns([1, 1], gap="medium")

        with cc1:
            if dom_info:
                def _dc2(l, v, bad=False):
                    c = "#f87171" if bad else "rgba(255,255,255,0.7)"
                    return f'<div class="dcell"><div class="dclbl">{l}</div><div class="dcval" style="color:{c}">{v}</div></div>'
                g = (f'{_dc2("Domain", dom_info.get("domain","—"))}'
                     f'{_dc2("TLD", dom_info.get("tld","—"), dom_info.get("uses_shortener",False))}'
                     f'{_dc2("HTTPS", "Yes" if dom_info["is_https"] else "No", not dom_info["is_https"])}'
                     f'{_dc2("Subdomains", str(dom_info.get("num_subdomains",0)), dom_info.get("num_subdomains",0)>1)}'
                     f'{_dc2("IP Host", "Yes" if dom_info["has_ip"] else "No", dom_info["has_ip"])}'
                     f'{_dc2("Shortener", "Yes" if dom_info["uses_shortener"] else "No", dom_info["uses_shortener"])}'
                     f'{_dc2("Domain Age", (str(dom_info["domain_age_days"])+" days") if dom_info.get("domain_age_days") else "N/A")}'
                     f'{_dc2("Registrar", dom_info.get("registrar") or "N/A")}')
                st.markdown(f'<div class="syn-card"><div class="syn-card-lbl">Domain Intelligence</div><div class="dgrid">{g}</div></div>', unsafe_allow_html=True)
                if typosquat:
                    if typosquat["detected"]:
                        st.markdown(
                            f'<div class="typo-box"><div class="typo-t">Typosquatting Detected</div>'
                            f'<div style="font-size:.76rem;color:#fbbf24;line-height:1.55">'
                            f'<code style="color:#fbbf24;background:rgba(255,32,32,0.08);padding:1px 5px;border-radius:3px">{typosquat["domain"]}</code>'
                            f' resembles <code style="color:#34d399;background:rgba(255,32,32,0.08);padding:1px 5px;border-radius:3px">{typosquat["closest_brand"]}</code>'
                            f'<br>Similarity: <strong style="color:#fbbf24">{typosquat["similarity"]}%</strong> — possible brand impersonation.</div></div>',
                            unsafe_allow_html=True,
                        )
                    else:
                        cb_t = f' — closest: {typosquat.get("closest_brand","")} ({typosquat.get("similarity",0)}%)' if typosquat.get("closest_brand") else ""
                        st.markdown(
                            f'<div style="background:rgba(16,185,129,.04);border:1px solid rgba(16,185,129,.18);'
                            f'border-radius:10px;padding:.6rem .9rem;margin-top:.6rem">'
                            f'<span style="font-size:.76rem;font-weight:600;color:#34d399">No typosquatting detected{cb_t}</span></div>',
                            unsafe_allow_html=True,
                        )
            else:
                el  = explanation.replace("- ", "").split("\n")
                ei  = "".join(f'<div class="aaction aa-v" style="margin-bottom:.3rem">{ln.strip()}</div>' for ln in el if ln.strip())
                st.markdown(f'<div class="syn-card"><div class="syn-card-lbl">Model Explanation</div>{ei}</div>', unsafe_allow_html=True)

        with cc2:
            pm: list[tuple[str, str]] = []
            for sig in signals:
                sev = "r" if sig["weight"] > .15 else ("o" if sig["weight"] > .05 else "b")
                for ph2 in re.findall(r"'([^']+)'", sig["detail"]):
                    pm.append((ph2, sev))
            raw = content or ""
            hm  = _html.escape(raw[:1500])
            for ph2, sev in pm:
                if not ph2: continue
                ep = _html.escape(ph2)
                hm = re.sub(re.escape(ep), f'<span class="hw hw-{sev}">{ep}</span>', hm, count=3, flags=re.IGNORECASE)
            hm = hm.replace("\n", "<br>")
            leg = ' &nbsp; '.join([
                '<span class="hw hw-r" style="font-size:.64rem">High</span>',
                '<span class="hw hw-o" style="font-size:.64rem">Medium</span>',
                '<span class="hw hw-b" style="font-size:.64rem">Low</span>',
            ])
            st.markdown(
                f'<div class="syn-card"><div class="syn-card-lbl">Risk Heatmap &nbsp; {leg}</div>'
                f'<div style="font-size:.77rem;color:rgba(255,255,255,0.6);line-height:1.75;'
                f'font-family:\'JetBrains Mono\',monospace;background:rgba(255,255,255,0.02);'
                f'border:1px solid var(--border);border-radius:12px;padding:.85rem;'
                f'max-height:280px;overflow-y:auto">{hm}</div></div>',
                unsafe_allow_html=True,
            )

        if dom_info:
            el2 = explanation.replace("- ", "").split("\n")
            ei2 = "".join(f'<div class="aaction aa-v" style="margin-bottom:.3rem">{ln.strip()}</div>' for ln in el2 if ln.strip())
            st.markdown(f'<div class="syn-card"><div class="syn-card-lbl">Model Explanation</div>{ei2}</div>', unsafe_allow_html=True)

        with st.expander("Raw Feature Values"):
            if all_feats:
                cols4 = st.columns(4)
                for i, (k, v) in enumerate(sorted(all_feats.items())):
                    disp = str(v) if v is not None else "N/A"
                    bad  = v and v not in (0, False, "False", 0.0)
                    clr  = "#f87171" if bad else "#34d399"
                    with cols4[i % 4]:
                        st.markdown(
                            f'<div style="background:rgba(255,255,255,0.02);border:1px solid var(--border);'
                            f'border-radius:8px;padding:.42rem .6rem;margin-bottom:.3rem">'
                            f'<div style="font-size:.58rem;color:var(--text3);text-transform:uppercase;'
                            f'letter-spacing:.1em;margin-bottom:.12rem">{k}</div>'
                            f'<div style="font-size:.78rem;font-family:\'JetBrains Mono\',monospace;color:{clr}">{disp}</div></div>',
                            unsafe_allow_html=True,
                        )

    # ── Empty state ───────────────────────────────────────────────────────
    else:
        st.markdown("""
<div style="text-align:center;padding:4rem 2rem;border:1px solid var(--border);border-radius:20px;
  background:rgba(255,255,255,0.02);margin-top:1.2rem;position:relative;overflow:hidden">
  <div style="position:absolute;top:-60px;left:50%;transform:translateX(-50%);
    width:300px;height:300px;border-radius:50%;
    background:radial-gradient(circle,rgba(255,32,32,0.06) 0%,transparent 70%);pointer-events:none"></div>
  <div style="width:52px;height:52px;border-radius:14px;
    background:rgba(255,32,32,0.08);border:1px solid rgba(255,32,32,0.2);
    display:flex;align-items:center;justify-content:center;
    margin:0 auto 1.1rem;
    font-family:'Instrument Serif',serif;font-size:1.1rem;color:#ff6060">TL</div>
  <div style="font-family:'Instrument Serif',serif;font-size:1.5rem;color:#fff;
    margin-bottom:.45rem;letter-spacing:-.02em">Ready to Scan</div>
  <div style="font-size:.84rem;color:var(--text2);line-height:1.65;max-width:380px;margin:0 auto">
    Paste an email, SMS, or URL above and click
    <strong style="color:#ff6060">Scan for Threats</strong>
    to run the Random Forest classifiers.
  </div>
  <div style="display:flex;justify-content:center;gap:.6rem;margin-top:1.3rem;flex-wrap:wrap">
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff2020"></span>Random Forest Detection</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#ff6060"></span>Feature-Level Explainability</span>
    <span class="syn-chip"><span class="syn-chip-dot" style="background:#10B981"></span>Zero Data Egress</span>
  </div>
</div>""", unsafe_allow_html=True)

    # ── Footer ────────────────────────────────────────────────────────────
    st.markdown("""
<div class="pgfooter">
  <div class="pgfooter-l">Designed &amp; Developed by Rudransh Sharma &copy; 2026</div>
  <div class="pgfooter-chips">
    <span class="pgfooter-chip">FastAPI</span>
    <span class="pgfooter-chip">Streamlit</span>
    <span class="pgfooter-chip">Random Forest</span>
    <span class="pgfooter-chip">scikit-learn</span>
    <span class="pgfooter-chip">Explainable ML</span>
  </div>
</div>

<!-- ── MOBILE ONLY: About section at bottom ── -->
<div class="mob-about">
  <div style="height:1px;background:rgba(255,32,32,0.12);margin:2rem 0 1.5rem"></div>
  <div style="font-size:.55rem;font-weight:700;letter-spacing:.22em;text-transform:uppercase;
    color:rgba(255,255,255,0.2);margin-bottom:1rem">About the Developer</div>

  <div style="background:rgba(5,5,5,0.85);border:1px solid rgba(255,32,32,0.08);
    border-radius:16px;padding:1.2rem 1.3rem;margin-bottom:.8rem">
    <div style="font-family:'Instrument Serif',serif;font-size:1.4rem;letter-spacing:-.02em;
      background:linear-gradient(135deg,#ff6060,#ffa0a0);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
      margin-bottom:.2rem">Rudransh Sharma</div>
    <div style="font-size:.72rem;color:rgba(255,255,255,0.45);margin-bottom:.8rem">
      ML Engineer &nbsp;&middot;&nbsp; VIT Chennai &nbsp;&middot;&nbsp; Graduating 2028
    </div>
    <p style="font-size:.78rem;color:rgba(255,255,255,0.5);line-height:1.7;margin-bottom:.9rem">
      ML Engineering student with a strong interest in machine learning,
      cybersecurity, and full-stack development. ThreatLens is built and
      trained entirely from scratch — zero external APIs, full local inference.
    </p>
    <div style="display:flex;gap:.5rem;flex-wrap:wrap">
      <a style="display:inline-flex;align-items:center;background:rgba(255,255,255,0.04);
        border:1px solid rgba(255,32,32,0.15);border-radius:8px;padding:.35rem .75rem;
        font-size:.72rem;color:#ff6060;text-decoration:none;" href="https://github.com/rudransh27sharma" target="_blank">GitHub</a>
      <a style="display:inline-flex;align-items:center;background:rgba(255,255,255,0.04);
        border:1px solid rgba(255,32,32,0.15);border-radius:8px;padding:.35rem .75rem;
        font-size:.72rem;color:#ff6060;text-decoration:none;" href="https://www.linkedin.com/in/rudransh-sharma-/" target="_blank">LinkedIn</a>
      <a style="display:inline-flex;align-items:center;background:rgba(255,255,255,0.04);
        border:1px solid rgba(255,32,32,0.15);border-radius:8px;padding:.35rem .75rem;
        font-size:.72rem;color:#ff6060;text-decoration:none;" href="mailto:contact.rudranshsharma@gmail.com">Email</a>
    </div>
  </div>

  <div style="background:rgba(5,5,5,0.85);border:1px solid rgba(255,32,32,0.08);
    border-radius:16px;padding:1.2rem 1.3rem">
    <div style="font-size:.55rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase;
      color:rgba(255,255,255,0.2);margin-bottom:.7rem">About ThreatLens</div>
    <p style="font-size:.78rem;color:rgba(255,255,255,0.5);line-height:1.7;margin-bottom:.7rem">
      Two Random Forest classifiers — URL model (14 features) and Text model (11 features).
      Every verdict is traceable. Nothing leaves your device.
    </p>
    <div style="display:flex;flex-wrap:wrap;gap:.4rem">
      <span style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,32,32,0.12);
        border-radius:9999px;padding:.2rem .6rem;font-size:.65rem;color:rgba(255,255,255,0.35)">scikit-learn</span>
      <span style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,32,32,0.12);
        border-radius:9999px;padding:.2rem .6rem;font-size:.65rem;color:rgba(255,255,255,0.35)">FastAPI</span>
      <span style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,32,32,0.12);
        border-radius:9999px;padding:.2rem .6rem;font-size:.65rem;color:rgba(255,255,255,0.35)">Streamlit</span>
      <span style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,32,32,0.12);
        border-radius:9999px;padding:.2rem .6rem;font-size:.65rem;color:rgba(255,255,255,0.35)">Python 3.11</span>
    </div>
  </div>
  <div style="height:5rem"></div>
</div>

<!-- ── MOBILE BOTTOM NAV ── -->
<div class="mob-nav" id="mob-nav">
  <button class="mob-nav-btn active" id="mob-btn-scanner" onclick="setMobPage('Scanner')">
    <span class="mob-nav-icon">🔍</span>Scanner
  </button>
  <button class="mob-nav-btn" id="mob-btn-engineering" onclick="setMobPage('Engineering')">
    <span class="mob-nav-icon">⚙️</span>Engineering
  </button>
</div>

<script>
function setMobPage(p) {
  document.querySelectorAll('.mob-nav-btn').forEach(function(b){ b.classList.remove('active'); });
  var btn = document.getElementById('mob-btn-' + p.toLowerCase());
  if(btn) btn.classList.add('active');
  var btns = document.querySelectorAll('[data-testid="stSidebar"] button');
  btns.forEach(function(b){ if(b.innerText.trim() === p) b.click(); });
}
</script>
""", unsafe_allow_html=True)
