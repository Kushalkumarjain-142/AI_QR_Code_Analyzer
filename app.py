import base64
import streamlit as st
import requests
from PIL import Image
from pyzbar.pyzbar import decode
from cassandra.cluster import Cluster
from urllib.parse import urlparse
from datetime import datetime

GEMINI_API_KEY = st.secrets["GEMINI_API_KEY"]
VT_API_KEY     = st.secrets["VT_API_KEY"]

cluster = Cluster([st.secrets["CASSANDRA_HOST"]])
session = cluster.connect()

session.execute("CREATE KEYSPACE IF NOT EXISTS qr_security WITH replication = {'class':'SimpleStrategy','replication_factor':1}")
session.execute("USE qr_security")
session.execute("CREATE TABLE IF NOT EXISTS scans (id uuid PRIMARY KEY, url text, verdict text, scanned_at timestamp)")

def scan(url):
    if urlparse(url).scheme not in ("http","https"):
        return "DANGER: Invalid URL"

    encoded = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

    vt = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{encoded}",
        headers={"x-apikey": VT_API_KEY}
    )

    vt_stats = vt.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})

    prompt = f"URL: {url}. VirusTotal: {vt_stats}. Output only STATUS: SAFE/WARNING/DANGER and REASON in 2 lines."

    ep = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"

    r = requests.post(
        ep,
        json={
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }
    )

    try:
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]
    except:
        return "ERROR"

st.set_page_config(page_title="QR Security Scanner")
st.title("QR Code Security Scanner")

img_file = st.file_uploader(
    "Upload QR Code Image",
    type=["png","jpg","jpeg","webp"]
)

if img_file:
    img = Image.open(img_file)

    st.image(img, width=200)

    results = decode(img)

    if not results:
        st.warning("No QR code detected. Try a clearer image.")
    else:
        url = results[0].data.decode("utf-8")

        st.info(f"Decoded URL: {url}")

        if st.button("Check Security"):
            with st.spinner("Scanning..."):

                verdict = scan(url)

                from uuid import uuid4

                session.execute(
                    "INSERT INTO scans (id,url,verdict,scanned_at) VALUES (%s,%s,%s,%s)",
                    (uuid4(), url, verdict, datetime.utcnow())
                )

                if "SAFE" in verdict:
                    st.success(verdict)

                elif "WARNING" in verdict:
                    st.warning(verdict)

                elif "DANGER" in verdict:
                    st.error(verdict)

                else:
                    st.info(verdict)