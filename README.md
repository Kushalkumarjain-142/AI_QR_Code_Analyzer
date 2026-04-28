# AI QR Code Analyzer 🛡️

An end-to-end security pipeline designed to scan, decode, and analyze QR codes for potential threats using AI reasoning and multi-engine antivirus scans.

---

## 🚀 Execution Flow
The application follows an Eight(8)-step automated process to ensure the safety of a QR code:

1. **User Interface:** The user accesses the tool via a **Streamlit** web interface.
2. **Image Upload:** Supports common image formats including **PNG, JPG, and WEBP**.
3. **Decoding:** Utilizes the **pyzbar** library to read pixel patterns and extract the hidden URL.
4. **URL Validation:** A protocol check (`http` / `https`) ensures the URL is valid and blocks malformed input.
5. **Multi-Engine Scan:** The URL is sent to the **VirusTotal API**, where it is checked against **70+ engines**.
6. **AI Reasoning:** **Gemini 2.5 Flash** performs advanced reasoning on the raw data for context-aware insights.
7. **Data Persistence:** Results are stored in a **Cassandra** database for permanent scan history.
8. **User Reporting:** Final result is displayed with **color-coded status** (SAFE / WARNING / DANGER).

---

## 🛠️ Tech Stack
* **Frontend:** Streamlit
* **QR Processing:** pyzbar
* **Threat Intel:** VirusTotal API
* **AI Reasoning:** Gemini 2.5 Flash
* **Database:** Apache Cassandra

---

## ⚙️ Installation & Setup

### Prerequisites
* Python 3.9+
* `zbar` shared library (required by pyzbar)
* A running Cassandra instance

Status,Description
🟢 SAFE,No engines detected threats; AI confirms low-risk.
🟡 WARNING,Suspicious patterns detected or low-confidence flags.
🔴 DANGER,Confirmed malicious URL or high-risk phishing attempt.

