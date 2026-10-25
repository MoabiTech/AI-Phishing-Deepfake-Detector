# AI Phishing & Deepfake Detector — Prototype

## Requirements
- Python 3.10 or newer recommended
- pip

## Install (Windows PowerShell)
Open PowerShell in this folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
.\start_detector.bat
```

If `py` is not recognized, use `python` to create the virtual environment.

The app should open in your browser. If it does not, visit the local URL printed in the terminal, usually http://localhost:8501.

## Current functionality
- Streamlit interface for pasted email and uploaded-media analysis
- Email text screening with explainable rules and a risk score
- URL extraction without opening links
- TXT/EML inspection using the email rules
- Image metadata inspection and optional logo similarity checks
- WAV audio metadata inspection
- Video metadata inspection using OpenCV when supported
- Before/after SHA-256 integrity verification
- Downloadable JSON reports and measured processing time
- Local end-to-end chat demo using browser Web Crypto

## Run the chat demo
From PowerShell:

```powershell
cd e2ee_chat
.\start_server.bat
```

Then open http://127.0.0.1:5000/. The chat is a local demonstration, not a production messenger.

## Important limitation
This is an initial prototype, not a complete AI deepfake detector. It does not contain a trained phishing classifier or validated image, video, or audio deepfake models. Email scoring is rule-based; media authenticity is deliberately marked NOT DETERMINED. Do not claim model accuracy until validated models are integrated and evaluated using labelled test data. The chat demo does not authenticate public keys, so a malicious server could substitute them.

## Suggested next milestone
Integrate models for:
1. phishing email text classification,
2. image deepfake detection,
3. video deepfake detection,
4. synthetic speech/audio detection.

For every model, document model name/version, source, license, supported inputs, hardware requirements, evaluation dataset, precision/recall, false positives/negatives, processing time and limitations.
