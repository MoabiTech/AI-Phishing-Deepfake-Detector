# AI Phishing & Deepfake Detector - Technical Documentation

## Project Overview
This prototype demonstrates an AI-assisted approach to detecting phishing emails and inspecting media files for deepfake indicators as part of DISS3110 coursework.

## Features Implemented

### 0. User Interface
- Streamlit tabs for pasted email screening and file inspection
- Downloadable JSON reports for both workflows
- TXT/EML uploads are run through the email rules

### 1. Email Screening (Hybrid Rule-Based)
- Urgency and pressure tactic detection
- Credential/phishing keyword analysis
- Financial scam indicators (wire transfer, crypto, gift cards)
- Malicious URL detection (IP addresses, punycode/internationalized domains)
- Suspicious TLD detection (.tk, .ml, .ga, .cf, .gq, .top, .xyz)
- Sender impersonation heuristics (free email + authority claims)
- URL extraction without opening links
- Risk scoring (0-100) with severity levels
- Explainable findings with point values

### 2. Media Inspection
- **Text** (TXT, EML): Email rules applied without opening extracted links
- **Images** (JPG, JPEG, PNG, WEBP, BMP, TIF, TIFF): Format, dimensions, mode, SHA-256
- **Audio** (WAV): Duration, sample rate, channels, sample width
- **Video** (MP4, MOV, AVI, MKV, WEBM): FPS, frame count, duration, dimensions via OpenCV
- Perceptual hashing for logo detection (pHash) to identify copied/altered brand logos
- SHA-256 before/after verification of the in-memory upload bytes
- No file modification - original bytes held in memory only

### 3. Reporting & Evidence
- Downloadable JSON reports with timestamps (UTC)
- Analysis time measurement for all operations
- Model status documentation
- Clear disclaimers about limitations

### 4. Model Framework
- Modular design for easy integration of trained models
- Model registry documenting current status
- Prepared for ONNX Runtime, PyTorch integration
- Hybrid scoring architecture ready

## Technical Stack
- **Frontend**: Streamlit 1.66.0
- **Image Processing**: Pillow 12.3.0
- **Video Processing**: OpenCV (opencv-python-headless) 5.0.0.93
- **Perceptual Hashing**: ImageHash
- **ML Framework Ready**: scikit-learn, onnxruntime, numpy, pandas
- **Language**: Python 3.13.7

## Detection Models and Current Status
The email component uses transparent rules; it is not a trained AI classifier. No
validated media deepfake models are integrated, and media authenticity is reported
as NOT DETERMINED. The project is prepared for later integration of:
- Phishing text classification models
- Image deepfake detection (e.g., from DeepfakeBench)
- Video deepfake detection (frame-level analysis)
- Audio anti-spoofing/synthetic speech detection (e.g., wav2vec-based)

## Performance (Measured)
See benchmark_results.json for actual measurements on this machine.

## Non-Corruption Guarantee
- Files uploaded via Streamlit are read with `.getvalue()` and never rewritten
- SHA-256 is computed both before and after inspection and equality is reported
- Temporary files for video inspection are deleted immediately
- No write operations to source files

## Installation & Usage
`ash
# Activate virtual environment
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run application
streamlit run app.py
`

## Limitations
- No trained deepfake models integrated (honestly reported as NOT DETERMINED)
- Video/audio deepfake detection pending model integration
- Logo database can be expanded with curated brand logos
- Performance depends on hardware (CPU-only in current environment)

## Future Enhancements
- Integrate validated deepfake detection models
- Expand logo database
- Add TF-IDF + Logistic Regression baseline for comparison
- Implement LoRA fine-tuning pipeline
- Add comprehensive test suite with labelled datasets
