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
- Explainable email phishing rules for urgency, threats/deadlines, credentials, payment requests, MFA manipulation, secrecy, QR-code lures, sender impersonation, and suspicious URL patterns
- Optional local DistilBERT email classifier, enabled by a checkbox and downloaded on first use
- URL extraction without opening links
- TXT/EML analysis and image/video OCR; extracted text is screened with the same phishing rules
- QR payload extraction from images and sampled video frames; destinations are screened but never opened
- Image technical metadata and perceptual similarity against reference logos in `logos/`
- WAV/FLAC/OGG/AIFF/M4A metadata and local audio deepfake classification, enabled by default for audio uploads
- OpenCV video metadata, OCR from up to eight evenly sampled frames, and optional frame-by-frame image classification
- Before/after SHA-256 integrity checks; original upload bytes are not modified
- Downloadable JSON reports with findings, recommendations, limitations, errors, and timing
- Local end-to-end chat demo using browser Web Crypto

## Run the chat demo
From PowerShell:

```powershell
cd e2ee_chat
.\start_server.bat
```

Then open http://127.0.0.1:5000/. The chat is a local demonstration, not a production messenger.

## Optional local models and downloads

The app uses CPU inference and downloads model weights to the Hugging Face cache the first time each feature is selected. OCR is enabled by default for images/videos. Experimental image/video and audio classifiers are enabled by default for matching uploads; their checkboxes can be cleared to skip model inference. Email classification remains opt-in. The image/video classifier downloads about 355 MiB and the audio classifier about 360 MiB on first use; both need internet access. Initial audio model loading can take a few minutes on CPU. M4A uploads are decoded locally with FFmpeg to mono 16 kHz PCM, limited to 20 seconds for inspection; the report retains the original upload's hash and full duration. On this Windows setup, the launcher keeps the FFmpeg runtime and audio temporary files on D: (`DETECTOR_FFMPEG_RUNTIME`, `DETECTOR_AUDIO_TEMP_DIR`) and stores the audio model in `D:\detector\hf-cache` with Xet chunks in `D:\detector\hf-cache\xet`; set the corresponding environment variables before launch to override these paths. Hugging Face Xet transfer support is included to improve downloads for large model files.

| Capability | Model/source | Published status |
|---|---|---|
| Email classification | [DistilBERT phishing email classifier](https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1) | Apache-2.0; model card reports 99.58% accuracy, but its label mapping/evaluation are not independently validated here |
| Image and sampled video-frame classification | [SigLIP image classifier](https://huggingface.co/prithivMLmods/deepfake-detector-model-v1) | Apache-2.0; model card labels it experimental and reports 94.44% accuracy on its own evaluation split |
| Audio classification | [Wav2Vec2 audio classifier](https://huggingface.co/Hemgg/Deepfake-audio-detection) | Apache-2.0; model card reports 95.45% accuracy, with evaluation data details not independently verified |
| OCR | [RapidOCR](https://github.com/RapidAI/RapidOCR) ONNX Runtime package | Local OCR; the default model supports Chinese and English |

Model revisions are pinned in `utils/experimental_models.py`. Classifiers run locally; no email or media is sent to an inference API. Initial downloads require internet access and several hundred MiB per transformer model. Each model's report records its exact revision and caveats. Email model scores are kept separate from the rule-based risk score.

## Important limitations

The linked model cards' scores are self-reported and do not prove generalization to this institution, current attacks, different languages, or unseen media generators. This project has not independently validated any model or produced its own labelled test-set precision/recall results. Treat every model output as an experimental estimate, not a forensic verdict.

The image classifier estimates synthetic-like imagery; it is not a general detector of every face swap or image edit. Video classification applies that image model to up to eight sampled frames and does not analyze temporal consistency. Audio classification analyzes up to 20 seconds of WAV/FLAC/OGG/AIFF/M4A audio; M4A decoding requires the bundled FFmpeg dependency. OCR can omit or misread text. Logo similarity compares the uploaded image with reference logos; it does not locate logos embedded inside other images. The `logos/` directory is empty by default, so this signal is inactive until authorized references are supplied. A low score does not prove authenticity; a high score does not prove manipulation. Rules can miss attacks or flag legitimate mail. URL values are extracted but never opened.

For an assignment claim of "validated", evaluate the models against labelled held-out samples representative of the intended use, including false positives/negatives and per-media performance. Do not report the model-card accuracy values as results from this project.

The chat demo also does not authenticate public keys, so a malicious server could substitute them.

## Reports, testing, and logo references

- Assignment report drafts are in `reports/`. Replace the group/member placeholders, verify institutional facts with authorized LUCT staff, and check the final page count after formatting for submission.
- The `logos/` directory currently contains no reference images. Add only logos you are authorized to use, then restart the app so the local reference matcher loads them. Until then, the report marks logo matching as inactive.
- Run the detector tests and refresh benchmark measurements from this folder:

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
..\.venv\Scripts\python.exe scripts\benchmark.py
```

- Run chat relay and browser-crypto tests from `e2ee_chat`:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
node ..\tests\test_chat_crypto.js
node --check static\app.js
```

The detector is launched with `start_detector.bat`; it is source code plus a Windows launcher, not a packaged standalone executable. See `BUILD_INSTRUCTIONS.md`.
