# Limkokwing University of Technology (LUCT)
## AI-Generated Phishing and Deepfake Media Detector

**Course:** DISS3110 — Information Systems Security  
**Group:** [Enter group number]  
**Members:** [Enter all member names and student numbers]  
**Date:** 3 November 2026

**Contents:** Introduction · System and models · Verification results · Lessons learnt · References

### Introduction

This local prototype screens suspicious email text and inspects text, image, audio, and video files for phishing or synthetic-media indicators. It provides explainable findings and a downloadable JSON report; it is a triage aid, not a forensic verdict. A separate local chat demonstration provides end-to-end encrypted text and file transfer.

### System and models

Email rules check urgency, credential and MFA requests, payments, impersonation, secrecy, QR lures, and suspicious URLs. URLs and QR destinations are extracted and screened but never opened. Optional local OCR screens image text and up to eight sampled video frames. The experimental image/video classifier is enabled by default for visual uploads; first use downloads about 355 MiB of model weights. Email classification remains opt-in. Results remain estimates and are not independently validated by this project.

| Capability | Model / method | Scope and limitation |
|---|---|---|
| Email | DistilBERT `cybersectony/phishing-email-detection-distilbert_v2.4.1` | Optional; up to 512 tokens. Model-card metrics are not this project's evaluation. |
| Image and sampled video frames | SigLIP `prithivMLmods/deepfake-detector-model-v1` | Image-level estimate; video samples at most eight frames and does not analyze temporal consistency. |
| Audio | Wav2Vec2 `Hemgg/Deepfake-audio-detection` | Enabled by default for WAV/FLAC/OGG/AIFF/M4A; M4A is decoded locally and up to 20 seconds are analyzed after first-use model loading. |
| Text extraction | RapidOCR / ONNX Runtime | Optional for images/video; OCR may omit or misread text. |
| Logo comparison | pHash against local `logos/` reference images | Similarity only; compares the uploaded image as a whole, not a logo embedded inside another image. The reference directory is empty, so the signal is inactive until authorized images are added. |

Email risk scoring, OCR/QR findings, classifier estimates, and logo similarity are reported separately. Audio classification is enabled by default for WAV/FLAC/OGG/AIFF/M4A uploads, uses local Wav2Vec2 inference after a first-use model download, and analyzes up to 20 seconds. Video uses frame-level image inference, not a dedicated video model. No model metrics were reproduced on a labelled local test set; do not present model-card accuracy as project accuracy.

### Verification results

Validated on Windows 11, Python 3.13.7, Intel Core i5-1135G7 (8 logical processors), 11.8 GiB RAM, CPU inference. Measurements are three media runs and five email runs; optional model inference and OCR are disabled. They are sample averages, not performance guarantees. Report generation is measured separately as JSON serialization and is included in total time.

| Test input | Average analysis | Average report generation | Average total | Largest successful sample observed |
|---|---:|---:|---:|---:|
| Suspicious email text | 0.009992 s | 0.000444 s | 0.010446 s | Not capacity-tested |
| Benign email text | 0.000497 s | 0.000207 s | 0.000708 s | Not capacity-tested |
| PNG image, 1.4679 MiB | 0.282738 s | 0.000316 s | 0.284331 s | 5.6269 MiB |
| WAV audio, 1 MiB | 0.194181 s | 0.000422 s | 0.194687 s | 5 MiB |
| AVI video, 1.0909 MiB | 3.058705 s | 0.000890 s | 3.064407 s | 5.5161 MiB |

These are largest tested files, not maximum supported sizes. The application does not establish a safe hard maximum for every decoder or browser upload. SHA-256 before/after matched on all measured media samples; inspection reads uploaded bytes without rewriting them. The 34-test detector suite, 3 chat relay tests, and 2 browser crypto tests pass in the project environment.

The 5.6269 MiB PNG, 5 MiB WAV, and 5.5161 MiB AVI capacity samples completed without inspection errors (three-run average total times 1.763788 s, 0.136402 s, and 2.705396 s respectively). These larger-file times are not model-enabled or OCR-enabled. Audio classifier tests use mocked model outputs to verify audio resampling, chunking, and report handling; they are not an independent accuracy or latency evaluation.

An M4A voice note of 44.16 seconds decoded and completed local model inference. The classifier analyzed the first 20 seconds and reported 24.16 seconds omitted; its estimate was 5.9% synthetic-like. The original file hash was unchanged. Model loading plus report generation took 114.27 seconds in this single run. This result is an experimental estimate, not evidence of model accuracy or proof that the voice is genuine.

### Encrypted chat and lessons learnt

The browser encrypts each message/file with AES-256-GCM and wraps a fresh AES key to the recipient's RSA-OAEP-2048/SHA-256 public key. The relay forwards ciphertext and does not decrypt it. Browser crypto tests verify round trips and modified-ciphertext rejection; file transfer is capped at 10 MiB. This classroom demo does not authenticate public keys, provide forward secrecy, or protect connection metadata; do not expose it to the public internet.

Part I reinforced that risk ownership, evidence, likelihood/impact scoring, and tested controls are needed before residual risk can be accepted. Part II demonstrated the value of independent identity verification, layered detection, safe URL handling, preserving file hashes, measuring performance on real hardware, and documenting limitations. An AI score is not proof: staff must verify high-impact requests through a separately known channel. Future work is to populate the logo reference set with authorized assets, validate models on labelled held-out samples, measure model-enabled latency, and obtain institution-specific risk evidence.

### References (Harvard)

Cybersecurity and Infrastructure Security Agency (CISA) (n.d.) *Avoiding social engineering and phishing attacks*. Available at: https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks (Accessed: 3 November 2026).

CyberSectony (n.d.) *A DistilBERT based phishing email detection model*. Available at: https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1 (Accessed: 3 November 2026).

Hemgg (n.d.) *Deepfake audio recognition*. Available at: https://huggingface.co/Hemgg/Deepfake-audio-detection (Accessed: 3 November 2026).

PrithivMLmods (n.d.) *Deepfake detector model v1*. Available at: https://huggingface.co/prithivMLmods/deepfake-detector-model-v1 (Accessed: 3 November 2026).
