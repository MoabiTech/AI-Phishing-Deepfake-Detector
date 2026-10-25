# AI Phishing & Deepfake Detector — Assignment Plan & Working Document

**Course:** DISS3110 — Information Systems Security
**Institution:** Limkokwing University of Technology (LUCT) — Faculty of Information & Communication Technology
**Programme:** Diploma in Information Technology, Semester 5
**Lecturer:** Itumeleng Mokhachane — itumeleng.mokhachane@limkokwing.ac.ls
**Weight:** 20% of course mark (150 marks total: Part I 75 + Part II 75)
**Deadlines:** Part I — Week 11 · Part II — Week 15 (20 min per presentation)
**Source brief:** `D:\SCHOOL WORK\YEAR 3 SEMESTER 1\SECURITY\2026 Group Assignment.pdf`

---

## 1. Assignment requirements (verbatim from the brief)

### Assignment overview
Integrate software development skills with information systems security skills. Required skill sets:
- Information security planning and governance, especially **risk management** (identifying risk, assessing relative magnitude, reducing to acceptable level)
- Security Systems Development Life Cycle (**SecSDLC**)
- Cyber-attacks and their controls (**AI-generated phishing emails**, AI-powered threat detection)
- Team cohesion
- Programming in preferred language

### Expected outcomes
A complete analysis of the **information security status quo** of any institution of choice — to refine or establish that institution's risk management process by recognising, enumerating and documenting risks to information assets, determining the extent of exposure, and applying controls that reduce risk to an acceptable level.

> "Again, you are expected to develop your own **end-to-end encrypted chat application**."

### The 10 questions

| # | Requirement | Current status |
|---|---|---|
| 1 | Research an institution of choice | NOT STARTED (Part I) |
| 2 | Identify / assess / control risks; produce processes and documents | NOT STARTED (Part I) |
| 3 | Context: deepfake phishing (fake CEO voice note, fake LinkedIn profiles) | Understood — informs design |
| 4 | Research AI-generated phishing email + deepfake media detectors | DONE (see §5) |
| 5 | **Design and implement** the detector — identify phishing via **imitated text, copied logos, altered media** | PARTIAL — see §3 |
| 6 | Verify the tool works; report on: (a) extra detection steps, (b) **max file size**, (c) **average time** per email/media + report generation, (d) **AI model(s) used**, (e) support **text, image, video, audio** | NOT DONE — see §3 |
| 7 | Detect varied media files within a reasonable time | NOT DONE |
| 8 | Verify the tool **does not corrupt** detected emails and media | PARTIAL — hash recorded, not compared |
| 9 | Account of **lessons learnt** (risk management + detector) | NOT STARTED |
| 10 | Prepare reports and presentations | NOT STARTED |

### Marking criteria (150 total)

**Part I — Risk Management: 75**
- Identification, Assessment and Control: 25 marks (5 each)
- Layout (presentation) 10 · Content 3 · Originality 3 · Effectiveness 4 · Readability 5

**Part II — End-to-end Encrypted Chat Application: 75**
- Efficiency and robustness 6
- Average performance (time taken, max file and device size) 10
- **Employed AI model(s) 10**
- Support for varied media file formats 6
- Extra steps taken for detecting emails and media 6
- Non-corruption of detected emails and media 6
- Lessons learnt (Part I and II) 6
- Audibility 5 · Confidence 5 · Dress code 5 · Teamwork 5 · Questions and answers 5

> Technical subtotal 44 + lessons 6 + presentation 25 = 75.

### Submission information
- Submit **reports** with LUCT cover page, stapled together
- Soft copies via Google Classroom **plus the detecting tool's source code and executable file(s)**
- Share responsibilities; all group members must contribute to presentations
- No copying templates from other sources — templates are guidelines only; work must be original

### Specific information
- Risk management documents **must not exceed 21 pages** (7 max per sub-step: identification, assessment, control)
- AI detector report **must not exceed 2 pages** — high-level, integral to the presentation
- Six groups of five members (one group of six); every member involved in every aspect

### Required report structure

**Part I**
1. LUCT cover page
2. Title of the assignment
3. Abstract
4. Table of contents
5. Institution's risk management
6. Bibliography (Harvard)

**Part II**
1. LUCT cover page
2. Title of the assignment
3. Table of contents
4. Introduction
5. AI-Generated Phishing Email and Deepfake Media Detector details
6. Lessons learnt
7. Bibliography (Harvard)

---

## 2. Hardware and environment constraints (measured)

| Resource | Value | Implication |
|---|---|---|
| GPU | **None** | CPU-only inference; training must be done on Kaggle/Colab free T4 |
| Logical CPUs | 8 | ONNX Runtime is a better fit than PyTorch for CPU inference |
| RAM | 11.8 GiB total, **~1.2 GiB free** | Keep at most 1-2 models resident; load lazily |
| C: free disk | **6.5 GiB** | Insufficient — move venv and model cache to D: |
| D: free disk | 174.6 GiB | Use for venv, HF cache and model weights |
| Python | 3.13.7 | Onnxruntime 1.20+ and torch 2.7+ support 3.13 |
| torch | **not installed** | ~1.5 GB install |

Existing environment: venv at `..\.venv` (Python 3.13.7) with `streamlit 1.66.0`, `pillow 12.3.0`, `opencv-python-headless 5.0.0.93`. All already installed and matching `requirements.txt`.

**Action:** move or recreate the venv on D:, and set `HF_HOME` to a D: path so the HF model cache does not fill C:.

```bash
# Proposed layout
D:/detector/{venv,models,hf-cache,project}
setx HF_HOME "D:/detector/hf-cache"
```

---

## 3. Compliance gap analysis

### 3.1 Part I — Risk Management (75 marks): 0% present
No artefact in the project relates to this part. Requires institution research plus Risk Identification, Risk Assessment and Risk Control processes and documentation, capped at 21 pages total.

### 3.2 Part II — End-to-end Encrypted Chat Application: 0% present
The marking table titles Part II this. Nothing in the repository addresses it. **Confirm scope with the lecturer** — the marking table is misaligned in the PDF text layer, so it is unclear whether Part II is the chat app, the detector, or both, and how the 75 marks split between them.

Suggested minimum viable scope: server + client, asymmetric key agreement (RSA-2048 or ECC P-256), symmetric session key (AES-256-GCM), per-message nonce, HMAC or AEAD authentication, key derivation via PBKDF2 or HKDF, plus a short design note showing the SecSDLC reasoning. Document the threat model and what is *not* protected (no forward secrecy, no certificate/PKI, metadata visible).

### 3.3 Part II — AI Detector technical criteria (44 marks)

| Criterion | Marks | Status | Notes |
|---|---:|---|---|
| Employed AI model(s) | 10 | **ZERO** | Regex rules only. `app.py:89` states `"Rule-based prototype; no trained AI classifier configured"`; `app.py:149` states `"NOT DETERMINED"` for all media |
| Average performance (time, max file, device size) | 10 | **ZERO** | `TEST_PLAN.md` is a blank template — all 9 rows empty |
| Support for varied media file formats | 6 | PARTIAL | All four categories exist, but the media path crashes 100% and audio is WAV-only |
| Extra steps for detecting emails and media | 6 | WEAK | Rules + URL extraction only. **No "copied logos" / brand-impersonation detection**, which Q5 explicitly requires |
| Non-corruption of emails and media | 6 | PARTIAL | `sha256_before` only (`app.py:99`); no after-value, no actual verification |
| Efficiency and robustness | 6 | **FAILING** | Media module crashes; no measurements |
| Lessons learnt (Part I and II) | 6 | **ZERO** | Not written |

### 3.4 Deliverables missing
- **Executable file(s)** — the brief explicitly requires "source code and executable file(s)". No packaging exists. Use PyInstaller.
- **Part I risk documents** (≤21 pages)
- **Part II report** (≤2 pages) with cover page, ToC, introduction, detector details, lessons learnt, Harvard bibliography
- **Lessons learnt** account
- **Git repository + `.gitignore`** — the current git root is `C:\Users\Administrator` (the entire home directory), so the project is not version-controlled as a unit

---

## 4. Code defects found (verified by execution)

### D1 — CRITICAL: `NameError` crashes all media inspection
`app.py:103` calls `os.path.splitext(filename)` but `os` is never imported (`app.py:1-9`). The call sits **outside** the `try:` block that begins at `app.py:104`, so the exception is unhandled and the whole media tab fails.

```
REPRODUCED NameError : name 'os' is not defined
```

**Fix:** add `import os` to the import block.
**Impact:** kills tests M01, M02, M03, I01, P01, P02 — every media row of `TEST_PLAN.md`.

### D2 — HIGH: video metadata never reads on Windows
`app.py:124-127` opens the file with `tempfile.NamedTemporaryFile(delete=True)` and calls `cv2.VideoCapture(tmp.name)` **while the handle is still open**. Windows locks the file, so OpenCV cannot read it.

```
cv::findDecoder imread_('...\tmp4zy1msys.mp4'): can't open/read file
NamedTemporaryFile+open (app.py way) -> isOpened: False
```

**Fix:** write to a named temp path, close the file, then open with OpenCV (e.g. `tempfile.mkstemp` + `os.close`, or `NamedTemporaryFile(delete=False)` then unlink in a `finally`).

### D3 — MEDIUM: audio support is WAV-only
`app.py:111` matches only `.wav`; `app.py:207` restricts uploads to `wav`. But the brief's own worked example (Q3) is *"a Deepfake voice note of a CEO"* — voice notes are mp3/m4a/ogg, never WAV. As shipped the tool cannot analyse the exact attack scenario described.

**Fix:** decode via `soundfile`/`librosa` (needs `ffmpeg` for mp3/m4a) and accept `mp3, m4a, ogg, flac, aac, opus, wav`.

### D4 — MEDIUM: `sha256_after` missing
Only `sha256_before` is stored (`app.py:99`). The About tab's own step 5 and the README promise a before/after comparison to prove the source file is preserved. Nothing computes or compares it.

### D5 — LOW: `cap.release()` skipped on the failure path
`app.py:128-139` — `cap.release()` is inside the `if cap.isOpened():` branch, so the handle leaks when the video fails to open.

### D6 — LOW: `urls_found` returns raw URLs while findings use cleaned URLs
`app.py:52` computes `cleaned = raw.rstrip(".,;:")` and uses it in findings (`app.py:57-63`), but `urls_found` (`app.py:88`) returns the raw strings. The JSON report and the UI therefore disagree on trailing punctuation.

### D7 — LOW: sender parsing breaks on display-name form
`app.py:66` uses `sender.lower().split("@")[-1]`, which for `John <john@x.com>` yields `x.com>` and fails the provider check.

### D8 — LOW: provider regex is imprecise
`app.py:66` — `r"(gmail|outlook|yahoo)\.com$"` also matches `notgmail.com`, and covers no non-`.com` provider.

---

## 5. AI model strategy

### 5.1 Do we need to train? — Recommendation
**Not from scratch.** The rubric says **"Employed AI model(s)"** (10 marks) and Q6(d) asks *"AI model(s) **used to** detect…"*. Both refer to the models deployed, not the models built. Q5's wording ("Develop AI models") creates the tension, so use the hybrid below to be safe.

| Approach | Marks | Risk |
|---|---|---|
| Pretrained only | ~7-8/10 | Lecturer asks "did you train anything?" — risk of losing marks |
| **Pretrained + 1 fine-tune + 1 baseline + own logo detector** | **~10/10** | Low |
| Train everything from scratch | 10/10 | Not feasible on this hardware; weeks of work |

**Hybrid plan:**
1. **Deploy pretrained models** for email, audio, image/video detection (below).
2. **Fine-tune one model yourself** — LoRA on the phishing DistilBERT, trained on AI-generated phishing email data. Train on Kaggle/Colab free T4 (~15 min), download the multi-MB LoRA adapter. This is the "develop" evidence.
3. **Build the logo detection yourself** — no pretrained model exists for "copied logos", so pHash/dHash matching against a curated brand-logo bank is genuinely original work and directly answers Q5.
4. **Train a TF-IDF + LogisticRegression baseline** on a public dataset (~15 min, CPU only) to produce a comparison table for the report — this is what makes the report read as engineering rather than a model download.

### 5.2 Recommended model stack

**Email text — `mikaelnurminen/phishing-email-detector-v51`**
- MIT licence · DistilBERT, 253 MB · multi-task (phishing vs safe) + 6-class phishing-type auxiliary head
- Reported: accuracy 0.9855, F1 0.9806, ROC-AUC 0.9989, PR-AUC 0.9981, FP/1k 8.06, FN/1k 25.23
- Calibrated thresholds: balanced 0.3635, high-recall 0.9546, high-precision 0.0100
- Trained on `zefang-liu/phishing-email-dataset` (~18.6k) + `ealvaradob/phishing-dataset` (~4.8k), merged to ~30k
- Alternative: `dima806/phishing-email-detection` (Apache-2.0, 251 MB, ONNX mirror available)

**Audio — `shravan37/vaanishield-wav2vec2-asvspoof`**
- MIT licence · 117 MB int8 ONNX · **runs on onnxruntime without torch** — the right choice given the disk/RAM limits
- ~160 ms per 1 s of audio on one CPU core · EER 2.66% int8 (2.36% fp32), balanced accuracy 91.7%
- Weights: `facebook/wav2vec2-base`, top 4 transformer layers fine-tuned, 3-layer MLP head
- Alternatives: `caa-speech-detection-asvspoof2019/wav2vec2-v2-unfrozen` (1.55% EER but 725 MB + fairseq dependency), `Sara1708/deepfake-audio-wav2vec2` (Apache-2.0, 468 MB)
- **Document honestly:** ASVspoof-2019 attack families only, English only, A10 is the weakest family, 1-second windows degrade EER to ~10%

**Image / video — `KoreaPeter/ms-eff-gcvit-deepfake-b5-kodf`**
- MIT licence · 216 MB · timm/PyTorch, frame-level, works on images and video via `pipeline("video-classification")`
- b0 variant: 8.7M params, 224×224, real-time capable (best fit for this hardware)
- **Document honestly:** the model card's own cross-dataset results are AUC 0.47 on Celeb-DF-v2 (worse than chance) and 0.53-0.59 on FaceForensics++ when trained on KoDF. Do not quote the 0.97 KoDF figure as a general result — this is exactly the kind of thing a lecturer probing "Effectiveness" will check.
- Alternatives: `SCLBD/DeepfakeBench` (36 detectors, CC BY-NC — academic use OK, heavyweight), `DavidCombei/deepfake-detection` (routing audio/video/lipsync, needs three separate environments — avoid)

**Logo / brand impersonation — build yourself**
- Perceptual hashing (pHash/dHash) of uploaded images compared against a curated bank of brand logos (banking, email providers, government, corporate)
- Use Pillow + `imagehash` (add `imagehash` and `ImageHash`); report Hamming distance threshold
- This is the "copied logos" requirement and an original contribution for the originality marks

### 5.3 Design: hybrid detector

Keep the existing rule engine as the transparent, explainable layer and add the models alongside it. The hybrid is what earns the "extra steps taken" (6 marks) as well as the model marks.

```
Email  -> rule indicators (urgency, credentials, payment, CTA, prize, authority)
       -> URL checks (IP host, punycode, long host, display-name mismatch)
       -> phishing classifier (pretrained + your LoRA fine-tune)
       -> logo pHash match against brand bank
       -> combined verdict + per-signal explanation

Image  -> metadata + SHA-256 -> pHash logo match -> image deepfake model -> verdict
Video  -> metadata (fixed temp-file bug) -> frame sampling -> image deepfake model -> verdict
Audio  -> metadata + SHA-256 -> resample 16 kHz mono -> anti-spoofing model -> verdict
```

Report each signal separately with its own confidence so the report satisfies "extra steps taken".

---

## 6. Datasets for training and evaluation

You must produce **your own** measured metrics. The model cards' self-reported numbers do not satisfy Q6 or the `TEST_PLAN.md` formulas.

| Purpose | Dataset | Size | Access |
|---|---|---|---|
| AI-generated phishing (train + eval) | `kxm1k4m1/generate_phishing_email_final` | 5.4 MB | Open |
| Phishing classification | `zefang-liu/phishing-email-dataset` | 49.6 MB | Open |
| Ham/spam sanity check | `talby/spamassassin` | 0.5 MB | Open |
| Phishing classification (large) | `SetFit/enron_spam` | 151.7 MB | Open |
| Spam/phishing corpora | `puyang2025/seven-phishing-email-datasets` | 219.2 MB | Open |
| Email corpus | `ealvaradob/phishing-dataset` | 1623.6 MB | Open |
| Audio anti-spoofing | ASVspoof 2019 LA — 25,380 train / 71,237 eval utterances | large | Open |
| Audio out-of-domain | In-the-Wild (31,779 trials) | medium | Open |
| Audio vocoder | WaveFake | small | Open |
| Image/video deepfake | FaceForensics++ | large | EULA form required |
| Image/video deepfake | Celeb-DF v2 | large | Request form |
| Speech dataset | `YMLLG/SpeechFake` — 3M+ samples, 46 languages, 30 generators | very large | Open |

### Evaluation formulas (from `TEST_PLAN.md` — use exactly)
- TP: malicious/deepfake sample correctly flagged
- FP: genuine sample incorrectly flagged
- TN: genuine sample correctly not flagged
- FN: malicious/deepfake sample missed
- Precision = TP / (TP + FP) x 100%
- Recall = TP / (TP + FN) x 100%
- Accuracy = (TP + TN) / (TP + TN + FP + FN) x 100%
- Average processing time = total measured time / number of completed runs
- Only compute metrics when labels are reliable and denominators are non-zero

---

## 7. Action plan

### Phase 0 — Unblock (est. 1-2 hours)
- [ ] Fix D1: add `import os`
- [ ] Fix D2: close temp file before OpenCV
- [ ] Fix D3: add mp3/m4a/ogg/flac via `soundfile`/`librosa` + ffmpeg
- [ ] Fix D4: add `sha256_after` and a real before/after comparison
- [ ] Fix D5, D6, D7, D8
- [ ] Move venv and `HF_HOME` to D:
- [ ] `git init` in the project folder, add `.gitignore` (`.venv/`, `__pycache__/`, `*.pyc`, `models/`, `hf-cache/`)

### Phase 1 — Models (the 10-mark criterion)
- [ ] Email classifier behind a `detect_email()` interface, cached with `@st.cache_resource`
- [ ] Audio anti-spoofing via onnxruntime
- [ ] Image deepfake model via timm/PyTorch
- [ ] Video deepfake model via the same frame-level model, sampling frames
- [ ] Logo pHash module + curated brand-logo bank
- [ ] Hybrid scoring layer + per-signal explanation in the JSON report

### Phase 2 — Originality + evidence
- [ ] TF-IDF + LogisticRegression baseline on the same data, for a comparison table
- [ ] LoRA fine-tune script for the phishing model (Kaggle/Colab-ready) on AI-generated phishing data
- [ ] `benchmark.py` producing max file size and average time per media type on this machine
- [ ] Fill in every row of `TEST_PLAN.md` with real measurements
- [ ] Labelled test set with TP/FP/TN/FN counts and precision/recall/accuracy

### Phase 3 — Documents and packaging
- [ ] Part I risk documents (≤21 pages: identification / assessment / control, ≤7 each)
- [ ] Part II report (≤2 pages)
- [ ] Lessons learnt (Part I and II)
- [ ] Harvard bibliography for both parts
- [ ] LUCT cover pages and table of contents for both parts
- [ ] PyInstaller `.exe` (plus keep source code for submission)
- [ ] Group responsibility matrix and presentation allocation

---

## 8. Report content guidance

### Part I — Institution risk management (≤21 pages)
1. Institution profile and information assets (inventory)
2. Risk Identification — enumerate risks to each asset (use a proper risk register table: asset, threat, vulnerability, existing controls, risk owner)
3. Risk Assessment — likelihood x impact matrix, inherent vs residual risk, ranking
4. Risk Control — control type (preventive/detective/corrective), chosen controls, residual risk, treatment rationale (accept/mitigate/transfer/avoid)
5. Cite SecSDLC phases and relate controls to the risk register

### Part II — AI Detector (≤2 pages, high level)
1. Introduction and problem statement
2. Architecture diagram: rule engine + models + logo matcher + integrity hashing
3. **AI model(s) used** — name, version, source URL, licence, inputs supported, hardware requirements, evaluation dataset, precision/recall, FP/FN counts, processing time, limitations
4. Extra detection steps taken
5. Performance table — average time and maximum file size per media type, on this machine
6. Non-corruption evidence — SHA-256 before/after
7. Limitations and honest failure modes (including the cross-dataset generalisation weakness of the image model)
8. Lessons learnt
9. References (Harvard)

### Marking hints
- "Employed AI model(s)" (10) is earned by the model documentation table in point 3 above — fill every column
- "Average performance" (10) is earned by the table in point 5 — measure on the machine that will be used for the demo
- "Non-corruption" (6) is earned by point 6
- "Extra steps" (6) is earned by point 4 — the hybrid rule + hash + logo pipeline
- "Originality" (Part I, 3 marks) is earned by the original logo-detection module and the fine-tune

---

## 9. Bibliography — Harvard style, ready to expand

> Harvard referencing in this course: Author, A. (Year) *Title of work*. Edition. Place of publication: Publisher. Available at: URL (Accessed: DD Month YYYY).

Seed references:

- Yan, Z., Zhang, Y., Yuan, X., Lyu, S., Wu, B. et al. (2023) *DeepfakeBench: a comprehensive benchmark of deepfake detection*. NeurIPS 2023 Datasets and Benchmarks. Available at: https://github.com/SCLBD/DeepfakeBench (Accessed: 22 October 2026).
- Tak, H., Todisco, M., Wang, Y., Jung, H., Yamagishi, H. and Evans, N. (2022) *Automatic speaker verification spoofing and deepfake detection using wav2vec 2.0 and data augmentation*. IEEE Odyssey 2022. Available at: https://arxiv.org/abs/2202.12233 (Accessed: 22 October 2026).
- Rosin, S.L., et al. (2019) *FaceForensics++: learning to detect manipulated facial images*. Available at: https://github.com/ondyari/faceforensics (Accessed: 22 October 2026).
- Wang, Z., et al. (2024) *SpeechFake: a large-scale multilingual speech deepfake dataset*. Available at: https://github.com/YMLLG/SpeechFake (Accessed: 22 October 2026).
- Ba, Z., et al. (2024) *W2V2-AASIST: automatic speaker verification spoofing and deepfake detection using wav2vec 2.0 and data augmentation*. Available at: https://huggingface.co/SpeechAntiSpoofingBenchmarks/W2V2-AASIST (Accessed: 22 October 2026).
- Nurminen, M. (2026) *Phishing email detector V5.1*. Available at: https://huggingface.co/mikaelnurminen/phishing-email-detector-v51 (Accessed: 22 October 2026).
- Kasar, S. (2026) *VaaniShield wav2vec2 voice-clone detector*. Available at: https://huggingface.co/shravan37/vaanishield-wav2vec2-asvspoof (Accessed: 22 October 2026).
- Kim, Y., Yun, K., Hong, S., Cha, S., Koo, S.S. and Noh, J. (2026) *X-AVDT: audio-visual cross-attention for robust deepfake detection*. CVPR 2026. Available at: https://huggingface.co/datasets/zaqxsw0526/MMDF (Accessed: 22 October 2026).

**Licence note for the report:** DeepfakeBench and AVPF are **CC BY-NC 4.0** (non-commercial, academic research use) and the FaceForensics++ data is under the FaceForensics Terms of Use. This is acceptable for a student assignment but must be stated in the report and bibliography.

---

## 10. Open questions for the lecturer

1. Does Part II mean the **chat application**, the **detector**, or **both**? The marking table is misaligned in the PDF text layer. How do the 75 marks split?
2. Is integrating a pre-trained model sufficient for "Develop AI models" (Q5), or is a self-trained model expected?
3. Are there institutional requirements for the risk register template (the brief says templates may be used as guidelines only)?
4. What is the maximum acceptable size for the submitted executable, and must it run offline?
5. Is there a required demonstration dataset for the presentation, and must it be supplied with the submission?

---

## 11. Current project inventory

```
AI_Phishing_Deepfake_Detector/
├── app.py               274 lines — single-file Streamlit app, 3 tabs
│                         (Email scanner, Media inspector, About & testing)
├── README.md            prototype scope + limitations + suggested next milestone
├── TEST_PLAN.md         blank template, 9 test rows (E01-E03, M01-M03, I01, P01, P02)
├── requirements.txt     streamlit>=1.36,<2.0 / Pillow>=10.0 / opencv-python-headless>=4.9
└── PROJECT_PLAN.md     this document
```

**Strengths to preserve**
- Honest labelling: media results explicitly `NOT DETERMINED`, no invented accuracy claims
- URL extraction never opens links; no network calls anywhere in `app.py`
- Correct 4-category media coverage in principle (text via email, image, video, audio)
- JSON report download with measured analysis time
- `scan_email` scoring is sound: capped at 100, thresholds 50/25, no-match case states "This does not prove the email is safe"
- App boots clean under `streamlit.testing.v1.AppTest` — 3 tabs, 0 exceptions

**Weaknesses to close**
- No AI model of any kind
- Media tab crashes on every file
- Video broken on Windows
- Audio WAV-only
- No measurements, no benchmarks, empty test plan
- No chat application, no Part I documents, no report, no executable
