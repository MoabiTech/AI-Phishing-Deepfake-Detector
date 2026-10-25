# Fill in with actual measurements from testing
# Do not invent results. Fill after running each test.

| ID | Input | Expected check | Actual result | Time (seconds) | Pass/Fail | Notes |
|---|---|---|---|---:|---|---|
| E01 | Test email with urgency + password request | Indicators and score appear (High/Med risk) | Risk score 47 | 0.002859 | Pass | Five benchmark iterations; see `benchmark_results.json` |
| E02 | Benign sample email (legitimate) | Low score, no false high-risk claim; shows 'does not prove safe' disclaimer | Risk score 0 | 0.000644 | Pass | Five benchmark iterations; see `benchmark_results.json` |
| E03 | Email with URL (http/https) | URL extracted but NOT opened by tool | To be measured | TBD | TBD | Verify extraction only |
| E04 | Email with IP address URL | IP-based URL flagged | To be measured | TBD | TBD | Suspicious indicator |
| E05 | Email with punycode domain | Punycode flagged | To be measured | TBD | TBD | Internationalized domain |
| M01 | JPG/PNG image | Dimensions, format, size, SHA-256 appear | 1.4679 MiB generated PNG; integrity verified | 0.113246 | Pass | Three benchmark iterations; small PNG startup timing is separately visible in `benchmark_results.json` |
| M02 | WAV audio | Duration, sample rate, channels appear | 1 MiB generated WAV; integrity verified | 0.018213 | Pass | Three benchmark iterations |
| M03 | Supported video file | Metadata appears when OpenCV reads file | 1.0909 MiB generated AVI; integrity verified | 0.055244 | Pass | Three benchmark iterations; AVI is a supported video input |
| I01 | Inspect same file twice | SHA-256 values identical | SHA-256 unchanged for all benchmarked media | TBD | Pass | |
| P01 | Representative file each type (<2MiB) | Record analysis time for each | Email, PNG, WAV, and AVI measurements recorded; see below | See below | Pass | Three media iterations and five email iterations |
| P02 | Medium files (1-5MB) | Record times, check stability | 1.4679 MiB PNG and 5 MiB WAV processed without error | See `benchmark_results.json` | Pass | 5.5161 MiB AVI also processed successfully |
| P03 | Larger files (up to limit) | Find max successfully processed size | Largest tested: 1.4679 MiB PNG, 5 MiB WAV, 5.5161 MiB AVI | N/A | Partial | These are largest tested samples, not proven maximum limits |
| S01 | JSON report download | Valid JSON, contains all required fields | Automated JSON report test passed | TBD | Pass | |

## Executed Verification (2026-10-25)

- Detector suite: 8 tests passed, including the Streamlit email-analysis UI.
- Chat relay suite: 3 tests passed.
- Browser crypto suite: 2 tests passed; JavaScript syntax check passed.
- Local Streamlit and chat HTTP smoke checks returned 200 for their page/health/client assets.
- The benchmark script ran successfully after its project-root import path was corrected. It measured two email samples over five iterations each and generated PNG/WAV/AVI samples over three iterations each. All reported media samples retained their original SHA-256 hashes.
- The original 588-byte PNG run includes model-initialization variability; use the separately generated 1.4679 MiB PNG timing as the warmed image-processing estimate, not as a general service-level guarantee.
- Capacity checks successfully processed a 1.4679 MiB PNG, 5 MiB WAV, and 5.5161 MiB AVI through the media-analysis function. These are the largest tested samples only; no absolute maximum or Streamlit/browser upload ceiling was established.

## Performance Measurements (Measured samples)

**Test Environment:**
- Machine: [Record hostname/specs]
- OS: Windows
- RAM: [Record]
- CPU: [Record]
- Python: 3.13.7
- Date Tested: 2026-10-25

**Average Processing Times:**
| Media Type | Avg Time (s) | Max Time (s) | Min Time (s) | Runs |
|---|---:|---:|---:|---:|
| Email (text; suspicious sample) | 0.002859 | 0.012336 | 0.000412 | 5 |
| Email (text; benign sample) | 0.000644 | 0.002515 | 0.000152 | 5 |
| Image (generated PNG; 1.4679 MiB) | 0.113246 | 0.132802 | 0.097087 | 3 |
| Audio (generated WAV; 1 MiB) | 0.018213 | 0.019148 | 0.017423 | 3 |
| Video (generated AVI; 1.0909 MiB) | 0.055244 | 0.080549 | 0.024812 | 3 |

**Observed File Size Capacity (not proven maximum limits):**
| Media Type | Largest Successfully Tested | Notes |
|---|---|---|
| Image | 1.4679 MiB tested successfully | Largest generated sample; not a proven maximum |
| Audio | 5 MiB tested successfully | Largest generated sample; not a proven maximum |
| Video | 5.5161 MiB tested successfully | Largest generated sample; not a proven maximum |
| Email text | TBD | No maximum-size test run |

## Labelled Classification Tests (When Models Integrated)

For evaluation when trained models are added:

| Metric | Formula | Result | Notes |
|---|---|---:|---|
| True Positive (TP) | Malicious/synthetic correctly flagged | TBD | |
| False Positive (FP) | Genuine incorrectly flagged | TBD | |
| True Negative (TN) | Genuine correctly not flagged | TBD | |
| False Negative (FN) | Malicious/synthetic missed | TBD | |
| Precision | TP / (TP + FP) × 100% | TBD | |
| Recall (Sensitivity) | TP / (TP + FN) × 100% | TBD | |
| Accuracy | (TP + TN) / (TP + TN + FP + FN) × 100% | TBD | |
| F1-Score | 2×(Precision×Recall)/(Precision+Recall) | TBD | |

*Note: Only calculate metrics with reliable ground truth labels. Current prototype has no trained classifier.*
