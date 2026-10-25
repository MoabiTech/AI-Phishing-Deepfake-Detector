# Enhanced AI Phishing & Deepfake Detector
# Complete implementation with all required features

import streamlit as st
import hashlib
import io
import re
import time
import json
import mimetypes
import os
from datetime import datetime, timezone
from urllib.parse import urlparse
from PIL import Image

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def scan_email(text: str, sender: str = '', subject: str = ''):
    start_time = time.perf_counter()
    content = f'{subject}\n{sender}\n{text}'.strip()
    lower = content.lower()
    findings = []
    score = 0
    
    checks = [
        (r'\b(urgent|immediately|act now|final warning|account suspended|verify your account|expire|limited time)\b',
         'Urgency or account-pressure wording', 15),
        (r'\b(password|login credentials|one-time password|otp|verification code|pin|ssn|social security)\b',
         'Requests sensitive authentication/personal information', 20),
        (r'\b(wire transfer|bank account|payment|gift card|crypto|bitcoin|change of bank details|remittance)\b',
         'Payment or financial-action wording', 18),
        (r'\b(click here|open the attachment|enable macros|download now|click link|confirm now)\b',
         'Call to click, download, or enable content', 12),
        (r'\b(prize|winner|claim your reward|you have won|lottery|congratulations.*won)\b',
         'Prize or reward lure', 12),
        (r'\b(ceo|director|manager|lecturer|administrator|hr|payroll|finance|it support)\b',
         'Authority/personnel impersonation - verify independently', 6),
        (r'\b(update.*details|re-verify|confirm.*identity)\b',
         'Identity verification request', 10),
    ]
    for pattern, label, points in checks:
        if re.search(pattern, lower):
            findings.append({'indicator': label, 'points': points})
            score += points
    
    urls = re.findall(r'(?:https?://|www\.)[^\s<>\])\"\'\}]+', content, flags=re.I)
    for raw in urls:
        cleaned = raw.rstrip('.,;:)]}')
        try:
            parsed = urlparse(cleaned if cleaned.startswith('http') else 'http://' + cleaned)
            host = (parsed.hostname or '').lower()
        except ValueError:
            findings.append({'indicator': f'Malformed URL could not be parsed: {cleaned}', 'points': 8})
            score += 8
            continue
        if host:
            if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', host):
                findings.append({'indicator': f'URL uses IP address (suspicious): {cleaned}', 'points': 18})
                score += 18
            if 'xn--' in host or any(ord(c) > 127 for c in host):
                findings.append({'indicator': f'URL contains punycode/internationalized domain: {cleaned}', 'points': 18})
                score += 18
            if len(host) > 40:
                findings.append({'indicator': f'Unusually long URL host ({len(host)} chars): {host}', 'points': 7})
                score += 7
            if re.search(r'\.(tk|ml|ga|cf|gq|top|xyz)$', host):
                findings.append({'indicator': f'Suspicious top-level domain: {host}', 'points': 10})
                score += 10
    
    if sender:
        sender_domain = sender.lower().split('@')[-1] if '@' in sender else ''
        if re.search(r'(gmail|outlook|hotmail|yahoo|aol)\.com$', sender_domain) and re.search(
            r'\b(ceo|director|payroll|finance|bank|wire|transfer|urgent|confidential)\b', lower
        ):
            findings.append({'indicator': 'Free email provider used with business/financial urgency - high impersonation risk', 'points': 15})
            score += 15
    
    if re.search(r'\b(copy|paste).*link|link.*below', lower):
        findings.append({'indicator': 'Instructions to copy/paste link (bypass security)', 'points': 8})
        score += 8
    
    score = min(score, 100)
    if score >= 60:
        level = 'High Risk - Strong phishing indicators'
    elif score >= 35:
        level = 'Medium Risk - Suspicious indicators present'
    elif score >= 15:
        level = 'Low-Medium Risk - Some concerns'
    else:
        level = 'Low Risk - Few indicators found'
    
    if not findings:
        findings.append({'indicator': 'No configured rule matched. This does not prove the email is safe.', 'points': 0})
    
    return {
        'module': 'Email hybrid rule-based screening',
        'risk_score': score,
        'risk_level': level,
        'findings': findings,
        'urls_found': urls,
        'model_status': 'Rule-based hybrid (v1.0); trained AI classifier not yet integrated',
        'detection_methods': ['Urgency analysis', 'Credential request detection', 'Financial lure detection', 'URL/IP/punycode analysis', 'Sender impersonation heuristics', 'Domain reputation heuristics'],
        'limitations': 'Rules can miss sophisticated attacks and may flag legitimate messages. Always verify sender through official channels independently.',
        'analysis_time_seconds': round(time.perf_counter() - start_time, 6)
    }

def media_metadata(data: bytes, filename: str, mime: str = ''):
    start_time = time.perf_counter()
    info = {
        'filename': filename,
        'mime_type': mime or mimetypes.guess_type(filename)[0] or 'unknown',
        'size_bytes': len(data),
        'size_mib': round(len(data) / (1024 * 1024), 4),
        'sha256_before': sha256_bytes(data),
        'integrity_check': 'Original upload is held in memory only; SHA-256 is compared before and after inspection.',
        'processing_timestamp': datetime.now(timezone.utc).isoformat()
    }
    ext = os.path.splitext(filename)[1].lower()
    try:
        if ext in ['.txt', '.eml']:
            text = data.decode('utf-8-sig', errors='replace')
            info['media_type'] = 'text'
            info['character_count'] = len(text)
            info['email_analysis'] = scan_email(text)
            info['metadata_note'] = 'Text is analyzed as email content using transparent rules. No links are opened; trained AI phishing classification is not configured.'
        elif ext in ['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tif', '.tiff']:
            image = Image.open(io.BytesIO(data))
            info['media_type'] = 'image'
            info['image_format'] = image.format
            info['dimensions'] = f'{image.width} x {image.height}'
            info['mode'] = image.mode
            info['metadata_note'] = 'Basic format/dimensions extracted. EXIF/metadata present - cannot determine authenticity alone. No deepfake model configured.'
            
            # Try logo detection if available
            try:
                from utils.logo_detector import LogoDetector
                ld = LogoDetector()
                logo_results = ld.detect(data)
                if logo_results and not any('error' in r for r in logo_results):
                    info['logo_detection'] = logo_results
                    info['copied_logo_indicator'] = len(logo_results) > 0
            except Exception as le:
                info['logo_detection_error'] = str(le)
                
        elif ext in ['.wav']:
            import wave
            with wave.open(io.BytesIO(data), 'rb') as wav:
                info['media_type'] = 'audio'
                info['duration_seconds'] = round(wav.getnframes() / float(wav.getframerate()), 4)
                info['sample_rate_hz'] = wav.getframerate()
                info['channels'] = wav.getnchannels()
                info['sample_width_bytes'] = wav.getsampwidth()
                info['metadata_note'] = 'Technical audio properties only. Synthetic speech detection (anti-spoofing) not yet integrated. No validated audio deepfake model configured.'
        elif ext in ['.mp4', '.mov', '.avi', '.mkv', '.webm']:
            info['media_type'] = 'video'
            try:
                import cv2
                import tempfile
                suffix = ext
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name
                cap = None
                try:
                    cap = cv2.VideoCapture(tmp_path)
                    if cap.isOpened():
                        fps = cap.get(cv2.CAP_PROP_FPS)
                        frames = cap.get(cv2.CAP_PROP_FRAME_COUNT)
                        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                        info['fps'] = round(fps, 3) if fps and fps > 0 else None
                        info['frame_count'] = int(frames) if frames and frames > 0 else None
                        info['dimensions'] = f'{width} x {height}'
                        if fps and fps > 0 and frames and frames > 0:
                            info['duration_seconds'] = round(frames / fps, 4)
                        info['codec_info'] = 'Extracted via OpenCV'
                    else:
                        info['metadata_note'] = 'Video metadata could not be fully read by OpenCV decoder.'
                finally:
                    if cap is not None:
                        cap.release()
                    try:
                        os.unlink(tmp_path)
                    except OSError as cleanup_error:
                        info['cleanup_warning'] = f'Could not remove temporary video file: {cleanup_error}'
            except Exception as ve:
                info['metadata_note'] = f'Video inspection limited: {str(ve)}'
            info.setdefault('metadata_note', 'Technical video properties only. Frame-level deepfake analysis not yet integrated. No validated video deepfake model configured.')
        else:
            info['media_type'] = 'other'
            info['metadata_note'] = f'File type {ext} not in supported categories for detailed inspection.'
    except Exception as exc:
        info['inspection_error'] = str(exc)
        info['metadata_note'] = 'File could not be parsed by available inspectors.'
    
    info['deepfake_result'] = 'NOT DETERMINED - No validated deepfake detection model configured'
    info['ai_detection_status'] = 'Pending model integration'
    info['warning'] = 'Do NOT interpret technical inspection as a deepfake verdict. This is metadata analysis only.'
    info['sha256_after'] = sha256_bytes(data)
    info['integrity_verified'] = info['sha256_before'] == info['sha256_after']
    info['analysis_time_seconds'] = round(time.perf_counter() - start_time, 6)
    return info

def render_report(report):
    return json.dumps(report, indent=2, ensure_ascii=False)

def clear_media_report():
    st.session_state.pop('media_report', None)

def run_app():
    st.set_page_config(page_title='AI Phishing & Deepfake Detector', page_icon='🔍', layout='wide')
    st.title('AI Phishing & Deepfake Detector')
    st.caption('Email screening, media inspection, integrity checks, and downloadable reports')
    st.warning(
        'Prototype status: email screening uses explainable rules. Media is inspected for technical '
        'properties and logo similarity only. No validated deepfake model is configured, so media '
        'authenticity is always reported as NOT DETERMINED.'
    )

    email_tab, media_tab = st.tabs(['Email analysis', 'Media inspection'])

    with email_tab:
        st.subheader('Screen email text')
        sender = st.text_input('Sender address (optional)', key='email_sender')
        subject = st.text_input('Subject (optional)', key='email_subject')
        email_text = st.text_area('Paste email text', height=220, key='email_body')
        if st.button('Analyze email', type='primary'):
            if not email_text.strip() and not subject.strip():
                st.error('Enter an email subject or message before analysis.')
            else:
                analysis = scan_email(email_text, sender, subject)
                email_report = {
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'sender': sender,
                    'subject': subject,
                    'analysis': analysis
                }
                report_start = time.perf_counter()
                render_report(email_report)
                email_report['report_generation_time_seconds'] = round(
                    time.perf_counter() - report_start, 6
                )
                email_report['total_processing_time_seconds'] = round(
                    analysis['analysis_time_seconds'] + email_report['report_generation_time_seconds'], 6
                )
                st.session_state.email_report = email_report

        email_report = st.session_state.get('email_report')
        if email_report:
            analysis = email_report['analysis']
            st.metric('Risk score', f"{analysis['risk_score']} / 100", analysis['risk_level'])
            st.subheader('Findings')
            for finding in analysis['findings']:
                st.text(f"{finding['indicator']} (+{finding['points']})")
            st.caption('Extracted URLs are listed only; the detector never opens them.')
            if analysis['urls_found']:
                for url in analysis['urls_found']:
                    st.code(url, language=None)
            st.caption(analysis['limitations'])
            st.download_button(
                'Download email report (JSON)',
                data=render_report(email_report),
                file_name='email_analysis_report.json',
                mime='application/json'
            )

    with media_tab:
        st.subheader('Inspect a media or email file')
        uploaded_file = st.file_uploader(
            'Supported: TXT, EML, common images, WAV audio, and common video formats',
            type=['txt', 'eml', 'jpg', 'jpeg', 'png', 'webp', 'bmp', 'tif', 'tiff',
                  'wav', 'mp4', 'mov', 'avi', 'mkv', 'webm'],
            key='media_file',
            on_change=clear_media_report
        )
        if st.button('Inspect file', type='primary', disabled=uploaded_file is None):
            if uploaded_file is not None:
                data = uploaded_file.getvalue()
                media_report = media_metadata(
                    data, uploaded_file.name, uploaded_file.type or ''
                )
                report_start = time.perf_counter()
                render_report(media_report)
                media_report['report_generation_time_seconds'] = round(
                    time.perf_counter() - report_start, 6
                )
                media_report['total_processing_time_seconds'] = round(
                    media_report['analysis_time_seconds'] + media_report['report_generation_time_seconds'], 6
                )
                st.session_state.media_report = media_report

        media_report = st.session_state.get('media_report')
        if media_report:
            st.text(f"File: {media_report['filename']}")
            st.text(f"Type: {media_report.get('media_type', 'unknown')}")
            st.text(f"Size: {media_report['size_mib']} MiB")
            if media_report.get('inspection_error'):
                st.error('File inspection failed; details are included in the JSON report.')
                st.text(media_report['inspection_error'])
            if media_report.get('integrity_verified'):
                st.success('SHA-256 is unchanged after analysis; uploaded bytes were not modified.')
            else:
                st.error('Integrity verification failed: before/after SHA-256 values differ.')
            st.info(media_report['warning'])
            if 'email_analysis' in media_report:
                st.subheader('Email text findings')
                st.text(
                    f"Risk score: {media_report['email_analysis']['risk_score']} / 100 — "
                    f"{media_report['email_analysis']['risk_level']}"
                )
                for finding in media_report['email_analysis']['findings']:
                    st.text(f"{finding['indicator']} (+{finding['points']})")
            st.json(media_report)
            st.download_button(
                'Download media inspection report (JSON)',
                data=render_report(media_report),
                file_name='media_inspection_report.json',
                mime='application/json'
            )

if __name__ == '__main__':
    run_app()
