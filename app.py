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
import ipaddress
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from datetime import datetime, timezone
from urllib.parse import urlparse
from PIL import Image

APP_ROOT = os.path.dirname(os.path.abspath(__file__))


@st.cache_resource
def get_ocr_engine():
    from utils.experimental_models import load_ocr_engine

    return load_ocr_engine()


@st.cache_resource
def get_email_classifier():
    from utils.experimental_models import load_email_classifier

    return load_email_classifier()


@st.cache_resource
def get_image_classifier():
    from utils.experimental_models import load_image_classifier

    return load_image_classifier()


@st.cache_resource
def get_audio_classifier():
    from utils.experimental_models import load_audio_classifier

    return load_audio_classifier()


@st.cache_resource
def get_logo_detector():
    from utils.logo_detector import LogoDetector

    return LogoDetector(os.path.join(APP_ROOT, 'logos'))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _HtmlTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {'script', 'style'}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in {'script', 'style'} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth and data.strip():
            self.text_parts.append(data.strip())


def _extract_eml(data: bytes) -> tuple[str, str, str]:
    message = BytesParser(policy=policy.default).parsebytes(data)
    body_parts = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == 'attachment':
            continue
        content_type = part.get_content_type()
        if content_type not in {'text/plain', 'text/html'}:
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            body = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
        if not isinstance(body, str):
            continue
        if content_type == 'text/html':
            parser = _HtmlTextExtractor()
            parser.feed(body)
            body = '\n'.join(parser.text_parts)
        if body.strip():
            body_parts.append(body.strip())
    return str(message.get('From', '')), str(message.get('Subject', '')), '\n'.join(body_parts)


def scan_email(
    text: str,
    sender: str = '',
    subject: str = '',
    ml_result: dict | None = None,
):
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
        (r'\b(within (?:\d+|one|two|three|four|five|six|seven|eight|nine|ten) hours?|'
         r'by (?:close of business|end of day|midnight)|final notice|legal action|'
         r'permanently (?:suspend|disable|close))\b',
         'Threat or deadline pressure', 12),
        (r'\b(do not tell|keep this confidential|do not discuss|bypass (?:the )?usual process)\b',
         'Secrecy or process-bypass instruction', 14),
        (r'\b(mfa|multi.factor|authenticator app|approve the sign.in|push notification)\b',
         'Possible authentication-prompt manipulation', 12),
        (r'\b(scan (?:the )?(?:qr|code)|qr code|quick response code)\b',
         'QR-code instruction may conceal a destination URL', 8),
        (r'\b(invoice attached|payment overdue|past.due invoice|refund available|'
         r'failed delivery|missed package|voicemail attached)\b',
         'Common delivery, invoice, or refund lure', 8),
    ]
    for pattern, label, points in checks:
        if re.search(pattern, lower):
            findings.append({'indicator': label, 'points': points})
            score += points
    
    raw_urls = re.findall(
        r'(?<![@\w])(?:https?://|www\.)[^\s<>\])\"\'\}]+'
        r'|(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
        r'(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?::\d+)?(?:/[^\s<>\])\"\'\}]*)?',
        content,
        flags=re.I,
    )
    urls = []
    for raw in raw_urls:
        cleaned = raw.rstrip('.,;:)]}')
        if cleaned in urls:
            continue
        urls.append(cleaned)
        try:
            parsed = urlparse(cleaned if re.match(r'^https?://', cleaned, re.I) else 'http://' + cleaned)
            host = (parsed.hostname or '').lower()
        except ValueError:
            findings.append({'indicator': f'Malformed URL could not be parsed: {cleaned}', 'points': 8})
            score += 8
            continue
        if host:
            try:
                ipaddress.ip_address(host)
                is_ip_address = True
            except ValueError:
                is_ip_address = False
            if is_ip_address:
                findings.append({'indicator': f'URL uses IP address (suspicious): {cleaned}', 'points': 18})
                score += 18
            if parsed.username or parsed.password:
                findings.append({'indicator': f'URL contains misleading embedded credentials: {cleaned}', 'points': 16})
                score += 16
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
        from email.utils import parseaddr

        display_name, address = parseaddr(sender)
        sender_domain = address.rsplit('@', 1)[-1].lower() if '@' in address else ''
        free_email_domains = {
            'gmail.com', 'googlemail.com', 'outlook.com', 'outlook.co.uk',
            'hotmail.com', 'hotmail.co.uk', 'yahoo.com', 'yahoo.co.uk',
            'aol.com', 'icloud.com', 'proton.me', 'protonmail.com',
        }
        if sender_domain in free_email_domains and re.search(
            r'\b(ceo|director|payroll|finance|bank|wire|transfer|urgent|confidential)\b', lower
        ):
            findings.append({'indicator': 'Free email provider used with business/financial urgency - high impersonation risk', 'points': 15})
            score += 15
        try:
            if display_name and sender_domain and re.search(
                r'\b(ceo|director|manager|lecturer|administrator|hr|payroll|finance|it support)\b',
                display_name,
                re.I,
            ):
                display_token = re.sub(r'[^a-z0-9]', '', display_name.lower())
                domain_token = re.sub(r'[^a-z0-9]', '', sender_domain.split('.')[0])
                if display_token and display_token not in domain_token:
                    findings.append({
                        'indicator': 'Display name claims an authority role but sender domain does not identify that role',
                        'points': 10,
                    })
                    score += 10
        except (TypeError, ValueError):
            findings.append({'indicator': 'Sender header could not be parsed reliably', 'points': 3})
            score += 3
    
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
    recommendations = [
        'Do not open links or attachments until you verify the request through a known, independent contact channel.',
        'Never provide passwords, one-time codes, or approve unexpected authentication prompts.',
    ]
    if urls:
        recommendations.append('Inspect each listed URL using your organization-approved security tools; this detector did not visit any URL.')
    if score >= 35:
        recommendations.append('Report this message to your institution’s IT/security team and follow its incident process.')
    if ml_result is not None:
        recommendations.append('Treat the experimental model estimate as supporting evidence only; the rule-based risk score remains separate.')
        if ml_result.get('input_characters_truncated') or ml_result.get('input_tokens_truncated'):
            recommendations.append(
                'The experimental classifier analyzed only a truncated portion of the email; rule-based checks scanned the complete supplied text.'
            )
    
    return {
        'module': 'Rule-based email screening with optional experimental ML',
        'risk_score': score,
        'risk_level': level,
        'findings': findings,
        'urls_found': urls,
        'model_status': (
            'Experimental local transformer classifier run'
            if ml_result is not None
            else 'Optional local transformer classifier not run; transparent rules active'
        ),
        'ml_classification': ml_result,
        'detection_methods': [
            'Urgency, threats, and deadline analysis',
            'Credential and MFA-prompt request detection',
            'Financial, delivery, QR-code, and secrecy lures',
            'URL/IP/punycode/embedded-credential analysis',
            'Sender display-name and free-provider heuristics',
        ],
        'limitations': 'Rules can miss sophisticated attacks and may flag legitimate messages. Always verify sender through official channels independently.',
        'recommendations': recommendations,
        'analysis_time_seconds': round(time.perf_counter() - start_time, 6)
    }


def media_metadata(
    data: bytes,
    filename: str,
    mime: str = '',
    *,
    run_ocr: bool = False,
    run_models: bool = False,
):
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
    extracted_text = ''
    qr_payloads = []
    try:
        if ext in ['.txt', '.eml']:
            sender = ''
            subject = ''
            if ext == '.eml':
                sender, subject, text = _extract_eml(data)
                info['email_sender'] = sender
                info['email_subject'] = subject
            else:
                text = data.decode('utf-8-sig', errors='replace')
            info['media_type'] = 'text'
            info['character_count'] = len(text)
            ml_result = None
            if run_models:
                try:
                    from utils.experimental_models import classify_email

                    tokenizer, model, torch = get_email_classifier()
                    ml_result = classify_email(text, tokenizer, model, torch)
                    info['experimental_phishing_classification'] = ml_result
                except Exception as model_error:
                    info['phishing_model_error'] = str(model_error)
            info['email_analysis'] = scan_email(text, sender, subject, ml_result)
            info['metadata_note'] = 'Text is analyzed using transparent rules and optional experimental local classification. No links are opened.'
        elif ext in ['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tif', '.tiff']:
            info['deepfake_classifier_status'] = 'not run'
            image = Image.open(io.BytesIO(data))
            info['media_type'] = 'image'
            info['image_format'] = image.format
            info['dimensions'] = f'{image.width} x {image.height}'
            info['mode'] = image.mode
            info['metadata_note'] = 'Image metadata and optional OCR/logo similarity are inspection signals; they do not establish authenticity.'
            try:
                logo_results = get_logo_detector().detect(data)
                logo_errors = [result for result in logo_results if 'error' in result]
                info['logo_detection'] = [result for result in logo_results if 'error' not in result]
                info['known_logo_count'] = len(get_logo_detector().logo_hashes)
                info['copied_logo_indicator'] = bool(info['logo_detection'])
                info['logo_detection_status'] = (
                    'error' if logo_errors else
                    'no known logo references configured' if not info['known_logo_count'] else
                    'similarity checked'
                )
                if logo_errors:
                    info['logo_detection_error'] = '; '.join(item['error'] for item in logo_errors)
            except Exception as logo_error:
                info['logo_detection_status'] = 'error'
                info['logo_detection_error'] = str(logo_error)

            try:
                from utils.experimental_models import decode_qr_codes

                qr_payloads = decode_qr_codes(image)
                info['qr_payloads'] = qr_payloads
            except Exception as qr_error:
                info['qr_detection_error'] = str(qr_error)

            if run_ocr:
                try:
                    from utils.experimental_models import extract_text_from_image

                    ocr_result = extract_text_from_image(image, get_ocr_engine())
                    info['ocr'] = ocr_result
                    info['ocr']['engine'] = 'RapidOCR using ONNX Runtime'
                    extracted_text = ocr_result['text']
                except Exception as ocr_error:
                    info['ocr_error'] = str(ocr_error)

            if run_models:
                try:
                    from utils.experimental_models import classify_images

                    processor, model, torch = get_image_classifier()
                    info['experimental_ai_classification'] = classify_images(
                        [image], processor, model, torch
                    )[0]
                    info['deepfake_classifier_status'] = 'completed'
                except Exception as model_error:
                    info['deepfake_model_error'] = str(model_error)
                    info['deepfake_classifier_status'] = 'error'
                
        elif ext in ['.wav', '.flac', '.ogg', '.aif', '.aiff', '.m4a']:
            info['deepfake_classifier_status'] = 'not run'
            import soundfile as sf

            info['media_type'] = 'audio'
            audio_data = data
            source_duration = None
            if ext == '.m4a':
                try:
                    from utils.experimental_models import decode_m4a_audio

                    audio_data, source_duration = decode_m4a_audio(data)
                except Exception as decode_error:
                    info['deepfake_classifier_status'] = 'error'
                    info['deepfake_model_error'] = f'M4A decoding failed: {decode_error}'
                    info['metadata_note'] = 'M4A audio could not be decoded for inspection.'
                    audio_data = None

            if audio_data is not None:
                audio_info = sf.info(io.BytesIO(audio_data))
                info['duration_seconds'] = round(
                    source_duration if source_duration is not None else audio_info.duration,
                    4,
                )
                info['sample_rate_hz'] = audio_info.samplerate
                info['channels'] = audio_info.channels
                info['audio_format'] = (
                    'M4A (decoded to WAV for inspection)' if ext == '.m4a' else audio_info.format
                )
                info['audio_subtype'] = audio_info.subtype
                info['metadata_note'] = (
                    'M4A audio is decoded locally to mono 16 kHz PCM for inspection. '
                    'The experimental classifier analyzes at most 20 seconds; metadata and model '
                    'estimates do not establish authenticity.'
                    if ext == '.m4a' else
                    'Audio metadata does not establish authenticity. The optional experimental classifier '
                    'analyzes at most 20 seconds and is not a validated forensic verdict.'
                )
            if run_models and audio_data is not None:
                try:
                    from utils.experimental_models import classify_audio

                    processor, model, torch = get_audio_classifier()
                    classification = classify_audio(audio_data, processor, model, torch)
                    if source_duration is not None:
                        classification['duration_omitted_seconds'] = round(
                            max(0, source_duration - classification['duration_analyzed_seconds']),
                            3,
                        )
                    info['experimental_ai_classification'] = classification
                    info['deepfake_classifier_status'] = 'completed'
                except Exception as model_error:
                    info['deepfake_model_error'] = str(model_error)
                    info['deepfake_classifier_status'] = 'error'
        elif ext in ['.mp4', '.mov', '.avi', '.mkv', '.webm']:
            info['deepfake_classifier_status'] = 'not run'
            info['media_type'] = 'video'
            info['metadata_note'] = 'Video analysis samples frames; it does not evaluate temporal consistency and is not a validated video-forensics verdict.'
            try:
                from utils.experimental_models import extract_video_frames

                frames, video_metadata = extract_video_frames(data, ext)
                info.update(video_metadata)
                info['sampled_frame_count'] = len(frames)
            except Exception as video_error:
                info['video_inspection_error'] = str(video_error)
                frames = []
            if frames and run_ocr:
                try:
                    from utils.experimental_models import extract_text_from_image

                    ocr_engine = get_ocr_engine()
                    ocr_results = [
                        extract_text_from_image(frame, ocr_engine)
                        for frame in frames
                    ]
                    extracted_text = '\n'.join(
                        result['text'] for result in ocr_results if result['text']
                    )
                    info['ocr'] = {
                        'text': extracted_text,
                        'engine': 'RapidOCR using ONNX Runtime',
                        'sampled_frame_detections': ocr_results,
                    }
                except Exception as ocr_error:
                    info['ocr_error'] = str(ocr_error)
            if frames:
                try:
                    from utils.experimental_models import decode_qr_codes

                    for frame in frames:
                        qr_payloads.extend(decode_qr_codes(frame))
                    qr_payloads = list(dict.fromkeys(qr_payloads))
                    info['qr_payloads'] = qr_payloads
                except Exception as qr_error:
                    info['qr_detection_error'] = str(qr_error)
            if frames and run_models:
                try:
                    from utils.experimental_models import classify_images

                    processor, model, torch = get_image_classifier()
                    frame_results = classify_images(frames, processor, model, torch)
                    if frame_results:
                        info['experimental_frame_classification'] = {
                            'model': frame_results[0]['model'],
                            'model_revision': frame_results[0]['model_revision'],
                            'sample_count': len(frame_results),
                            'mean_fake_probability': round(
                                sum(item['fake_probability'] for item in frame_results) / len(frame_results),
                                6,
                            ),
                            'frame_results': frame_results,
                            'limitations': (
                                'Image model applied independently to sampled frames; this is not temporal video analysis. '
                                + frame_results[0]['limitations']
                            ),
                        }
                        info['deepfake_classifier_status'] = 'completed'
                except Exception as model_error:
                    info['deepfake_model_error'] = str(model_error)
                    info['deepfake_classifier_status'] = 'error'
        else:
            info['media_type'] = 'other'
            info['metadata_note'] = f'File type {ext} not in supported categories for detailed inspection.'
    except Exception as exc:
        info['inspection_error'] = str(exc)
        info['metadata_note'] = 'File could not be parsed by available inspectors.'
    
    if extracted_text:
        info['ocr_email_analysis'] = scan_email(extracted_text)
        info['ocr_email_analysis']['recommendations'].append(
            'OCR can misread text or miss content; manually review the original image/video as well.'
        )
    if qr_payloads:
        info['qr_email_analysis'] = scan_email('\n'.join(qr_payloads))
        info['qr_email_analysis']['recommendations'].append(
            'QR contents are decoded for inspection only; the detector did not open or follow them.'
        )
    info['deepfake_result'] = (
        'EXPERIMENTAL MODEL ESTIMATE - Not an authenticity verdict'
        if info.get('experimental_ai_classification') or info.get('experimental_frame_classification')
        else 'NOT DETERMINED - Experimental model inference was not run or is unavailable'
    )
    info['ai_detection_status'] = (
        'Experimental local model was run; independent validation is not established'
        if info.get('experimental_ai_classification') or info.get('experimental_frame_classification')
        else 'Model inference not run'
    )
    info['warning'] = (
        'Model scores are estimates, not proof. A low score does not prove the media is authentic, '
        'and a high score does not prove it is manipulated.'
    )
    info['sha256_after'] = sha256_bytes(data)
    info['integrity_verified'] = info['sha256_before'] == info['sha256_after']
    info['recommendations'] = [
        'Verify the sender and context through an independent, trusted channel before acting.',
        'Do not treat metadata, logo similarity, OCR, or experimental model scores as proof of authenticity.',
    ]
    if info.get('ocr_email_analysis', {}).get('risk_score', 0) >= 35:
        info['recommendations'].append(
            'OCR found suspicious email wording; inspect the message and any destination using approved security tools.'
        )
    if info.get('qr_email_analysis', {}).get('risk_score', 0) >= 35:
        info['recommendations'].append(
            'A decoded QR payload contains suspicious indicators; do not open it and report it through approved channels.'
        )
    if info.get('integrity_verified'):
        info['recommendations'].append(
            'Preserve the original file and its SHA-256 hash if incident response or formal evidence handling is needed.'
        )
    info['analysis_time_seconds'] = round(time.perf_counter() - start_time, 6)
    return info

def render_report(report):
    return json.dumps(report, indent=2, ensure_ascii=False)

def clear_media_report():
    st.session_state.pop('media_report', None)
    st.session_state.pop('run_media_models', None)
    st.session_state.pop('run_image_classifier', None)
    st.session_state.pop('run_video_classifier', None)
    st.session_state.pop('run_other_media_classifier', None)


def should_run_media_classifier_by_default(filename: str) -> bool:
    extension = os.path.splitext(filename)[1].lower()
    return extension in {
        '.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tif', '.tiff',
        '.mp4', '.mov', '.avi', '.mkv', '.webm',
        '.wav', '.flac', '.ogg', '.aif', '.aiff', '.m4a',
    }


def render_integrity_status(integrity_verified: bool) -> None:
    if integrity_verified:
        st.success('SHA-256 is unchanged after analysis; uploaded bytes were not modified.')
    else:
        st.error('Integrity verification failed: before/after SHA-256 values differ.')


def run_app():
    st.set_page_config(page_title='AI Phishing & Deepfake Detector', page_icon='🔍', layout='wide')
    st.title('AI Phishing & Deepfake Detector')
    st.caption('Email screening, media inspection, integrity checks, and downloadable reports')
    st.warning(
        'Local OCR and experimental classifiers are available. Image, video, and audio classifiers run by default '
        'for matching uploads; model weights download on first use. '
        'Their reported scores have not been independently validated for this application and cannot establish '
        'authenticity. Rule-based findings and model estimates are reported separately.'
    )

    email_tab, media_tab = st.tabs(['Email analysis', 'Media inspection'])

    with email_tab:
        st.subheader('Screen email text')
        sender = st.text_input('Sender address (optional)', key='email_sender')
        subject = st.text_input('Subject (optional)', key='email_subject')
        email_text = st.text_area('Paste email text', height=220, key='email_body')
        run_email_model = st.checkbox(
            'Run experimental local email classifier (downloads about 270 MB on first use)',
            key='run_email_model',
        )
        if st.button('Analyze email', type='primary'):
            if not email_text.strip() and not subject.strip():
                st.error('Enter an email subject or message before analysis.')
            else:
                processing_start = time.perf_counter()
                ml_result = None
                ml_error = None
                if run_email_model:
                    try:
                        with st.spinner('Loading local email classifier and analyzing message...'):
                            from utils.experimental_models import classify_email

                            tokenizer, model, torch = get_email_classifier()
                            ml_result = classify_email(
                                f'{subject}\n{sender}\n{email_text}', tokenizer, model, torch
                            )
                    except Exception as model_error:
                        ml_error = str(model_error)
                analysis = scan_email(email_text, sender, subject, ml_result)
                email_report = {
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'sender': sender,
                    'subject': subject,
                    'analysis': analysis,
                    'ml_model_error': ml_error,
                }
                report_start = time.perf_counter()
                render_report(email_report)
                report_generation_time = time.perf_counter() - report_start
                email_report['analysis_wall_time_seconds'] = round(
                    time.perf_counter() - processing_start, 6
                )
                email_report['report_generation_time_seconds'] = round(
                    report_generation_time, 6
                )
                email_report['total_processing_time_seconds'] = round(
                    email_report['analysis_wall_time_seconds'] + report_generation_time, 6
                )
                st.session_state.email_report = email_report

        email_report = st.session_state.get('email_report')
        if email_report:
            analysis = email_report['analysis']
            st.metric('Risk score', f"{analysis['risk_score']} / 100", analysis['risk_level'])
            if email_report.get('ml_model_error'):
                st.error(f"Optional classifier could not run: {email_report['ml_model_error']}")
            elif analysis.get('ml_classification'):
                ml = analysis['ml_classification']
                st.metric(
                    'Experimental model estimate',
                    ml['model_estimate'],
                    f"{ml['phishing_probability']:.1%} phishing-like probability",
                )
                st.caption(ml['limitations'])
            st.subheader('Findings')
            for finding in analysis['findings']:
                st.text(f"{finding['indicator']} (+{finding['points']})")
            st.caption('Extracted URLs are listed only; the detector never opens them.')
            if analysis['urls_found']:
                for url in analysis['urls_found']:
                    st.code(url, language=None)
            st.caption(analysis['limitations'])
            st.subheader('Recommendations')
            for recommendation in analysis.get('recommendations', []):
                st.markdown(f'- {recommendation}')
            st.download_button(
                'Download email report (JSON)',
                data=render_report(email_report),
                file_name='email_analysis_report.json',
                mime='application/json'
            )

    with media_tab:
        st.subheader('Inspect a media or email file')
        uploaded_file = st.file_uploader(
            'Supported: TXT/EML, common images, WAV/FLAC/OGG/AIFF/M4A audio, and common video formats',
            type=['txt', 'eml', 'jpg', 'jpeg', 'png', 'webp', 'bmp', 'tif', 'tiff',
                  'wav', 'flac', 'ogg', 'aif', 'aiff', 'm4a', 'mp4', 'mov', 'avi', 'mkv', 'webm'],
            key='media_file',
            on_change=clear_media_report
        )
        run_ocr = st.checkbox(
            'Extract text from image/video frames and screen it for phishing (downloads OCR weights on first use)',
            value=True,
            key='run_media_ocr',
        )
        if uploaded_file is not None:
            extension = os.path.splitext(uploaded_file.name)[1].lower()
            is_image = extension in {
                '.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tif', '.tiff',
            }
            is_video = extension in {'.mp4', '.mov', '.avi', '.mkv', '.webm'}
            is_audio = extension in {'.wav', '.flac', '.ogg', '.aif', '.aiff', '.m4a'}
            is_visual_media = is_image or is_video
            model_label = (
                'Run experimental deepfake image classifier (downloads about 355 MiB on first use)'
                if is_image else
                'Run experimental deepfake video classifier on sampled frames (downloads about 355 MiB on first use)'
                if is_video else
                'Run experimental deepfake audio classifier (downloads about 360 MiB on first use)'
                if is_audio
                else 'Run experimental local classifier (downloads model weights on first use)'
            )
            model_key = (
                'run_image_classifier' if is_image else
                'run_video_classifier' if is_video else
                'run_other_media_classifier'
            )
            run_media_models = st.checkbox(
                model_label,
                value=should_run_media_classifier_by_default(uploaded_file.name),
                key=model_key,
            )
            if is_visual_media:
                st.caption(
                    'This experimental classifier estimates synthetic-like imagery; it cannot prove authenticity. '
                    'The first run downloads about 355 MiB and requires internet access.'
                )
            elif is_audio:
                st.caption(
                    'This experimental Wav2Vec2 classifier estimates AI-generated versus human speech. '
                    'It analyzes at most the first 20 seconds. The first model load downloads about 360 MiB '
                    'and may take a few minutes on CPU; it cannot prove authenticity.'
                )
        else:
            run_media_models = False
        if st.button('Inspect file', type='primary', disabled=uploaded_file is None):
            if uploaded_file is not None:
                data = uploaded_file.getvalue()
                if run_media_models:
                    with st.spinner('Loading the local classifier and analyzing this file...'):
                        media_report = media_metadata(
                            data,
                            uploaded_file.name,
                            uploaded_file.type or '',
                            run_ocr=run_ocr,
                            run_models=True,
                        )
                else:
                    media_report = media_metadata(
                        data,
                        uploaded_file.name,
                        uploaded_file.type or '',
                        run_ocr=run_ocr,
                        run_models=False,
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
            for error_key, title in (
                ('ocr_error', 'OCR could not run'),
                ('deepfake_model_error', 'Experimental media model could not run'),
                ('phishing_model_error', 'Experimental email model could not run'),
                ('qr_detection_error', 'QR code detection could not run'),
                ('video_inspection_error', 'Video could not be inspected'),
            ):
                if media_report.get(error_key):
                    st.error(f"{title}: {media_report[error_key]}")
            if media_report.get('qr_payloads'):
                st.subheader('Decoded QR payloads (not opened)')
                for payload in media_report['qr_payloads']:
                    st.code(payload, language=None)
            if media_report.get('ocr', {}).get('text'):
                st.subheader('Text found by OCR')
                st.text(media_report['ocr']['text'])
            for analysis_key, heading, metric_label in (
                ('email_analysis', 'Email screening', 'Email rule score'),
                ('ocr_email_analysis', 'OCR phishing screening', 'OCR text rule score'),
                ('qr_email_analysis', 'QR payload screening', 'QR payload rule score'),
            ):
                email_analysis = media_report.get(analysis_key, {})
                if email_analysis:
                    st.subheader(heading)
                    st.metric(
                        metric_label,
                        f"{email_analysis['risk_score']} / 100",
                        email_analysis['risk_level'],
                    )
                    for finding in email_analysis['findings']:
                        st.text(f"{finding['indicator']} (+{finding['points']})")
                    if email_analysis['urls_found']:
                        st.caption('URLs extracted from the message are listed only and are never opened.')
                        for url in email_analysis['urls_found']:
                            st.code(url, language=None)
                    for recommendation in email_analysis.get('recommendations', []):
                        st.markdown(f'- {recommendation}')
            if media_report.get('experimental_ai_classification'):
                classification = media_report['experimental_ai_classification']
                probability = classification.get(
                    'fake_probability',
                    classification.get('phishing_probability'),
                )
                if probability is not None:
                    st.metric(
                        'Experimental model score',
                        classification['model_estimate'],
                        f"{probability:.1%} model score",
                    )
                    st.caption(classification['limitations'])
            if media_report.get('experimental_phishing_classification'):
                classification = media_report['experimental_phishing_classification']
                st.metric(
                    'Experimental email model estimate',
                    classification['model_estimate'],
                    f"{classification['phishing_probability']:.1%} phishing-like probability",
                )
                st.caption(classification['limitations'])
            if media_report.get('experimental_frame_classification'):
                classification = media_report['experimental_frame_classification']
                st.metric(
                    'Experimental sampled-frame score',
                    f"{classification['mean_fake_probability']:.1%} synthetic-like",
                    f"{classification['sample_count']} frames sampled",
                )
                st.caption(classification['limitations'])
            if media_report.get('logo_detection_status'):
                st.caption(
                    f"Logo similarity: {media_report['logo_detection_status']} "
                    f"({media_report.get('known_logo_count', 0)} reference logos)"
                )
            if media_report.get('media_type') == 'image':
                if media_report.get('experimental_ai_classification'):
                    st.success('Experimental AI image classification completed.')
                elif media_report.get('deepfake_model_error'):
                    st.error(
                        'AI image classification failed; no synthetic-media estimate is available. '
                        'See the model error above and retry after checking network access/model setup.'
                    )
                else:
                    st.warning(
                        'No AI deepfake estimate was produced. Enable the experimental image classifier '
                        'before inspecting the file.'
                    )
                if media_report.get('logo_detection_status') == 'no known logo references configured':
                    st.info('Copied-logo matching is inactive because no reference logos are configured.')
            elif media_report.get('media_type') == 'audio':
                if media_report.get('experimental_ai_classification'):
                    st.success('Experimental AI audio classification completed.')
                elif media_report.get('deepfake_model_error'):
                    st.error(
                        'AI audio classification failed; no synthetic-audio estimate is available. '
                        'See the model error above and check network access/model setup.'
                    )
                else:
                    st.warning(
                        'No AI audio estimate was produced. Enable the experimental audio classifier '
                        'before inspecting the file.'
                    )
            render_integrity_status(media_report.get('integrity_verified', False))
            st.subheader('Recommendations')
            for recommendation in media_report.get('recommendations', []):
                st.markdown(f'- {recommendation}')
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
