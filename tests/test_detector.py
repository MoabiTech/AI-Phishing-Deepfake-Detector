import io
import json
import unittest
import wave
from pathlib import Path

from PIL import Image
from streamlit.testing.v1 import AppTest

from app import media_metadata, render_report, scan_email, sha256_bytes


class EmailAnalysisTests(unittest.TestCase):
    def test_flags_phishing_indicators_without_opening_links(self):
        result = scan_email(
            'Urgent: verify your password now at http://192.0.2.1/account'
        )

        self.assertGreaterEqual(result['risk_score'], 35)
        self.assertTrue(result['urls_found'])
        self.assertTrue(any('IP address' in item['indicator'] for item in result['findings']))
        self.assertIn('verify sender', result['limitations'].lower())

    def test_benign_message_is_not_declared_safe(self):
        result = scan_email('Hi, confirming our meeting tomorrow at 2 PM.')

        self.assertEqual(result['risk_score'], 0)
        self.assertIn('does not prove', result['findings'][0]['indicator'].lower())

    def test_malformed_url_does_not_crash_analysis(self):
        result = scan_email('Please review http://[invalid')

        self.assertTrue(any('Malformed URL' in item['indicator'] for item in result['findings']))


class MediaInspectionTests(unittest.TestCase):
    def test_text_file_runs_email_rules_and_preserves_bytes(self):
        original = b'Subject: Urgent account suspended. Verify your password.'
        report = media_metadata(original, 'message.eml')

        self.assertEqual(report['media_type'], 'text')
        self.assertGreater(report['email_analysis']['risk_score'], 0)
        self.assertEqual(report['sha256_before'], sha256_bytes(original))
        self.assertEqual(report['sha256_before'], report['sha256_after'])
        self.assertTrue(report['integrity_verified'])

    def test_image_metadata_and_hash_are_reported(self):
        buffer = io.BytesIO()
        Image.new('RGB', (12, 8), color='white').save(buffer, format='PNG')
        original = buffer.getvalue()

        report = media_metadata(original, 'sample.png', 'image/png')

        self.assertEqual(report['media_type'], 'image')
        self.assertEqual(report['dimensions'], '12 x 8')
        self.assertTrue(report['integrity_verified'])
        self.assertEqual(report['sha256_before'], report['sha256_after'])

    def test_wav_metadata_is_reported(self):
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(8000)
            wav.writeframes(b'\x00\x00' * 8000)

        report = media_metadata(buffer.getvalue(), 'sample.wav', 'audio/wav')

        self.assertEqual(report['media_type'], 'audio')
        self.assertEqual(report['duration_seconds'], 1.0)
        self.assertEqual(report['sample_rate_hz'], 8000)
        self.assertEqual(report['deepfake_result'], 'NOT DETERMINED - No validated deepfake detection model configured')

    def test_json_report_is_valid(self):
        report = media_metadata(b'ordinary text', 'message.txt')

        self.assertEqual(json.loads(render_report(report))['filename'], 'message.txt')


class StreamlitUiTests(unittest.TestCase):
    def test_email_screening_renders_a_report(self):
        app_path = Path(__file__).resolve().parents[1] / 'app.py'
        app = AppTest.from_file(str(app_path), default_timeout=30).run()
        self.assertFalse(app.exception)

        app.text_area(key='email_body').set_value(
            'Urgent: verify your password immediately at http://192.0.2.1/login'
        ).run()
        app.button[0].click().run()

        self.assertFalse(app.exception)
        self.assertEqual(app.metric[0].value, '53 / 100')
        self.assertEqual(len(app.download_button), 1)


if __name__ == '__main__':
    unittest.main()
