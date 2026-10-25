# Benchmark Script
# Measures max file size and average processing time per media type

import io
import time
import os
import json
import tempfile
import wave
from datetime import datetime, timezone
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

try:
    from app import scan_email, media_metadata, sha256_bytes
except Exception as e:
    print(f'Import error: {e}')
    sys.exit(1)

class Benchmark:
    def __init__(self):
        self.results = {
            'benchmark_info': {
                'date': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'tool': 'AI Phishing & Deepfake Detector',
                'version': '1.0-prototype'
            },
            'email_tests': [],
            'media_tests': [],
            'capacity_tests': []
        }
    
    def test_email(self, text, iterations=5):
        times = []
        for i in range(iterations):
            start = time.perf_counter()
            result = scan_email(text)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        return {
            'iterations': iterations,
            'avg_time_s': round(sum(times)/len(times), 6),
            'min_time_s': round(min(times), 6),
            'max_time_s': round(max(times), 6),
            'risk_score': result['risk_score']
        }
    
    def test_media(self, data, filename, mime=''):
        times = []
        iterations = 3
        for i in range(iterations):
            start = time.perf_counter()
            result = media_metadata(data, filename, mime)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        return {
            'filename': filename,
            'size_bytes': len(data),
            'size_mib': round(len(data)/(1024*1024), 4),
            'iterations': iterations,
            'avg_time_s': round(sum(times)/len(times), 6),
            'min_time_s': round(min(times), 6),
            'max_time_s': round(max(times), 6),
            'media_type': result.get('media_type'),
            'sha256': result.get('sha256_before'),
            'integrity_verified': result.get('integrity_verified'),
            'inspection_error': result.get('inspection_error')
        }

    def test_capacity(self, data, filename, mime=''):
        result = media_metadata(data, filename, mime)
        self.results['capacity_tests'].append({
            'filename': filename,
            'size_bytes': len(data),
            'size_mib': round(len(data) / (1024 * 1024), 4),
            'media_type': result.get('media_type'),
            'processed_without_error': not result.get('inspection_error'),
            'integrity_verified': result.get('integrity_verified')
        })

    @staticmethod
    def make_wav_sample(target_mib):
        target_bytes = target_mib * 1024 * 1024
        sample_bytes = target_bytes - 44
        sample_bytes -= sample_bytes % 2
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(8000)
            wav.writeframes(b'\x00\x00' * (sample_bytes // 2))
        return buffer.getvalue()

    @staticmethod
    def make_png_sample(target_mib):
        from PIL import Image
        import numpy as np

        target_bytes = target_mib * 1024 * 1024
        rng = np.random.default_rng(2026)
        side = 512
        while side <= 4096:
            pixels = rng.integers(0, 256, (side, side, 3), dtype=np.uint8)
            buffer = io.BytesIO()
            Image.fromarray(pixels).save(buffer, format='PNG', compress_level=0)
            image_data = buffer.getvalue()
            if len(image_data) >= target_bytes:
                return image_data
            side = int(side * 1.4)
        raise RuntimeError(f'Could not generate a {target_mib} MiB PNG sample.')

    @staticmethod
    def make_video_sample(target_mib):
        import cv2
        import numpy as np

        target_bytes = target_mib * 1024 * 1024
        with tempfile.NamedTemporaryFile(suffix='.avi', delete=False) as temp:
            video_path = temp.name

        writer = None
        try:
            writer = cv2.VideoWriter(
                video_path,
                cv2.VideoWriter_fourcc(*'MJPG'),
                10,
                (320, 240)
            )
            if not writer.isOpened():
                raise RuntimeError('OpenCV could not create the MJPG benchmark video.')

            rng = np.random.default_rng(2026)
            for frame_number in range(500):
                frame = rng.integers(0, 256, (240, 320, 3), dtype=np.uint8)
                writer.write(frame)
                if frame_number % 10 == 9 and os.path.getsize(video_path) >= target_bytes:
                    break
            writer.release()
            writer = None

            with open(video_path, 'rb') as video_file:
                video_data = video_file.read()
            if len(video_data) < target_bytes:
                raise RuntimeError(
                    f'Generated video was only {len(video_data)} bytes; '
                    f'{target_bytes} bytes were requested.'
                )
            return video_data
        finally:
            if writer is not None:
                writer.release()
            try:
                os.unlink(video_path)
            except OSError:
                pass
    
    def run(self):
        print('Running benchmarks...')
        # Email tests
        sample_email = '''Subject: Urgent - Verify Your Account
From: security@suspicious-domain.com
Your account will be suspended. Click here to verify your password immediately.
'''
        self.results['email_tests'].append(self.test_email(sample_email))
        
        benign_email = 'Hi, just wanted to confirm our meeting tomorrow at 2 PM.'
        self.results['email_tests'].append(self.test_email(benign_email))
        
        # Try to test any sample files
        test_dir = os.path.join(PROJECT_ROOT, 'tests', 'sample_files')
        if os.path.exists(test_dir):
            for fname in os.listdir(test_dir):
                fpath = os.path.join(test_dir, fname)
                if os.path.isfile(fpath):
                    try:
                        with open(fpath, 'rb') as f:
                            data = f.read()
                        mime = None
                        result = self.test_media(data, fname, mime)
                        self.results['media_tests'].append(result)
                        print(f'Tested {fname}: {result["avg_time_s"]}s')
                    except Exception as e:
                        print(f'Error testing {fname}: {e}')

        image_sample = self.make_png_sample(1)
        image_result = self.test_media(image_sample, 'benchmark.png', 'image/png')
        self.results['media_tests'].append(image_result)
        print(f'Tested benchmark.png: {image_result["avg_time_s"]}s')
        self.test_capacity(image_sample, 'capacity.png', 'image/png')

        wav_sample = self.make_wav_sample(1)
        wav_result = self.test_media(wav_sample, 'benchmark.wav', 'audio/wav')
        self.results['media_tests'].append(wav_result)
        print(f'Tested benchmark.wav: {wav_result["avg_time_s"]}s')
        self.test_capacity(self.make_wav_sample(5), 'capacity.wav', 'audio/wav')

        try:
            video_sample = self.make_video_sample(1)
            video_result = self.test_media(video_sample, 'benchmark.avi', 'video/x-msvideo')
            self.results['media_tests'].append(video_result)
            print(f'Tested benchmark.avi: {video_result["avg_time_s"]}s')
            self.test_capacity(self.make_video_sample(5), 'capacity.avi', 'video/x-msvideo')
        except (ImportError, RuntimeError) as e:
            self.results['capacity_tests'].append({
                'filename': 'benchmark.avi',
                'processed_without_error': False,
                'note': str(e)
            })
            print(f'Skipped video benchmark: {e}')
        
        # Save results
        outpath = os.path.join(PROJECT_ROOT, 'benchmark_results.json')
        with open(outpath, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f'Results saved to {outpath}')
        print(json.dumps(self.results, indent=2))

if __name__ == '__main__':
    b = Benchmark()
    b.run()
