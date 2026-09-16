import os
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
os.environ['MAILSENTINEL_DATA_DIR'] = 'test-data'
os.environ['DATABASE_URL'] = 'test-data/test.json'
os.environ['MAILSENTINEL_SQLITE_PATH'] = 'test-data/inbox_threats.db'
os.environ.pop('OPENROUTER_API_KEY', None)
os.environ.pop('VT_API_KEY', None)
from fastapi.testclient import TestClient
from backend.app import app, DB_PATH

RAW = b'''From: sender@example.com\nTo: receiver@example.com\nSubject: Hello\nMessage-ID: <one@example.com>\nReceived: from mx (8.8.8.8)\nAuthentication-Results: mx; dmarc=pass\n\nVisit https://example.com\n'''

MOCK_GEO = {"ip": "8.8.8.8", "city": "Mountain View", "country": "US", "org": "AS15169 Google LLC", "lat": 37.4056, "lon": -122.0775}

def _offline_monkeypatches(monkeypatch, tmp_path):
    monkeypatch.setattr('backend.app.DB_PATH', tmp_path / 'db.json')
    monkeypatch.setattr('backend.app.SQLITE_PATH', str(tmp_path / 'inbox_threats.db'))
    monkeypatch.setattr('backend.forensics.analyze_with_agent',
                        lambda extracted: {"run": False, "reason": "offline test, agent skipped"})
    monkeypatch.setattr('backend.forensics.ip_lookup_tool_instance.lookup', lambda ip: MOCK_GEO)
    monkeypatch.setattr('backend.forensics.url_checker_tool_instance.check_url',
                        lambda url: {"url": url, "verdict": "SAFE_OR_UNKNOWN", "details": "Check skipped in tests"})
    monkeypatch.setattr('backend.forensics.hash_checker_tool_instance.check_hash',
                        lambda h: {"hash": h, "verdict": "UNKNOWN", "details": "Check skipped in tests"})

def _wait_completed(client, analysis_id, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        item = client.get(f'/api/analyses/{analysis_id}').json()
        if item['status'] in ('completed', 'failed'):
            return item
        time.sleep(0.05)
    return item

def test_upload_and_persistence(tmp_path, monkeypatch):
    _offline_monkeypatches(monkeypatch, tmp_path)
    with TestClient(app) as client:
        response = client.post('/api/analyses', files={'file': ('mail.eml', RAW, 'message/rfc822')})
        assert response.status_code == 202
        result = _wait_completed(client, response.json()['analysis_id'])
        assert result['status'] == 'completed'
        assert result['verdict'] == 'INCONCLUSIVE'
        assert result['extraction']['urls'] == ['https://example.com']
        assert result['provider_results']['locations'][0]['city'] == 'Mountain View'
        assert result['agent']['run'] is False
        assert client.get('/api/analyses/does-not-exist').status_code == 404

def test_upload_validation():
    with TestClient(app) as client:
        assert client.post('/api/analyses', files={'file': ('note.txt', b'x', 'text/plain')}).status_code == 422

def test_timeline_endpoint(tmp_path, monkeypatch):
    _offline_monkeypatches(monkeypatch, tmp_path)
    with TestClient(app) as client:
        resp = client.post('/api/analyses', files={'file': ('mail.eml', RAW, 'message/rfc822')})
        _wait_completed(client, resp.json()['analysis_id'])
        tl = client.get('/api/dashboard/timeline').json()
        assert 'html' in tl
        assert tl['html'] is None or 'plotly' in tl['html'].lower()