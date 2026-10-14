"""Synthetic-only API smoke test with isolated storage."""
import hashlib
import os
import tempfile

def main():
    with tempfile.TemporaryDirectory() as temporary:
        os.environ['AUDIT_DIR'] = temporary
        from fastapi.testclient import TestClient
        from app import app
        with TestClient(app) as client:
            assert client.get('/').status_code == 200
            data = b'Synthetic metadata laboratory test input\n'
            response = client.post('/api/file-large', files={'file': ('synthetic.txt', data, 'text/plain')})
            assert response.status_code == 200, response.text
            record = response.json()
            assert record['sha256'] == hashlib.sha256(data).hexdigest()
            assert record['sha512'] == hashlib.sha512(data).hexdigest()
            assert client.get('/api/evidence/' + record['evidence_id']).status_code == 200
            chain = client.get('/api/forensic/custody/verify').json()
            assert chain['valid'] and chain['event_count'] >= 1, chain
        print('Synthetic dashboard, ingestion, hashes, lookup and custody checks passed.')

if __name__ == '__main__':
    main()
