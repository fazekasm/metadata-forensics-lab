"""Desktop entry point: local-only API and native webview."""
import os
import pathlib
import socket
import threading
import time
import sys


def free_local_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    if sys.platform == 'darwin':
        home = pathlib.Path.home() / 'Library' / 'Application Support' / 'Metadata Forensics Lab'
    elif sys.platform == 'win32':
        home = pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home() / 'AppData' / 'Local')) / 'Metadata Forensics Lab'
    else:
        home = pathlib.Path(os.environ.get('XDG_DATA_HOME', pathlib.Path.home() / '.local' / 'share')) / 'metadata-forensics-lab'
    home.mkdir(parents=True, exist_ok=True)
    os.environ['AUDIT_DIR'] = str(home / 'evidence')
    os.environ.setdefault('MAX_UPLOAD_BYTES', str(2 * 1024**3))
    # Import only after AUDIT_DIR is set: app initializes storage on import.
    from app import app
    import uvicorn
    import webview
    port = free_local_port()
    config = uvicorn.Config(app, host='127.0.0.1', port=port, log_level='warning', access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(.1)
    if not server.started:
        raise RuntimeError('Local forensic service failed to start')
    try:
        webview.create_window('Metadata Forensics Laboratory', f'http://127.0.0.1:{port}', width=1380, height=900, min_size=(850, 600))
        webview.start(gui={'darwin': 'cocoa', 'win32': 'edgechromium'}.get(sys.platform, 'qt'), debug=False)
    finally:
        server.should_exit = True
        thread.join(timeout=8)

if __name__ == '__main__':
    main()
