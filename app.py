import hashlib, io, json, os, ipaddress, socket, uuid, time, asyncio, pathlib, sqlite3, tempfile, shutil
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
import fitz, httpx

app = FastAPI(title='Metadata Verification Laboratory', docs_url=None, redoc_url=None)
MAX_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 2 * 1024 * 1024 * 1024))
MAX_BATCH_FILES = 25
AUDIT_DIR = pathlib.Path(os.environ.get("AUDIT_DIR", "./audit"))
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_LOG = AUDIT_DIR / "acquisitions.jsonl"

def stamp(): return datetime.now(timezone.utc).isoformat()
def write_audit(record):
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


HTML = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Metadata Verification Laboratory</title><style>
:root{font-family:system-ui,Arial;color:#e8eef8;background:#0b1220}body{max-width:1050px;margin:35px auto;padding:0 20px}h1{margin-bottom:4px}.sub{color:#9daec6}.panel{background:#152238;border:1px solid #30425d;border-radius:14px;padding:22px;margin:20px 0}button,input{font:inherit}input[type=url],input[type=file]{width:100%;box-sizing:border-box;padding:12px;border-radius:8px;background:#0c1729;color:white;border:1px solid #53647d;margin:12px 0}button{background:#4d85ed;color:white;border:0;border-radius:8px;padding:11px 17px;cursor:pointer;margin-right:8px}button:hover{background:#366cd0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#091323;padding:18px;border-radius:10px;max-height:560px;overflow:auto}.note{font-size:14px;color:#aebed3}.tag{display:inline-block;background:#273d5c;border-radius:5px;padding:4px 8px;font-size:12px}#results{display:none}</style></head><body>
<div class="tag">LOCAL + FLY.IO READY</div><h1>Metadata Verification Laboratory</h1><p class="sub">Document integrity • PDF metadata • HTTP evidence • Investigative reporting</p>
<section class="panel"><h2>1. Inspect PDF</h2><p class="note">Files are processed in memory and not intentionally retained on disk. Maximum 20 MB.</p><input type="file" id="file" accept="application/pdf,.pdf"><button onclick="inspect()">Analyze PDF</button></section>
<section class="panel"><h2>2. Inspect public URL</h2><p class="note">Checks public HTTPS websites only; headers do not conclusively establish the original upload date.</p><input type="url" id="url" placeholder="https://example.org/document.pdf"><button onclick="inspectUrl()">Inspect HTTP Headers</button><button onclick="acquireUrl()">Acquire Document + Audit</button><p class="note">Acquisition downloads up to 20 MB, records network and timing evidence, and saves the source bytes to the local audit directory. Do not expose this endpoint publicly without access controls.</p></section>
<section class="panel" id="results"><h2>Analysis result</h2><button onclick="download('json')">Download JSON</button><button onclick="download('txt')">Download Plain-English Report</button><pre id="output"></pre></section>
<p class="note">Forensic caution: PDF CreationDate, ModDate, Last-Modified and ETag may be altered by editing, copying, caching or server configuration. Preserve source files and independent acquisition records.</p>
<script>let current=null;function show(x){current=x;document.getElementById('results').style.display='block';document.getElementById('output').textContent=JSON.stringify(x,null,2)}async function inspect(){const f=document.getElementById('file').files[0];if(!f)return alert('Select a PDF first');const fd=new FormData();fd.append('file',f);await request('/api/pdf',{method:'POST',body:fd})}async function inspectUrl(){const u=document.getElementById('url').value;await request('/api/url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})})}async function acquireUrl(){const u=document.getElementById('url').value;await request('/api/acquire',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})})}async function request(path,opts){try{let r=await fetch(path,opts);let d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');show(d)}catch(e){alert(e.message)}}function download(type){if(!current)return;const s=type==='json'?JSON.stringify(current,null,2):'METADATA VERIFICATION LABORATORY\\n\\n'+(current.summary||'Analysis results')+'\\n\\nTECHNICAL FINDINGS\\n'+JSON.stringify(current,null,2);const blob=new Blob([s],{type:type==='json'?'application/json':'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='metadata-report.'+type;a.click();URL.revokeObjectURL(a.href)}</script></body></html>'''

@app.get('/', response_class=HTMLResponse)
def home(): return HTML

@app.post('/api/pdf')
async def inspect_pdf(file: UploadFile = File(...)):
    data = await file.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES: raise HTTPException(413,'PDF exceeds 20 MB')
    if not data.startswith(b'%PDF-'): raise HTTPException(400,'Not a PDF header')
    try:
        doc=fitz.open(stream=data,filetype='pdf')
        meta=dict(doc.metadata)
        pages=len(doc)
        doc.close()
    except Exception:
        raise HTTPException(422,'PDF cannot be parsed')
    return {'source':'uploaded PDF','filename':file.filename,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'page_count':pages,'pdf_metadata':meta,'analyzed_at_utc':datetime.now(timezone.utc).isoformat(),'summary':f'Inspected {pages} page(s). PDF metadata timestamps are document claims, not proof of upload or publication date. SHA-256 fingerprint recorded for future comparisons.','limitations':['Metadata fields can be absent, incorrect or modified.','This analysis does not establish server upload time or chain of custody.']}

class UrlRequest(BaseModel):
    url: str

def validate_public_https(url):
    p=urlparse(url)
    if p.scheme!='https' or not p.hostname or p.username or p.password or p.port not in (None,443): raise HTTPException(400,'Public HTTPS URLs on port 443 only')
    try: addresses=socket.getaddrinfo(p.hostname,443,type=socket.SOCK_STREAM)
    except OSError: raise HTTPException(400,'Hostname resolution failed')
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses): raise HTTPException(400,'Non-public destination rejected')

@app.post('/api/url')
async def inspect_url(req:UrlRequest):
    validate_public_https(req.url)
    try:
        async with httpx.AsyncClient(timeout=12,follow_redirects=False,trust_env=False) as client:
            r=await client.head(req.url)
    except httpx.HTTPError: raise HTTPException(502,'Remote site could not be reached')
    return {'source':'HTTP HEAD','url':req.url,'status_code':r.status_code,'headers':{k:v for k,v in r.headers.items() if k.lower() in ('date','last-modified','etag','content-type','content-length','cache-control','server','age','via')},'analyzed_at_utc':datetime.now(timezone.utc).isoformat(),'summary':'HTTP response headers captured. Last-Modified, when present, is not conclusive proof of original publication or upload date.','limitations':['HEAD responses can differ from GET responses.','Redirects are not followed.','Server headers and caches can be misleading.','This tool does not certify evidence provenance.']}


@app.post('/api/acquire')
async def acquire_document(req: UrlRequest):
    """Evidence-oriented HTTPS acquisition. Intended for trusted local deployments."""
    validate_public_https(req.url)
    parsed = urlparse(req.url)
    resolved = sorted({entry[4][0] for entry in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)})
    if not resolved or any(not ipaddress.ip_address(x).is_global for x in resolved):
        raise HTTPException(400, 'Non-public DNS result rejected')
    acquisition_id = uuid.uuid4().hex
    start = stamp()
    monotonic_start = time.monotonic()
    record = {
        'acquisition_id': acquisition_id, 'event': 'HTTPS_GET', 'started_utc': start,
        'request': {'method': 'GET', 'url': req.url, 'scheme': parsed.scheme,
                    'hostname': parsed.hostname, 'port': 443, 'url_path': parsed.path,
                    'url_directory': str(pathlib.PurePosixPath(parsed.path).parent),
                    'url_filename': unquote(pathlib.PurePosixPath(parsed.path).name),
                    'query_string': parsed.query, 'dns_resolved_ips': resolved},
        'physical_server_location': 'Unknown; not inferable from HTTP/DNS alone',
        'server_filesystem_directory': 'Unknown; URL path is not a filesystem path',
        'limitations': ['DNS IPs may identify a CDN or proxy rather than origin server.',
                        'Server Date and Last-Modified are not proof of original upload time.',
                        'Public hosting requires authentication, request limits and DNS-rebinding protections.']
    }
    target = AUDIT_DIR / (acquisition_id + '.bin')
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0), follow_redirects=False, trust_env=False) as client:
            async with client.stream('GET', req.url, headers={'Accept-Encoding': 'identity'}) as response:
                record['response'] = {'status_code': response.status_code, 'http_version': response.http_version,
                                      'headers': dict(response.headers), 'redirect_location': response.headers.get('location')}
                stream = response.extensions.get('network_stream')
                if stream:
                    try: record['response']['connected_peer'] = str(stream.get_extra_info('server_addr'))
                    except Exception: pass
                    try:
                        ssl_obj = stream.get_extra_info('ssl_object')
                        if ssl_obj:
                            record['response']['tls_version'] = ssl_obj.version()
                            record['response']['tls_cipher'] = str(ssl_obj.cipher())
                    except Exception: pass
                h = hashlib.sha256()
                total = 0
                with target.open('wb') as out:
                    async for chunk in response.aiter_raw():
                        total += len(chunk)
                        if total > MAX_BYTES: raise ValueError('Response exceeded 20 MB limit')
                        h.update(chunk)
                        out.write(chunk)
                record['file'] = {'stored_path': str(target.resolve()), 'size_bytes': total, 'sha256': h.hexdigest(),
                                  'pdf_signature': target.open('rb').read(5) == b'%PDF-'}
                if record['file']['pdf_signature']:
                    try:
                        with fitz.open(str(target)) as doc:
                            record['file']['page_count'] = len(doc)
                            record['file']['pdf_metadata'] = dict(doc.metadata)
                    except Exception as exc:
                        record['file']['pdf_parse_error'] = type(exc).__name__
        record['outcome'] = 'completed'
    except (httpx.HTTPError, ValueError, OSError) as exc:
        target.unlink(missing_ok=True)
        record['outcome'] = 'failed'
        record['error'] = {'type': type(exc).__name__, 'message': str(exc)[:300]}
    finally:
        record['finished_utc'] = stamp()
        record['elapsed_ms'] = round((time.monotonic() - monotonic_start) * 1000, 3)
        write_audit(record)
    return record

@app.get('/api/audit')
def audit_history():
    if not AUDIT_LOG.exists(): return {'acquisitions': []}
    lines = AUDIT_LOG.read_text(encoding='utf-8').splitlines()[-100:]
    return {'acquisitions': [json.loads(line) for line in reversed(lines)]}

# Universal, read-only file inspection. Optional tools enrich results when installed.
import mimetypes, subprocess, shutil, zipfile, xml.etree.ElementTree as ET

def universal_inspect(data, filename):
    name = pathlib.PurePath(filename or 'unnamed').name
    sigs = [(b'%PDF-', 'PDF'), (b'\x89PNG\r\n\x1a\n','PNG'), (b'\xff\xd8\xff','JPEG'), (b'GIF8','GIF'), (b'PK\x03\x04','ZIP/Office Open XML'), (b'RIFF','RIFF'), (b'ID3','MP3'), (b'SQLite format 3\x00','SQLite'), (b'\x7fELF','ELF'), (b'MZ','Windows executable')]
    signature = next((label for prefix,label in sigs if data.startswith(prefix)), 'Unknown')
    result = {'source':'local upload','filename':name,'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(), 'sha512':hashlib.sha512(data).hexdigest(), 'signature_type':signature, 'extension':pathlib.Path(name).suffix.lower(), 'extension_inferred_mime':mimetypes.guess_type(name)[0], 'analyzed_at_utc':stamp(), 'metadata':{}, 'warnings':[], 'limitations':['File system creation/modification timestamps are not preserved by ordinary browser uploads.','Metadata fields are editable and do not independently establish authenticity.']}
    if data.startswith(b'%PDF-'):
        try:
            d=fitz.open(stream=data,filetype='pdf'); result['metadata']['pdf']={'pages':len(d),'properties':dict(d.metadata)}; d.close()
        except Exception as e: result['warnings'].append('PDF parser failed: '+str(e)[:150])
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                items=z.infolist(); result['metadata']['archive']={'entry_count':len(items),'entries':[{'path':i.filename,'uncompressed_bytes':i.file_size,'stored_timestamp':i.date_time} for i in items[:200]],'truncated':len(items)>200}
                for core in ('docProps/core.xml','meta.xml'):
                    if core in z.namelist() and z.getinfo(core).file_size < 1000000:
                        root=ET.fromstring(z.read(core)); result['metadata']['document_properties']={el.tag.split('}')[-1]:el.text for el in root.iter() if el.text and len(el.text)<1000}
        except Exception as e: result['warnings'].append('Archive parser failed: '+str(e)[:150])
    try:
        from PIL import Image, ExifTags
        im=Image.open(io.BytesIO(data)); result['metadata']['image']={'format':im.format,'width':im.width,'height':im.height,'mode':im.mode,'exif':{str(ExifTags.TAGS.get(k,k)):str(v)[:1000] for k,v in im.getexif().items()}}
    except Exception: pass
    # External parsers receive a temporary copy; never execute the uploaded file.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p=pathlib.Path(td)/('sample'+pathlib.Path(name).suffix[:20]); p.write_bytes(data)
        if shutil.which('exiftool'):
            try:
                r=subprocess.run(['exiftool','-json','-G1','-a',str(p)],capture_output=True,text=True,timeout=12)
                if r.returncode==0: result['metadata']['exiftool']=json.loads(r.stdout)[0]
            except Exception as e: result['warnings'].append('ExifTool: '+str(e)[:120])
        if shutil.which('ffprobe'):
            try:
                r=subprocess.run(['ffprobe','-v','error','-show_format','-show_streams','-of','json',str(p)],capture_output=True,text=True,timeout=12)
                if r.returncode==0: result['metadata']['media']=json.loads(r.stdout)
            except Exception as e: result['warnings'].append('FFprobe: '+str(e)[:120])
    result['summary']='Read-only analysis completed; hashes establish a fingerprint of the bytes received, not the historical origin of the file.'
    return result

@app.post('/api/file')
async def inspect_any_file(file: UploadFile = File(...)):
    data=await file.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES: raise HTTPException(413,'File exceeds configured 20 MB limit')
    return universal_inspect(data,file.filename)

# Override the earlier dashboard with a general-purpose file input.
HTML=HTML.replace('Document integrity • PDF metadata','Document integrity • Universal file metadata').replace('1. Inspect PDF','1. Inspect Any File').replace('Select a PDF first','Select a file first').replace('Analyze PDF','Analyze File').replace('accept="application/pdf,.pdf"','').replace("request('/api/pdf'","request('/api/file'")


# Evidence registry: persistent when AUDIT_DIR is mounted on durable storage.
DB_PATH = AUDIT_DIR / "evidence.sqlite3"
def db_connect():
    c=sqlite3.connect(DB_PATH,timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, recorded_utc TEXT NOT NULL, source TEXT, filename TEXT, sha256 TEXT, size_bytes INTEGER, data_json TEXT NOT NULL)")
    c.commit()
    return c

def save_evidence(record):
    obj=jsonable_encoder(record)
    eid=obj.get('evidence_id') or uuid.uuid4().hex
    obj['evidence_id']=eid
    f=obj.get('file',{})
    with db_connect() as c:
        c.execute('INSERT INTO evidence VALUES (?,?,?,?,?,?,?)', (eid,stamp(),obj.get('source',''),obj.get('filename') or f.get('filename',''),obj.get('sha256') or f.get('sha256'),obj.get('size_bytes') or f.get('size_bytes'),json.dumps(obj,default=str)))
    return obj

@app.get('/api/evidence')
def evidence_search(q: str='', limit: int=100):
    limit=max(1,min(limit,500))
    with db_connect() as c:
        rows=c.execute('SELECT id,recorded_utc,source,filename,sha256,size_bytes FROM evidence WHERE filename LIKE ? OR sha256 LIKE ? OR data_json LIKE ? ORDER BY recorded_utc DESC LIMIT ?',tuple(['%'+q+'%']*3+[limit])).fetchall()
    return {'items':[dict(zip(('id','recorded_utc','source','filename','sha256','size_bytes'),r)) for r in rows]}

@app.get('/api/evidence/{evidence_id}')
def evidence_detail(evidence_id: str):
    with db_connect() as c: row=c.execute('SELECT data_json FROM evidence WHERE id=?',(evidence_id,)).fetchone()
    if not row: raise HTTPException(404,'Evidence record not found')
    return json.loads(row[0])

async def analyze_streamed_upload(file: UploadFile):
    # Stream to disk to avoid keeping multi-GB videos in RAM.
    eid=uuid.uuid4().hex
    folder=AUDIT_DIR/'uploads'; folder.mkdir(parents=True,exist_ok=True)
    path=folder/(eid+'.bin')
    sha=hashlib.sha256(); sha512=hashlib.sha512(); size=0
    try:
        with path.open('wb') as out:
            while True:
                chunk=await file.read(1024*1024)
                if not chunk: break
                size+=len(chunk)
                if size>MAX_BYTES: raise HTTPException(413,'Upload exceeds configured limit')
                sha.update(chunk);sha512.update(chunk);out.write(chunk)
        with path.open('rb') as f: prefix=f.read(32)
        sig=next((name for marker,name in [(b'%PDF-','PDF'),(b'\x89PNG','PNG'),(b'\xff\xd8\xff','JPEG'),(b'PK\x03\x04','ZIP/Office'),(b'RIFF','RIFF'),(b'SQLite format 3','SQLite')] if prefix.startswith(marker)),'Unknown')
        record={'source':'local upload','filename':pathlib.PurePath(file.filename or 'unnamed').name,'size_bytes':size,'sha256':sha.hexdigest(),'sha512':sha512.hexdigest(),'signature_type':sig,'acquired_at_utc':stamp(),'stored_path':str(path.resolve()),'metadata':{},'limitations':['Browser uploads do not reliably preserve original filesystem timestamps.','Metadata timestamps are not proof of historical publication.']}
        if size<=50*1024*1024:
            detailed=universal_inspect(path.read_bytes(),file.filename)
            record['metadata']=detailed.get('metadata',{});record['warnings']=detailed.get('warnings',[])
        else:
            # Probe large media directly from disk rather than loading it into memory.
            import subprocess
            if shutil.which('ffprobe'):
                try:
                    result=subprocess.run(['ffprobe','-v','error','-show_format','-show_streams','-of','json',str(path)],capture_output=True,text=True,timeout=45)
                    if result.returncode==0: record['metadata']['media']=json.loads(result.stdout)
                except Exception as exc:record.setdefault('warnings',[]).append('Media probe: '+type(exc).__name__)
            if shutil.which('exiftool'):
                try:
                    result=subprocess.run(['exiftool','-json','-G1','-a',str(path)],capture_output=True,text=True,timeout=45)
                    if result.returncode==0:record['metadata']['exiftool']=json.loads(result.stdout)[0]
                except Exception as exc:record.setdefault('warnings',[]).append('ExifTool: '+type(exc).__name__)
        return save_evidence(record)
    except Exception:
        path.unlink(missing_ok=True)
        raise

@app.post('/api/batch')
async def batch_upload(files: list[UploadFile] = File(...)):
    if len(files)>MAX_BATCH_FILES:raise HTTPException(413,'Maximum 25 files per batch')
    results=[]
    for file in files:
        try:results.append(await analyze_streamed_upload(file))
        except Exception as exc:results.append({'filename':file.filename,'error':str(exc)[:250]})
    return {'batch_id':uuid.uuid4().hex,'processed_at_utc':stamp(),'results':results}

@app.post('/api/file-large')
async def inspect_large_file(file: UploadFile=File(...)):
    return await analyze_streamed_upload(file)

@app.get('/api/timeline/{evidence_id}')
def evidence_timeline(evidence_id: str):
    obj=evidence_detail(evidence_id)
    events=[]
    def walk(value,path='',depth=0):
        if depth>9:return
        if isinstance(value,dict):
            for k,v in value.items():
                key=path+'.'+k if path else k
                if isinstance(v,(str,int,float)) and any(t in k.lower() for t in ('date','time','created','modified','acquired','started','finished','last-modified')):
                    if len(str(v))<250:events.append({'field':key,'value':str(v),'classification':'Source-provided timestamp; verify independently'})
                elif isinstance(v,(dict,list)):walk(v,key,depth+1)
        elif isinstance(value,list):
            for i,v in enumerate(value[:100]):walk(v,f'{path}[{i}]',depth+1)
    walk(obj)
    return {'evidence_id':evidence_id,'timestamps':events,'caution':'These timestamps may have different timezones and provenance. No inferred upload date is asserted.'}

# Persist URL acquisition records in the searchable evidence registry.
_original_acquire=acquire_document
@app.post('/api/acquire-recorded')
async def acquire_recorded(req:UrlRequest, request:Request):
    if os.environ.get("ENABLE_REMOTE_ACQUISITION", "false").lower() != "true" and request.client and request.client.host not in ("127.0.0.1", "::1", "testclient"):
        raise HTTPException(403,"Remote acquisition disabled for non-local requests; enable only in a secured deployment")
    result=await _original_acquire(req)
    result['source']='remote acquisition'
    result['filename']=result.get('request',{}).get('url_filename','')
    return save_evidence(result)

# Upgraded single-page UI; existing APIs remain available.
HTML = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Metadata Verification Laboratory</title><style>
:root{font-family:system-ui,sans-serif;color:#e7efff;background:#0a1322}body{margin:0}header{background:#10263b;padding:19px 28px;border-bottom:1px solid #36506b}h1{font-size:23px;margin:0}small,.muted{color:#9bb2ca}.wrap{max-width:1280px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.panel{background:#13263b;border:1px solid #34506c;border-radius:12px;padding:20px;margin-bottom:18px}input{box-sizing:border-box;width:100%;background:#0a192b;color:white;border:1px solid #526c87;border-radius:7px;padding:11px;margin:12px 0}button{background:#2075d8;color:white;border:0;border-radius:7px;padding:10px 14px;cursor:pointer;margin:5px 5px 5px 0}button:hover{background:#398cef}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#071423;padding:15px;max-height:500px;overflow:auto;border-radius:8px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:9px;border-bottom:1px solid #34506c;font-size:13px}a{color:#75b7ff}.notice{color:#f6c777}@media(max-width:800px){.grid{grid-template-columns:1fr}}</style></head><body>
<header><h1>⚗ Metadata Verification Laboratory</h1><small>Universal file forensics · Server acquisition · Evidence registry · Timeline analysis</small></header><main class="wrap"><div class="grid"><section class="panel"><h2>Analyze files / batch</h2><p class="muted">Choose up to 25 files, including documents, images, audio, and video. Large uploads are streamed to disk.</p><input id="files" type="file" multiple><button onclick="upload()">Analyze & Preserve Evidence</button><p class="muted">Maximum per file is set by server configuration (default 2 GB).</p></section><section class="panel"><h2>Acquire from website</h2><p class="muted">Records URL, request timestamps, DNS IPs, response headers, and downloaded bytes.</p><input id="url" type="url" placeholder="https://example.org/document.pdf"><button onclick="acquire()">Acquire & Audit</button><p class="notice">Public deployment without authentication is not recommended. Remote URL acquisition must be secured against SSRF.</p></section></div>
<section class="panel"><h2>Search evidence history</h2><input id="query" placeholder="Search filename, hash, URL, or metadata" onkeydown="if(event.key==='Enter')history()"><button onclick="history()">Search</button><table><thead><tr><th>Recorded UTC</th><th>Filename</th><th>SHA-256</th><th>Actions</th></tr></thead><tbody id="items"></tbody></table></section>
<section class="panel"><h2>Compare evidence versions</h2><p class="muted">Select 2–10 evidence records using their IDs (comma-separated). Compares hashes and extracted metadata, and shows acquisition context.</p><input id="compareids" placeholder="Evidence ID 1, Evidence ID 2"><button onclick="compareVersions()">Compare versions</button></section>
<section class="panel"><h2>Analysis & timeline</h2><button onclick="exportReport('json')">Download JSON</button><button onclick="exportReport('txt')">Download plain-English / technical report</button><pre id="output">Select or acquire a file to view its evidence record.</pre></section><p class="muted">Evidence is saved to AUDIT_DIR. Persistent storage, backup, request throttling, and access restrictions are required for an internet-facing deployment. Internal metadata does not establish historical upload date.</p></main>
<script>let current=null;const $=id=>document.getElementById(id);function show(v){current=v;$('output').textContent=JSON.stringify(v,null,2)}async function call(url,opt){try{const r=await fetch(url,opt);const v=await r.json();if(!r.ok)throw Error(JSON.stringify(v));show(v);history()}catch(e){alert(e.message)}}async function upload(){const files=$('files').files;if(!files.length)return alert('Select files');const fd=new FormData();for(const f of files)fd.append('files',f);await call('/api/batch',{method:'POST',body:fd})}async function acquire(){await call('/api/acquire-recorded',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:$('url').value})})}async function history(){const r=await fetch('/api/evidence?q='+encodeURIComponent($('query').value));const v=await r.json();$('items').replaceChildren();for(const x of v.items){const tr=document.createElement('tr');for(const s of [x.recorded_utc,x.filename,(x.sha256||'').slice(0,22)+'…']){const td=document.createElement('td');td.textContent=s;tr.append(td)}const td=document.createElement('td');const b=document.createElement('button');b.textContent='Open';b.onclick=()=>detail(x.id);td.append(b);const t=document.createElement('button');t.textContent='Timeline';t.onclick=()=>timeline(x.id);td.append(t);tr.append(td);$('items').append(tr)}}async function detail(id){const r=await fetch('/api/evidence/'+id);show(await r.json())}async function timeline(id){const r=await fetch('/api/timeline/'+id);show(await r.json())}async function compareVersions(){const evidence_ids=$('compareids').value.split(',').map(x=>x.trim()).filter(Boolean);await call('/api/compare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({evidence_ids})})}function exportReport(ext){if(!current)return;const s=ext==='json'?JSON.stringify(current,null,2):'METADATA VERIFICATION LABORATORY\n\nEvidence findings and limitations\n\n'+JSON.stringify(current,null,2);const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([s]));a.download='evidence-report.'+ext;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}history()</script></body></html>'''


# Evidence comparison: observations, not claims of historical publication.
class CompareRequest(BaseModel):
    evidence_ids: list[str]
    archive_observations: list[dict] = []

def _flatten_metadata(value, prefix='', depth=0):
    out={}
    if depth>8: return out
    if isinstance(value,dict):
        for k,v in value.items():
            key=f'{prefix}.{k}' if prefix else str(k)
            if isinstance(v,(dict,list)):out.update(_flatten_metadata(v,key,depth+1))
            elif isinstance(v,(str,int,float,bool)) or v is None:out[key]=v
    elif isinstance(value,list):
        for i,v in enumerate(value[:100]):out.update(_flatten_metadata(v,f'{prefix}[{i}]',depth+1))
    return out

@app.post('/api/compare')
def compare_evidence(req:CompareRequest):
    if not 2<=len(req.evidence_ids)<=10:raise HTTPException(422,'Select 2 to 10 evidence records')
    if len(set(req.evidence_ids))!=len(req.evidence_ids):raise HTTPException(422,'Evidence IDs must be distinct')
    records=[evidence_detail(eid) for eid in req.evidence_ids]
    hashes=[r.get('sha256') or (r.get('file') or {}).get('sha256') for r in records]
    if all(hashes) and len(set(hashes))==1:integrity='identical_bytes'
    elif all(hashes):integrity='different_bytes'
    else:integrity='insufficient_hashes'
    flat=[_flatten_metadata(r.get('metadata') or r.get('file',{}).get('metadata') or {}) for r in records]
    keys=sorted(set().union(*(set(x) for x in flat)))
    differences=[]
    for key in keys:
        values=[x.get(key) for x in flat]
        if any(v!=values[0] for v in values[1:]):differences.append({'field':key,'values':values})
    observations=[]
    for obs in req.archive_observations[:50]:
        if not isinstance(obs,dict):continue
        observations.append({'observed_at_utc':obs.get('observed_at_utc'),'archived_url':obs.get('archived_url'),'source':obs.get('source'),'notes':obs.get('notes'),'verification':'user-supplied; not independently verified'})
    findings=[]
    if integrity=='identical_bytes':findings.append('Available SHA-256 hashes match; recorded bytes appear identical.')
    elif integrity=='different_bytes':findings.append('SHA-256 hashes differ; file bytes are not identical. This alone does not establish when changes occurred.')
    else:findings.append('At least one SHA-256 hash is missing; byte-level equality cannot be established.')
    if differences:findings.append(f'{len(differences)} differing extracted metadata fields identified; inspect source provenance before interpreting.')
    return {'comparison_id':uuid.uuid4().hex,'compared_at_utc':stamp(),'evidence_ids':req.evidence_ids,'documents':[{'evidence_id':r.get('evidence_id'),'filename':r.get('filename'),'sha256':h,'source':r.get('source'),'acquired_at_utc':r.get('acquired_at_utc'),'request':r.get('request'),'response':r.get('response')} for r,h in zip(records,hashes)],'byte_comparison':integrity,'metadata_differences':differences,'archive_observations':observations,'findings':findings,'limitations':['Archive observations are user supplied, not fetched or authenticated by this comparison endpoint.','A server response date establishes a response observation, not the original publication date.','File creation/modification fields may be edited or inherited.','No conclusion about intentional alteration or misconduct is made.']}

# Version 6: case management, chain-of-custody hash chain, archive observations,
# source re-hashing and structured evidence dossiers.
from forensic_extensions import router as forensic_router, log as custody_log
app.include_router(forensic_router)
_previous_save_evidence = save_evidence
def save_evidence(record):
    saved = _previous_save_evidence(record)
    custody_log('evidence_ingested', evidence_id=saved['evidence_id'], details={'sha256':saved.get('sha256') or saved.get('file',{}).get('sha256'),'source':saved.get('source'),'filename':saved.get('filename')})
    return saved

HTML=HTML.replace('<section class="panel"><h2>Compare evidence versions</h2>', '''<section class="panel"><h2>Forensic workspace · v6</h2><p class="muted">Case management, custody integrity, preserved-file verification and archive observations.</p><input id="casename" placeholder="New case name"><button onclick="createCase()">Create Case</button><button onclick="forensic('/api/forensic/cases')">View Cases</button><button onclick="forensic('/api/forensic/custody/verify')">Verify Custody Log</button><button onclick="forensic('/api/forensic/custody')">Custody Events</button><input id="forensicid" placeholder="Evidence ID"><button onclick="forensic('/api/forensic/integrity/'+encodeURIComponent($('forensicid').value))">Verify Original File</button><button onclick="forensic('/api/forensic/report/'+encodeURIComponent($('forensicid').value))">Evidence Dossier</button><input id="archiveurl" placeholder="Historical archive URL (manual observation)"><button onclick="addObservation()">Record Archive Observation</button><p class="muted">Archive observations are manually supplied and not independently verified.</p></section><section class="panel"><h2>Compare evidence versions</h2>''')
HTML=HTML.replace('history()</script>', '''async function forensic(path){await call(path)}async function createCase(){await call('/api/forensic/cases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('casename').value})})}async function addObservation(){await call('/api/forensic/observations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({evidence_id:$('forensicid').value||null,source_url:$('archiveurl').value,archive_url:$('archiveurl').value})})}history()</script>''')

# Version 7: Wayback Machine discovery and archived snapshot preservation.
from wayback_extensions import router as wayback_router
app.include_router(wayback_router)
HTML=HTML.replace('<section class="panel"><h2>Forensic workspace · v6', '''<section class="panel"><h2>Automatic Wayback Retrieval · v7</h2><p class="note">Search historical captures and preserve an exact snapshot with its SHA-256 and acquisition audit. CDX availability varies.</p><input type="url" id="wburl" placeholder="https://example.org/meetings/document.pdf"><button onclick="wbLookup()">Find Archived Snapshots</button><input id="wbstamp" placeholder="14-digit capture timestamp (YYYYMMDDhhmmss)"><button onclick="wbPreserve()">Preserve Selected Snapshot</button><p class="note">Archived timestamps are observations, not proof of the original publication date.</p></section><section class="panel"><h2>Forensic workspace · v6''')
HTML=HTML.replace('history()</script>', '''async function wbLookup(){await request('/api/wayback/lookup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('wburl').value})})}async function wbPreserve(){await request('/api/wayback/preserve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('wburl').value,timestamp:document.getElementById('wbstamp').value})})}history()</script>''')

# Version 8: automatic Wayback discovery and bounded retrieval UI.
HTML=HTML.replace('Automatic Wayback Retrieval · v7','Automatic Wayback Retrieval · v8')
HTML=HTML.replace('<button onclick="wbLookup()">Find Archived Snapshots</button>','<button onclick="wbLookup()">Find Archived Snapshots</button><button onclick="wbAuto()">Auto-Fetch 3 Snapshots</button>')
HTML=HTML.replace('history()</script>', "async function wbAuto(){await request('/api/wayback/auto-retrieve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('wburl').value,max_preserve:3})})}history()</script>")
