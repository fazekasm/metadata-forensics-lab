"""Evidence workflow extensions. No automatic assertions of authenticity."""
import hashlib, json, os, pathlib, sqlite3, uuid, hmac, re, time
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router=APIRouter(prefix='/api/forensic', tags=['forensic'])
ROOT=pathlib.Path(os.environ.get('AUDIT_DIR','./audit'))
ROOT.mkdir(parents=True,exist_ok=True)
DB=ROOT/'forensic.sqlite3'
def now():return datetime.now(timezone.utc).isoformat()
def conn():
 c=sqlite3.connect(DB,timeout=30)
 c.execute('PRAGMA journal_mode=WAL')
 c.execute('CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT,created TEXT NOT NULL)')
 c.execute('CREATE TABLE IF NOT EXISTS assignments(case_id TEXT NOT NULL,evidence_id TEXT NOT NULL,added TEXT NOT NULL,PRIMARY KEY(case_id,evidence_id))')
 c.execute('CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE,utc TEXT NOT NULL,kind TEXT NOT NULL,evidence_id TEXT,case_id TEXT,details TEXT NOT NULL,prev_hash TEXT NOT NULL,event_hash TEXT NOT NULL)')
 c.execute('CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,evidence_id TEXT,source_url TEXT NOT NULL,archive_url TEXT,observed_utc TEXT,reported_utc TEXT NOT NULL,claim TEXT,verification TEXT NOT NULL)')
 c.commit();return c
def log(kind,evidence_id=None,case_id=None,details=None):
 with conn() as c:
  previous=c.execute('SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
  previous=previous[0] if previous else 'GENESIS'
  payload={'id':uuid.uuid4().hex,'utc':now(),'kind':kind,'evidence_id':evidence_id,'case_id':case_id,'details':details or {},'prev_hash':previous}
  digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  c.execute('INSERT INTO events(id,utc,kind,evidence_id,case_id,details,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?,?)',(payload['id'],payload['utc'],kind,evidence_id,case_id,json.dumps(payload['details'],sort_keys=True),previous,digest))
 return {'event_hash':digest,**payload}
def verify_chain():
 with conn() as c: rows=c.execute('SELECT id,utc,kind,evidence_id,case_id,details,prev_hash,event_hash FROM events ORDER BY seq').fetchall()
 prev='GENESIS'
 for i,r in enumerate(rows,1):
  id,utc,kind,eid,cid,details,old,digest=r
  try: parsed=json.loads(details)
  except Exception:return {'valid':False,'broken_at':i,'reason':'invalid JSON'}
  payload={'id':id,'utc':utc,'kind':kind,'evidence_id':eid,'case_id':cid,'details':parsed,'prev_hash':old}
  computed=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  if old!=prev or not hmac.compare_digest(computed,digest):return {'valid':False,'broken_at':i,'reason':'hash-chain mismatch'}
  prev=digest
 return {'valid':True,'event_count':len(rows),'head_hash':prev,'limitation':'A local hash chain detects many modifications but cannot prove that records were not deleted, rewritten, or replaced by an administrator. Export and independently timestamp the head hash.'}
class CaseIn(BaseModel):
 name:str=Field(min_length=1,max_length=160)
 description:str=Field(default='',max_length=4000)
class AssignIn(BaseModel):
 case_id:str
 evidence_id:str
class ObservationIn(BaseModel):
 evidence_id:str|None=None
 source_url:str
 archive_url:str|None=None
 observed_utc:str|None=None
 claim:str|None=None
 verification:str='user-supplied / unverified'
@router.post('/cases')
def create_case(data:CaseIn):
 case={'id':uuid.uuid4().hex,'name':data.name,'description':data.description,'created':now()}
 with conn() as c:c.execute('INSERT INTO cases VALUES(?,?,?,?)',(case['id'],case['name'],case['description'],case['created']))
 log('case_created',case_id=case['id'],details={'name':case['name']})
 return case
@router.get('/cases')
def cases():
 with conn() as c:
  rows=c.execute('SELECT id,name,description,created FROM cases ORDER BY created DESC').fetchall()
 return {'cases':[dict(zip(('id','name','description','created'),r)) for r in rows]}
@router.post('/assign')
def assign(data:AssignIn):
 with conn() as c:
  if not c.execute('SELECT 1 FROM cases WHERE id=?',(data.case_id,)).fetchone():raise HTTPException(404,'Case not found')
  if not (ROOT/'evidence.sqlite3').exists():raise HTTPException(404,'Evidence registry not initialized')
  with sqlite3.connect(ROOT/'evidence.sqlite3') as e:
   if not e.execute('SELECT 1 FROM evidence WHERE id=?',(data.evidence_id,)).fetchone():raise HTTPException(404,'Evidence not found')
  c.execute('INSERT OR IGNORE INTO assignments VALUES(?,?,?)',(data.case_id,data.evidence_id,now()))
 log('evidence_assigned',data.evidence_id,data.case_id)
 return {'assigned':True,'case_id':data.case_id,'evidence_id':data.evidence_id}
@router.get('/cases/{case_id}/evidence')
def case_evidence(case_id:str):
 with conn() as c: rows=c.execute('SELECT evidence_id,added FROM assignments WHERE case_id=?',(case_id,)).fetchall()
 return {'case_id':case_id,'items':[{'evidence_id':r[0],'added_utc':r[1]} for r in rows]}
@router.post('/observations')
def observation(data:ObservationIn):
 if not data.source_url.startswith(('https://','http://')):raise HTTPException(422,'Source URL required')
 item={'id':uuid.uuid4().hex,**data.model_dump(),'reported_utc':now()}
 with conn() as c:c.execute('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)',(item['id'],item['evidence_id'],item['source_url'],item['archive_url'],item['observed_utc'],item['reported_utc'],item['claim'],item['verification']))
 log('archive_observation_recorded',data.evidence_id,details={'observation_id':item['id'],'verification':data.verification})
 return item
@router.get('/observations')
def observations(evidence_id:str|None=None):
 with conn() as c:
  if evidence_id:rows=c.execute('SELECT * FROM observations WHERE evidence_id=? ORDER BY reported_utc DESC',(evidence_id,)).fetchall()
  else:rows=c.execute('SELECT * FROM observations ORDER BY reported_utc DESC LIMIT 200').fetchall()
 return {'observations':[dict(zip(('id','evidence_id','source_url','archive_url','observed_utc','reported_utc','claim','verification'),r)) for r in rows]}
@router.get('/custody')
def custody(evidence_id:str|None=None):
 with conn() as c:
  if evidence_id:rows=c.execute('SELECT seq,id,utc,kind,evidence_id,case_id,details,event_hash FROM events WHERE evidence_id=? ORDER BY seq',(evidence_id,)).fetchall()
  else:rows=c.execute('SELECT seq,id,utc,kind,evidence_id,case_id,details,event_hash FROM events ORDER BY seq DESC LIMIT 250').fetchall()
 return {'events':[dict(zip(('seq','id','utc','kind','evidence_id','case_id','details','event_hash'),r)) for r in rows]}
@router.get('/custody/verify')
def verify():return verify_chain()
@router.get('/integrity/{evidence_id}')
def integrity(evidence_id:str):
 with sqlite3.connect(ROOT/'evidence.sqlite3') as c:row=c.execute('SELECT data_json FROM evidence WHERE id=?',(evidence_id,)).fetchone()
 if not row:raise HTTPException(404,'Evidence not found')
 record=json.loads(row[0]); expected=record.get('sha256') or (record.get('file') or {}).get('sha256')
 rawpath=record.get('stored_path') or (record.get('file') or {}).get('stored_path')
 if not rawpath:return {'evidence_id':evidence_id,'status':'not_verifiable','reason':'No preserved source file path'}
 path=pathlib.Path(rawpath).resolve()
 if not path.is_relative_to(ROOT.resolve()):return {'evidence_id':evidence_id,'status':'not_verifiable','reason':'Preserved file outside managed evidence directory'}
 if not path.is_file():return {'evidence_id':evidence_id,'status':'missing_source_file'}
 sha=hashlib.sha256();size=0
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):sha.update(chunk);size+=len(chunk)
 actual=sha.hexdigest();status='match' if expected and hmac.compare_digest(actual,expected) else 'mismatch'
 return {'evidence_id':evidence_id,'status':status,'expected_sha256':expected,'actual_sha256':actual,'bytes_checked':size,'verified_at_utc':now()}
@router.get('/report/{evidence_id}')
def report(evidence_id:str):
 with sqlite3.connect(ROOT/'evidence.sqlite3') as c:row=c.execute('SELECT data_json FROM evidence WHERE id=?',(evidence_id,)).fetchone()
 if not row:raise HTTPException(404,'Evidence not found')
 record=json.loads(row[0]); integrity_result=integrity(evidence_id)
 return {'report_type':'forensic_evidence_dossier','generated_utc':now(),'evidence_id':evidence_id,'executive_summary':f"Evidence {evidence_id}: {record.get('filename','unnamed')}. Integrity recheck: {integrity_result['status']}.",'technical_record':record,'integrity_check':integrity_result,'interpretation':'Recorded file and server timestamps are claims or observations with distinct provenance; none independently establishes original publication date.','limitations':['Local records are not externally notarized.','Evidence handling before laboratory ingestion is unknown unless independently documented.','Network IP and HTTP headers may describe CDN infrastructure rather than origin.']}
