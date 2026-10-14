"""Wayback CDX snapshot discovery and bounded preservation. Public URLs only."""
import hashlib, ipaddress, json, os, pathlib, socket, time, uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router=APIRouter(prefix='/api/wayback',tags=['wayback'])
ROOT=pathlib.Path(os.environ.get('AUDIT_DIR','./audit'))/'wayback'
ROOT.mkdir(parents=True,exist_ok=True)
MAX=int(os.environ.get('WAYBACK_MAX_BYTES',50*1024*1024))
CDX='https://web.archive.org/cdx/search/cdx'
def utc(): return datetime.now(timezone.utc).isoformat()
def public_url(raw):
 p=urlsplit(raw)
 if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.port not in (None,80,443):raise HTTPException(422,'A public HTTP(S) URL is required')
 host=p.hostname
 if host.lower() in ('localhost','localhost.localdomain') or host.lower().endswith(('.local','.internal')):raise HTTPException(422,'Private hostname blocked')
 try:
  addresses=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
  if not addresses or any(not ipaddress.ip_address(x[4][0]).is_global for x in addresses):raise HTTPException(422,'Private or unresolvable address blocked')
 except socket.gaierror:raise HTTPException(422,'Could not resolve hostname')
 return raw
class Lookup(BaseModel):
 url:str=Field(min_length=8,max_length=2048)
 limit:int=Field(default=30,ge=1,le=100)
 from_year:int|None=Field(default=None,ge=1996,le=2100)
 to_year:int|None=Field(default=None,ge=1996,le=2100)
class Preserve(BaseModel):
 url:str=Field(min_length=8,max_length=2048)
 timestamp:str=Field(pattern=r'^\d{14}$')
async def cdx(data:Lookup):
 public_url(data.url)
 params={'url':data.url,'output':'json','filter':'statuscode:200','collapse':'timestamp:6','fl':'timestamp,original,statuscode,mimetype,digest,length','limit':str(data.limit)}
 if data.from_year:params['from']=str(data.from_year)
 if data.to_year:params['to']=str(data.to_year)
 started=utc(); t=time.monotonic()
 try:
  async with httpx.AsyncClient(timeout=25,follow_redirects=False,trust_env=False) as client:r=await client.get(CDX,params=params)
  r.raise_for_status(); rows=r.json()
 except (httpx.HTTPError,ValueError) as e:raise HTTPException(502,f'Wayback CDX unavailable: {type(e).__name__}')
 if not isinstance(rows,list):raise HTTPException(502,'Unexpected CDX response')
 headers=rows[0] if rows else []
 snapshots=[dict(zip(headers,row)) for row in rows[1:] if isinstance(row,list)]
 return {'source_url':data.url,'queried_at_utc':started,'duration_ms':round((time.monotonic()-t)*1000,2),'cdx_endpoint':CDX,'snapshots':snapshots,'count':len(snapshots),'limitations':['CDX is an archive index, not proof that a file was publicly available at its original timestamp.','Absence of a snapshot is not evidence of absence.','Archive records may be incomplete, delayed or subject to access restrictions.']}
@router.post('/lookup')
async def lookup(data:Lookup):return await cdx(data)
@router.post('/preserve')
async def preserve(data:Preserve):
 public_url(data.url)
 # Query the exact timestamp without monthly collapsing, which would hide captures.
 params={'url':data.url,'output':'json','fl':'timestamp,original,statuscode,mimetype,digest,length','from':data.timestamp,'to':data.timestamp,'filter':'statuscode:200'}
 try:
  async with httpx.AsyncClient(timeout=25,follow_redirects=False,trust_env=False) as client:
   index_response=await client.get(CDX,params=params)
   index_response.raise_for_status()
   rows=index_response.json()
 except (httpx.HTTPError,ValueError) as e:raise HTTPException(502,f'Wayback CDX unavailable: {type(e).__name__}')
 matches=[dict(zip(rows[0],row)) for row in rows[1:] if isinstance(row,list) and rows and isinstance(rows[0],list) and len(row)==len(rows[0]) and row[0]==data.timestamp and row[1]==data.url]
 if not matches:raise HTTPException(404,'Exact snapshot not confirmed in returned CDX index; query narrower date range or inspect manually')
 archive_url=f'https://web.archive.org/web/{data.timestamp}id_/{data.url}'
 started=utc();t=time.monotonic(); name=uuid.uuid4().hex; path=ROOT/(name+'.bin'); sha=hashlib.sha256(); count=0
 try:
  async with httpx.AsyncClient(timeout=60,follow_redirects=False,trust_env=False) as client:
   async with client.stream('GET',archive_url) as response:
    if response.status_code!=200:raise HTTPException(502,f'Archive returned HTTP {response.status_code}')
    with path.open('wb') as f:
     async for chunk in response.aiter_bytes(65536):
      count+=len(chunk)
      if count>MAX:raise HTTPException(413,'Archive file exceeds preservation limit')
      sha.update(chunk);f.write(chunk)
    headers=dict(response.headers)
 except (httpx.HTTPError,OSError) as e:raise HTTPException(502,f'Archive acquisition failed: {type(e).__name__}')
 except Exception:
  path.unlink(missing_ok=True);raise
 record={'id':name,'source_url':data.url,'archive_url':archive_url,'cdx_entry':matches[0],'request_started_utc':started,'request_completed_utc':utc(),'elapsed_ms':round((time.monotonic()-t)*1000,2),'response_headers':headers,'size_bytes':count,'sha256':sha.hexdigest(),'stored_path':str(path),'limitations':['Archive response bytes may include replay transformations; compare content and original headers carefully.','Archive timestamp is a claimed capture time, not proof of original publication time.']}
 (ROOT/(name+'.json')).write_text(json.dumps(record,indent=2),encoding='utf-8')
 return record

class AutoRetrieve(Lookup):
    max_preserve:int=Field(default=3,ge=1,le=10)

@router.post('/auto-retrieve')
async def auto_retrieve(data:AutoRetrieve):
    result=await cdx(Lookup(url=data.url,limit=data.limit,from_year=data.from_year,to_year=data.to_year))
    snapshots=result['snapshots']
    indices=sorted(set([0,len(snapshots)//2,len(snapshots)-1])) if snapshots else []
    indices += [i for i in range(len(snapshots)) if i not in indices]
    preserved=[]; failures=[]
    for i in indices[:data.max_preserve]:
        entry=snapshots[i]
        try:
            record=await preserve(Preserve(url=entry['original'],timestamp=entry['timestamp']))
            preserved.append({'timestamp':entry['timestamp'],'record':record})
        except HTTPException as exc:
            failures.append({'timestamp':entry.get('timestamp'),'status':exc.status_code,'reason':exc.detail})
    result['preserved']=preserved
    result['failures']=failures
    result['selection_policy']='earliest, middle, latest indexed captures, then chronological'
    return result
