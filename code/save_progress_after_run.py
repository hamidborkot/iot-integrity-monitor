# Run only AFTER the currently running experiment cell has finished.
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,zipfile
from IPython.display import display,FileLink

ROOT=Path('/kaggle/working/RAW_ONLY_REMEASUREMENT_20261017T130813279947Z')
REQUIRED=['fresh_HGB.joblib','fresh_LR.joblib','fresh_source_panel.csv.gz',
          'PRE_OUTCOME_PROTOCOL.json','model_binding.json','executed_pilot.py']
if not ROOT.is_dir():raise FileNotFoundError(ROOT)
missing=[n for n in REQUIRED if not (ROOT/n).is_file()]
if missing:raise RuntimeError('Essential restart files missing: '+repr(missing))
STAMP=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
ARCHIVE=Path('/kaggle/working')/('SAFE_PROGRESS_'+STAMP+'.zip')
manifest=[]
with zipfile.ZipFile(ARCHIVE,'w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file() or 'scratch' in p.relative_to(ROOT).parts or p.suffix.lower()=='.zip':continue
        if p.stat().st_size>64*1024**2:continue
        payload=p.read_bytes();name=str(p.relative_to(ROOT))
        z.writestr(name,payload)
        manifest.append({'member':name,'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()})
    z.writestr('HANDOFF_MANIFEST.json',json.dumps(manifest,indent=2))
with zipfile.ZipFile(ARCHIVE) as z:
    if z.testzip():raise RuntimeError('Archive CRC check failed')
    for item in manifest:
        if hashlib.sha256(z.read(item['member'])).hexdigest()!=item['sha256']:
            raise RuntimeError('Archive member hash mismatch: '+item['member'])
h=hashlib.sha256()
with ARCHIVE.open('rb') as f:
    for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
info={'archive':str(ARCHIVE),'bytes':ARCHIVE.stat().st_size,'sha256':h.hexdigest(),
      'members_verified':len(manifest),'download_still_required':True}
ARCHIVE.with_suffix('.receipt.json').write_text(json.dumps(info,indent=2))
print(json.dumps(info,indent=2))
display(FileLink(str(ARCHIVE)))
