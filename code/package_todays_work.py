# Package everything modified today in /kaggle/working into ONE zip. Read-only on your results.
# No training, no replay, no deletion. Run in a Kaggle cell; then download the zip from the Output panel.
from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib, json, zipfile, shutil

WORK = Path('/kaggle/working')
TZ = timezone(timedelta(hours=8))                    # CST used in the chat
SINCE = datetime(2026, 10, 18, 0, 0, tzinfo=TZ)      # "today"; edit if needed
MAX_FILE_BYTES = 2 * 1024**3                         # skip single files above 2 GiB
SKIP_SUFFIX = {'.sqlite', '.tmp', '.stale'}
SKIP_DIR_PARTS = {'__pycache__', '.ipynb_checkpoints', 'TODAY_PACKAGE'}
STAMP = datetime.now(TZ).strftime('%Y%m%dT%H%M%S')
PKG_DIR = WORK / 'TODAY_PACKAGE'; PKG_DIR.mkdir(exist_ok=True)
ZIP_PATH = PKG_DIR / f'WORK_{SINCE:%Y%m%d}_{STAMP}.zip'

def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(4 * 1024**2), b''):
            h.update(b)
    return h.hexdigest()

if shutil.disk_usage(WORK).free < 1 * 1024**3:
    raise SystemExit('Less than 1 GiB free: free space before packaging.')

picked, skipped = [], []
for p in sorted(WORK.rglob('*')):
    if not p.is_file() or any(part in SKIP_DIR_PARTS for part in p.parts):
        continue
    st = p.stat()
    if datetime.fromtimestamp(st.st_mtime, TZ) < SINCE:
        continue
    if p.suffix.lower() in SKIP_SUFFIX or st.st_size > MAX_FILE_BYTES:
        skipped.append({'file': str(p.relative_to(WORK)), 'bytes': st.st_size, 'reason': 'suffix_or_size'})
        continue
    picked.append(p)

manifest = []
with zipfile.ZipFile(ZIP_PATH, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as z:
    for p in picked:
        z.write(p, str(p.relative_to(WORK)))
        manifest.append({'file': str(p.relative_to(WORK)), 'bytes': p.stat().st_size,
                         'modified': datetime.fromtimestamp(p.stat().st_mtime, TZ).isoformat(), 'sha256': sha(p)})
    z.writestr('PACKAGE_MANIFEST.json', json.dumps({'since': SINCE.isoformat(), 'files': manifest, 'skipped': skipped}, indent=2))
with zipfile.ZipFile(ZIP_PATH) as z:
    bad = z.testzip()
    if bad: raise SystemExit(f'CRC failure inside zip: {bad}')

print('files packaged :', len(picked))
print('files skipped  :', len(skipped))
print('zip            :', ZIP_PATH, f'{ZIP_PATH.stat().st_size/1024**2:.1f} MB')
print('zip sha256     :', sha(ZIP_PATH))
print('top-level folders included:', sorted({m["file"].split("/")[0] for m in manifest})[:40])
try:
    from IPython.display import FileLink, display
    display(FileLink(str(ZIP_PATH.relative_to(WORK))))
except Exception:
    print('Download from the Kaggle Output panel (right sidebar).')
print('NOTE: runtime storage is temporary. Click "Save Version" or add the zip as a dataset too.')
