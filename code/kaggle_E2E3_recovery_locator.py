import json, os, re
from pathlib import Path
import pandas as pd

EXPECTED_CONFIG='48579ceb7266943472e3d4232d71a862e4643c54edd7f20123ce89100ae3adea'
EXPECTED_ALLOCATION='11c7e79d283ced769a7be8c13dd9f06952b604c411eb51eff714d9a81c20dd55'
WORK=Path('/kaggle/working')
MAX_WORKING_FILES=20000

# Read the newest completed inventory; do not repeat the large root scan.
inventories=sorted(WORK.glob('CLOSING_E0A_INVENTORY_*/file_inventory.csv'))
if not inventories:
    raise FileNotFoundError('No E0-A file inventory in this runtime')
INVENTORY=pd.read_csv(inventories[-1],dtype=str,keep_default_na=False)

working=[]
for i,(root,dirs,files) in enumerate(os.walk(WORK)):
    dirs[:]=sorted(d for d in dirs if d not in ['.git','__pycache__'])
    for name in sorted(files):
        p=Path(root)/name
        working.append(p)
        if len(working)>=MAX_WORKING_FILES:break
    if len(working)>=MAX_WORKING_FILES:break

run_dirs=set()
for p in working:
    if p.name=='configuration.json' and 'CLOSING_E2E3_DRIVER_v2_' in str(p):
        run_dirs.add(p.parent)
backup_hits=INVENTORY[INVENTORY.path.str.contains('CLOSING_E2E3_DRIVER_v2_',regex=False) |
                      INVENTORY.path.str.contains('source_allocations',regex=False) |
                      INVENTORY.path.str.contains('source_schema_results',regex=False)].copy()

print('INVENTORY:',inventories[-1])
print('WORKING FILES SCANNED:',len(working),'bounded=',len(working)>=MAX_WORKING_FILES)
print('E2E3 RUN DIRECTORIES FOUND:',len(run_dirs))
for d in sorted(run_dirs):
    cp=d/'configuration.json'
    try:
        cfg=json.loads(cp.read_text())
        settings=cfg.get('settings')
        sha=cfg.get('configuration_sha256')
        print('\nRUN:',d)
        print('CONFIG SHA:',sha,'expected:',EXPECTED_CONFIG,'match:',sha==EXPECTED_CONFIG)
        if isinstance(settings,dict):
            print('ALLOCATION PATH:',settings.get('allocation_path'))
            print('ALLOCATION SHA:',settings.get('allocation_sha256'),'expected:',EXPECTED_ALLOCATION)
        for name in ['source_fold_results.csv','primary_fold_results.csv','view_fold_results.csv',
                     'schema_summary.csv','source_feasibility.json','receipt.json']:
            p=d/name
            if p.is_file():
                print('ARTIFACT:',p.name,'bytes=',p.stat().st_size)
                if p.suffix=='.csv':
                    try:print(' HEADER:',pd.read_csv(p,nrows=0).columns.tolist())
                    except Exception as e:print(' HEADER ERROR:',repr(e))
                elif p.suffix=='.json' and p.stat().st_size<1024*1024:
                    try:print(' JSON:',json.dumps(json.loads(p.read_text()),indent=2)[:4000])
                    except Exception as e:print(' JSON ERROR:',repr(e))
    except Exception as e:
        print('CONFIG READ ERROR:',d,repr(e))
print('\nBACKUP INVENTORY HITS:',len(backup_hits))
if len(backup_hits):
    print(backup_hits[['root_label','path','bytes']].head(100).to_string(index=False))
else:
    print('No indexed E2E3 driver/allocation path was found in mounted backups.')
print('\nDECISION: this cell only locates/audits artifacts. It does not train, predict, or repair the failed feasibility result.')
