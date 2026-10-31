import hashlib,json,shutil,zipfile
from pathlib import Path
from datetime import datetime,timezone

RUN=Path('/kaggle/working/CLOSING_E2E3_DRIVER_v2_48579ceb7266')
EXPECTED_CONFIG='48579ceb7266943472e3d4232d71a862e4643c54edd7f20123ce89100ae3adea'
MAX_BYTES=512*1024**2
RESERVE_BYTES=2*1024**3

def main():
    audits=[]
    for p in Path('/kaggle/working').glob('CLOSING_E2E3_STOP_AUDIT_*/audit_manifest.json'):
        obj=json.loads(p.read_text())
        if obj.get('source_run')==str(RUN) and obj.get('expected_configuration_sha256')==EXPECTED_CONFIG:
            audits.append((p,obj))
    if not audits:raise RuntimeError('Run Cell 1 first')
    p,audit=sorted(audits,key=lambda x:str(x[0]))[-1]
    if audit.get('errors'):raise RuntimeError('Audit contains errors; do not mark snapshot accepted')
    if audit['decision']['status']!='STOP_PRIMARY_MONITOR_BRANCH_RECORDED':
        raise RuntimeError('Branch decision unresolved; inspect Cell 1 before continuing')
    out=p.parent
    planned=[Path(r['path']) for r in audit['files']]
    metadata_files=[out/'audit_manifest.json',out/'branch_decision.json',out/'receipt_scope_flags.csv',out/'schema_summary_evidence.csv']
    total=sum(q.stat().st_size for q in planned+metadata_files)
    if total>MAX_BYTES:raise RuntimeError(f'Run snapshot is {total/1024**2:.1f} MiB; exceeds bounded budget. No archive created.')
    if shutil.disk_usage('/kaggle/working').free<total+RESERVE_BYTES:
        raise RuntimeError('Insufficient reserve for bounded snapshot')
    archive=out/('PRIVATE_E2E3_SOURCE_CLOSURE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.zip')
    checks=[]
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_STORED,allowZip64=True) as z:
        for q in planned+metadata_files:
            before=q.stat()
            member=('source_run/'+str(q.relative_to(RUN))) if RUN in q.parents else 'audit/'+q.name
            h=hashlib.sha256()
            with q.open('rb') as src,z.open(member,'w',force_zip64=True) as dst:
                for block in iter(lambda:src.read(4*1024**2),b''):h.update(block);dst.write(block)
            after=q.stat()
            if before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns:
                raise RuntimeError('Source file changed during snapshot: '+str(q))
            checks.append({'member':member,'bytes':after.st_size,'sha256':h.hexdigest()})
        z.writestr('snapshot_member_hashes.json',json.dumps(checks,indent=2))
    with zipfile.ZipFile(archive) as z:
        for row in checks:
            h=hashlib.sha256()
            with z.open(row['member']) as src:
                for block in iter(lambda:src.read(4*1024**2),b''):h.update(block)
            if h.hexdigest()!=row['sha256']:raise RuntimeError('Snapshot member hash mismatch: '+row['member'])
    h=hashlib.sha256()
    with archive.open('rb') as f:
        for block in iter(lambda:f.read(4*1024**2),b''):h.update(block)
    receipt={'status':'PRIVATE_SOURCE_FOLD_SNAPSHOT_VERIFIED','archive':str(archive),
             'archive_bytes':archive.stat().st_size,'archive_sha256':h.hexdigest(),
             'members_verified':len(checks),'source_run':str(RUN),
             'expected_configuration_sha256':EXPECTED_CONFIG,
             'scope':'Source-run files and audit only; external source-panel dependencies remain in their existing locations',
             'contains_private_models_or_records':True,'public_release_approved':False,
             'models_trained':False,'predictions_computed':False,'targets_read':False,'original_files_deleted':False,
             'next_step':'Return audit/configuration and prediction artifact locations; no E4 or held-out execution'}
    (out/'snapshot_receipt.json').write_text(json.dumps(receipt,indent=2))
    print('\n=== VERIFIED SOURCE-FOLD SNAPSHOT ===\n'+json.dumps(receipt,indent=2))
    return str(archive)

E2E3_PRIVATE_SNAPSHOT=main()
