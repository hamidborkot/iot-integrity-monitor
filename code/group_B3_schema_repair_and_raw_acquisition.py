"""Group B3: fix NSL headerless schema validation, harvest authentic source evidence,
find captures including archive members, and obtain at most one small direct public
capture per dataset where an actual publisher-linked URL is discoverable.
Never bypass registration/login, invent URLs/traffic/labels, or approve Group C.
"""
import base64
import gzip
import hashlib
import json
import re
import shutil
import tarfile
import traceback
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urljoin,urlparse,quote
import joblib
import numpy as np
import pandas as pd
import requests

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup=None

ROOT=Path('/kaggle/working')
BASE=ROOT/'fresh_all_datasets_v1'
B1=ROOT/'group_B1_feature_provenance_evidence_v1'
OUT=ROOT/'group_B3_source_evidence_and_capture_acquisition_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
AUTO_DOWNLOAD_SMALL_PUBLIC_CAPTURE=True
MAX_CAPTURE_BYTES=128*1024*1024
MAX_DOWNLOADS_PER_DATASET=1
MAX_REMOTE_LINKS_PER_DATASET=30
MAX_ARCHIVE_MEMBERS=100000
TIMEOUT=(10,30)
SOURCES={
 'CICIoT2023':['https://www.unb.ca/cic/datasets/iotdataset-2023.html',
               'https://pmc.ncbi.nlm.nih.gov/articles/PMC10346235/'],
 'CICIoMT2024':['https://www.unb.ca/cic/datasets/iomt-dataset-2024.html'],
 'CSE':['https://www.unb.ca/cic/datasets/ids-2018.html',
        'https://registry.opendata.aws/cse-cic-ids2018/',
        'https://api.github.com/repos/ahlashkari/CICFlowMeter/contents/ReadMe.txt?ref=master'],
 'NSL':['https://kdd.ics.uci.edu/databases/kddcup99/task.html'],
 'TONIoT':['https://research.unsw.edu.au/projects/toniot-datasets']}
MARKERS={'CICIoT2023':['ciciot2023','ciciot23'],
         'CICIoMT2024':['ciciomt','cic-iomt'],
         'CSE':['csecicids2018','cse-cic-ids2018','cicids2018'],
         'NSL':['nsl-kdd','nslkdd'],'TONIoT':['toniot','ton-iot']}
NSL_COLUMNS=[
 'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot',
 'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations',
 'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count',
 'serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate',
 'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
 'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
 'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty']
CAPTURE_SUFFIXES=('.pcap','.pcapng','.cap','.pcap.gz','.pcapng.gz','.cap.gz')
PCAP_MAGIC={b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'}


def norm(value): return ''.join(c for c in str(value).lower() if c.isalnum())


def save_csv(rows,path,columns=None):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows,columns=columns)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def candidates_for_path(path):
    return [dataset for dataset,markers in MARKERS.items()
            if any(marker in str(path).lower() for marker in markers)]


def capture_name(value):
    return urlparse(str(value)).path.lower().endswith(CAPTURE_SUFFIXES)


def nsl_schema_sample(path):
    # Only canonical KDD data files, not README/field-description/attack-name files.
    if not re.match(r'^(kddtrain|kddtest)',path.name.lower()):return None
    if path.suffix.lower() not in ['.txt','.csv']:return None
    sample=pd.read_csv(path,header=None,nrows=5,low_memory=False)
    if sample.shape[1] not in [42,43]:return None
    if norm(sample.iloc[0,0])=='duration':sample=sample.iloc[1:].copy()
    if sample.empty:return None
    if not pd.to_numeric(sample.iloc[:,0],errors='coerce').notna().all():return None
    if not sample.iloc[:,1].astype(str).str.lower().isin(['tcp','udp','icmp']).all():return None
    sample.columns=NSL_COLUMNS[:sample.shape[1]]
    return sample


def verify_nsl_real_record(bundle):
    source=bundle['source_test_df'].copy()
    source['_row_id']=source['_row_id'].astype(str)
    locations=source['_row_id'].str.rsplit(':',n=1,expand=True)
    locations.columns=['filename','raw_position'];locations['raw_position']=pd.to_numeric(locations['raw_position'],errors='raise')
    locations['source_position']=np.arange(len(source))
    verified=[]
    for filename,group in locations.groupby('filename'):
        location=group.sort_values('raw_position').iloc[0]
        paths=[path for path in Path('/kaggle/input').rglob(filename)
               if path.is_file() and candidates_for_path(path)==['NSL']]
        if not paths:raise FileNotFoundError(f'Raw NSL source file absent: {filename}')
        path=min(paths,key=lambda p:len(str(p)))
        raw=pd.read_csv(path,header=None,nrows=int(location.raw_position)+1)
        if raw.shape[1] not in [42,43]:raise ValueError('Unexpected raw NSL layout.')
        raw.columns=NSL_COLUMNS[:raw.shape[1]]
        record=raw.iloc[int(location.raw_position)]
        encoded=source.iloc[int(location.source_position)]
        count=0
        for feature,specification in bundle['encoding'].items():
            if specification['kind']=='numeric':
                observed=pd.to_numeric(pd.Series([record[feature]]),errors='coerce').iloc[0]
                if not np.isclose(observed,encoded[feature],atol=1e-7,rtol=1e-7,equal_nan=True):
                    raise AssertionError(f'NSL raw/encoded numeric mismatch: {feature}')
                count+=1
            else:
                value='__MISSING__' if pd.isna(record[feature]) else str(record[feature])
                for index,category in enumerate(specification['categories']):
                    if encoded[f'{feature}__category_{index}']!=float(value==category):
                        raise AssertionError(f'NSL one-hot mismatch: {feature}')
                    count+=1
        expected=int(str(record['label']).strip().lower().rstrip('.')!='normal')
        if expected!=int(encoded.label):raise AssertionError('NSL binary-label mapping mismatch.')
        verified.append({'dataset':'NSL','file':str(path),'raw_position':int(location.raw_position),
                         'checked_encoded_features':count,'status':'REAL_RAW_TO_ENCODED_RECORD_MATCH'})
    return verified


def source_document(session,dataset,url):
    response=session.get(url,timeout=TIMEOUT)
    response.raise_for_status()
    if len(response.content)>20*1024*1024:raise ValueError('Source-document download unexpectedly large.')
    text=response.text
    content_type=response.headers.get('Content-Type','')
    if 'api.github.com' in url:
        data=response.json()
        if data.get('encoding')!='base64':raise ValueError('Unexpected GitHub source response.')
        content=base64.b64decode(data['content'])
        text=content.decode('utf-8',errors='replace');content_type='text/plain; GitHub contents API'
    else:content=response.content
    lower=text[:10000].lower()
    if any(marker in lower for marker in ['access denied','verify you are human','captcha','just a moment...']):
        raise RuntimeError('Access/anti-bot page returned; no bypass attempted.')
    name=hashlib.sha256(url.encode()).hexdigest()[:12]
    path=OUT/'source_documents'/dataset/f'{name}.source'
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
    links=[];tables=[]
    if BeautifulSoup is not None and 'html' in content_type.lower():
        soup=BeautifulSoup(text,'html.parser')
        links=[(urljoin(response.url,a.get('href','')),a.get_text(' ',strip=True))
               for a in soup.find_all('a',href=True)]
        for table in soup.find_all('table'):
            for row in table.find_all('tr'):
                cells=[cell.get_text(' ',strip=True) for cell in row.find_all(['td','th'])]
                if len(cells)>=2:tables.append(cells)
    return {'dataset':dataset,'requested_url':url,'resolved_url':response.url,
            'local_source':str(path),'source_sha256':sha(path),'status':'SOURCE_BYTES_ARCHIVED'},links,tables,text


def small_public_capture(session,dataset,url,known_size=None):
    if not capture_name(url):raise ValueError('URL is not a direct named capture; archives/forms are not downloaded automatically.')
    if known_size is not None and known_size>MAX_CAPTURE_BYTES:
        return {'dataset':dataset,'url':url,'status':'SKIPPED_SIZE_LIMIT','bytes':known_size}
    if shutil.disk_usage(OUT).free<MAX_CAPTURE_BYTES+100*1024*1024:
        return {'dataset':dataset,'url':url,'status':'SKIPPED_DISK_LIMIT','bytes':0}
    path=OUT/'raw_capture_pilots'/dataset/(hashlib.sha256(url.encode()).hexdigest()[:12]+'_'+Path(urlparse(url).path).name)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.part')
    try:
        with session.get(url,stream=True,timeout=TIMEOUT) as response:
            response.raise_for_status()
            if 'text/html' in response.headers.get('Content-Type','').lower():
                raise ValueError('HTML/login/form response, not a capture.')
            length=response.headers.get('Content-Length')
            declared=int(length) if length and length.isdigit() else None
            if declared is not None and declared>MAX_CAPTURE_BYTES:
                return {'dataset':dataset,'url':url,'status':'SKIPPED_SIZE_LIMIT','bytes':declared}
            received=0
            with open(temporary,'wb') as f:
                for block in response.iter_content(chunk_size=1024*1024):
                    if not block:continue
                    received+=len(block)
                    if received>MAX_CAPTURE_BYTES:raise ValueError('Size limit exceeded; partial capture discarded.')
                    f.write(block)
            if declared is not None and received!=declared:raise ValueError('Incomplete download: Content-Length mismatch.')
        if temporary.name.lower().endswith('.gz.part'):
            with gzip.open(temporary,'rb') as f:magic=f.read(4)
        else:
            with open(temporary,'rb') as f:magic=f.read(4)
        if magic not in PCAP_MAGIC:raise ValueError('Recognized PCAP/PCAPNG magic not found.')
        temporary.replace(path)
        return {'dataset':dataset,'url':url,'status':'COMPLETE_CAPTURE_DOWNLOADED_HEADER_RECOGNIZED',
                'bytes':received,'local_path':str(path),'sha256':sha(path),
                'trace_to_frozen_CSV_mapping_verified':False,'packet_semantic_validity_verified':False}
    except Exception:
        if temporary.exists():temporary.unlink()
        raise


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    ledger=pd.read_csv(B1/'feature_provenance_evidence_LEDGER.csv')
    session=requests.Session()
    session.headers.update({'User-Agent':'ResearchProvenanceAudit/1.0 (read-only source retrieval)'})
    nsl_rows=[];nsl_union=set();capture_inventory=[];archive_inventory=[];sources=[];failures=[];links=[];definitions=[];downloads=[]
    for path in Path('/kaggle/input').rglob('*'):
        if not path.is_file() or path.is_symlink():continue
        datasets=candidates_for_path(path)
        if capture_name(path.name):
            capture_inventory.append({'container':str(path),'member':'','dataset_candidates':'|'.join(datasets) or 'UNASSIGNED',
                                      'bytes':path.stat().st_size,'status':'LOCAL_CAPTURE_FOUND_NOT_MAPPED'})
        if datasets==['NSL']:
            try:
                sample=nsl_schema_sample(path)
                if sample is not None:
                    nsl_union.update(sample.columns)
                    nsl_rows.append({'file':str(path),'raw_columns':len(sample.columns),
                                     'predictor_columns_present':len(set(NSL_COLUMNS[:41])&set(sample.columns)),
                                     'status':'CANONICAL_HEADERLESS_KDD_LAYOUT_VALIDATED_ON_REAL_ROWS'})
            except Exception as error:failures.append({'dataset':'NSL','stage':'raw_schema','url_or_path':str(path),'error':str(error)})
        lower=path.name.lower()
        try:
            if lower.endswith('.zip'):
                with zipfile.ZipFile(path) as z:
                    for item in z.infolist()[:MAX_ARCHIVE_MEMBERS]:
                        if capture_name(item.filename):
                            archive_inventory.append({'container':str(path),'member':item.filename,
                                'dataset_candidates':'|'.join(datasets) or 'UNASSIGNED','uncompressed_bytes':item.file_size,
                                'status':'CAPTURE_MEMBER_FOUND_NOT_EXTRACTED_OR_MAPPED'})
            elif lower.endswith(('.tar','.tar.gz','.tgz')):
                with tarfile.open(path,'r:*') as archive:
                    for index,item in enumerate(archive):
                        if index>=MAX_ARCHIVE_MEMBERS:break
                        if item.isfile() and capture_name(item.name):
                            archive_inventory.append({'container':str(path),'member':item.name,
                                'dataset_candidates':'|'.join(datasets) or 'UNASSIGNED','uncompressed_bytes':item.size,
                                'status':'CAPTURE_MEMBER_FOUND_NOT_EXTRACTED_OR_MAPPED'})
        except Exception as error:failures.append({'dataset':'|'.join(datasets),'stage':'archive_listing','url_or_path':str(path),'error':str(error)})
    nsl_bundle=joblib.load(BASE/'NSL'/'NSL_bundle.joblib')
    expected={str(f).split('__category_')[0] for f in nsl_bundle['primary_features']}
    nsl_missing=sorted(expected-nsl_union)
    save_csv(nsl_rows,OUT/'NSL_corrected_source_schema.csv',columns=['file','raw_columns','predictor_columns_present','status'])
    try:real_nsl_verification=verify_nsl_real_record(nsl_bundle)
    except Exception as error:
        real_nsl_verification=[{'dataset':'NSL','status':'FAILED','error':str(error)}]
    save_csv(real_nsl_verification,OUT/'NSL_actual_raw_encoding_verification.csv')
    (OUT/'NSL_schema_repair_receipt.json').write_text(json.dumps({
        'expected_raw_features':len(expected),'matched_canonical_raw_features':len(expected&nsl_union),
        'missing_raw_features':nsl_missing,'raw_capture_mapping_verified':False,
        'correction':'Headerless KDD data were previously excluded from named-schema matching'},indent=2))
    for dataset,urls in SOURCES.items():
        raw_features=sorted(set(ledger.loc[ledger.dataset==dataset,'raw_feature'].astype(str)))
        for url in urls:
            try:
                receipt,found_links,table_rows,text=source_document(session,dataset,url)
                sources.append(receipt)
                for cells in table_rows:
                    for feature in raw_features:
                        if any(norm(cell)==norm(feature) for cell in cells[:2]):
                            definitions.append({'dataset':dataset,'raw_feature':feature,'source_url':receipt['resolved_url'],
                                'source_sha256':receipt['source_sha256'],'verbatim_table_row':' | '.join(cells),
                                'definition_status':'EXACT_NAME_TABLE_EVIDENCE_EXTRACTOR_MATCH_NOT_VERIFIED',
                                'approved_for_attack':False})
                for link,label in found_links:
                    low=(link+' '+label).lower()
                    if any(word in low for word in ['download','pcap','capture','dataset','github','cloudstor','drive.google']):
                        links.append({'dataset':dataset,'url':link,'anchor_text':label,'discovered_on':receipt['resolved_url'],
                                      'direct_capture':capture_name(link),'declared_bytes':np.nan})
            except Exception as error:failures.append({'dataset':dataset,'stage':'official_source','url_or_path':url,'error':str(error)})
        print(dataset,'OFFICIAL SOURCE EVIDENCE RETRIEVAL FINISHED',flush=True)
    # The official AWS registry identifies this public bucket and region.
    # This lists metadata only; it does NOT sync/download the complete dataset.
    try:
        endpoint='https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/'
        response=session.get(endpoint,params={'list-type':'2','max-keys':'1000'},timeout=TIMEOUT)
        response.raise_for_status();tree=ET.fromstring(response.content)
        for item in tree.findall('.//{*}Contents'):
            key=item.findtext('{*}Key');size=item.findtext('{*}Size')
            if key and capture_name(key):
                links.append({'dataset':'CSE','url':endpoint+quote(key,safe='/'),'anchor_text':key,
                              'discovered_on':'https://registry.opendata.aws/cse-cic-ids2018/',
                              'direct_capture':True,'declared_bytes':int(size) if size else np.nan})
    except Exception as error:failures.append({'dataset':'CSE','stage':'public_S3_metadata','url_or_path':'public cse-cic-ids2018 bucket','error':str(error)})
    if AUTO_DOWNLOAD_SMALL_PUBLIC_CAPTURE:
        for dataset in DATASETS:
            candidates=[r for r in links if r['dataset']==dataset and r['direct_capture']]
            # Prefer verified-small objects. Unknown sizes still have a strict streaming cap.
            candidates=sorted(candidates,key=lambda r:float(r['declared_bytes']) if pd.notna(r['declared_bytes']) else float('inf'))
            success=0;seen=set()
            for candidate in candidates[:MAX_REMOTE_LINKS_PER_DATASET]:
                if candidate['url'] in seen:continue
                seen.add(candidate['url'])
                try:
                    known=int(candidate['declared_bytes']) if pd.notna(candidate['declared_bytes']) else None
                    result=small_public_capture(session,dataset,candidate['url'],known)
                    downloads.append(result)
                    if result['status']=='COMPLETE_CAPTURE_DOWNLOADED_HEADER_RECOGNIZED':success+=1
                    if success>=MAX_DOWNLOADS_PER_DATASET:break
                except Exception as error:failures.append({'dataset':dataset,'stage':'bounded_capture_download',
                                                           'url_or_path':candidate['url'],'error':str(error)})
            if success==0:
                downloads.append({'dataset':dataset,'status':'NO_SMALL_PUBLIC_DIRECT_CAPTURE_ACQUIRED',
                                  'bytes':0,'next_action':'Use publisher access/download links; registration, large archives, and manual permissions are not bypassed.'})
    save_csv(capture_inventory,OUT/'local_capture_inventory.csv',columns=['container','member','dataset_candidates','bytes','status'])
    save_csv(archive_inventory,OUT/'captures_inside_input_archives.csv',columns=['container','member','dataset_candidates','uncompressed_bytes','status'])
    save_csv(sources,OUT/'archived_official_source_receipts.csv',columns=['dataset','requested_url','resolved_url','local_source','source_sha256','status'])
    save_csv(definitions,OUT/'verbatim_feature_table_evidence.csv',columns=['dataset','raw_feature','source_url','source_sha256','verbatim_table_row','definition_status','approved_for_attack'])
    save_csv(links,OUT/'publisher_download_and_extractor_links.csv',columns=['dataset','url','anchor_text','discovered_on','direct_capture','declared_bytes'])
    save_csv(downloads,OUT/'bounded_capture_acquisition_results.csv')
    save_csv(failures,OUT/'retrieval_errors.csv',columns=['dataset','stage','url_or_path','error'])
    corrections=ledger.copy()
    # Withdraw unsupported blanket Duration semantics; only an actual quoted
    # feature-definition row may support a dataset-specific TTL/time interpretation.
    for dataset in ['CICIoT2023','CICIoMT2024']:
        mask=corrections.dataset.eq(dataset)&corrections.raw_feature.map(norm).eq('duration')
        matches=[r for r in definitions if r['dataset']==dataset and norm(r['raw_feature'])=='duration']
        corrections.loc[mask,'B3_duration_semantics_status']=('VERBATIM_DEFINITION_FOUND_REVIEW_REQUIRED' if matches
                                                           else 'UNVERIFIED_DO_NOT_TREAT_AS_PACING_OR_TTL')
    corrections['approved_for_confirmatory_attack']=False
    save_csv(corrections,OUT/'B1_candidate_ledger_with_B3_corrections.csv')
    protocol={
        'tasks':['Headerless NSL schema repair and actual encoding check','Authentic official source snapshots',
                 'Capture inventory including archive members','Bounded public pilot acquisition where available'],
        'automatic_download_limit_per_file_bytes':MAX_CAPTURE_BYTES,
        'automatic_download_limit_per_dataset':MAX_DOWNLOADS_PER_DATASET,
        'no_bypass':['No login/registration bypass','No disabled TLS verification','No full AWS sync'],
        'no_synthetic_records_or_labels':True,'models_and_data_bundles_modified':False,
        'source_scope':'Captured bytes/table excerpts are evidence for review, not automatic semantic/attack approval',
        'remaining':'An acquired pilot still needs exact CSV lineage, compatible extractor settings and reproduction validation',
        'Group_C_ready':False}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nNSL SCHEMA REPAIR\n'+json.dumps(json.loads((OUT/'NSL_schema_repair_receipt.json').read_text()),indent=2),flush=True)
    print('\nREAL NSL ENCODING VERIFICATION\n'+pd.DataFrame(real_nsl_verification).to_string(index=False),flush=True)
    print('\nCAPTURE ACQUISITION\n'+pd.DataFrame(downloads).to_string(index=False),flush=True)
    print('\nFILES SAVED\n'+str(OUT),flush=True)
    return {'NSL_raw_schema_missing_features':nsl_missing,
            'source_documents_archived':len(sources),'exact_name_feature_table_rows':len(definitions),
            'local_captures_found':len(capture_inventory),'capture_archive_members_found':len(archive_inventory),
            'capture_download_results':downloads,'Group_C_ready':False}

if __name__=='__main__':
    B3_STATUS=main()
