"""Rebuild missing Group B from actual publisher documents and frozen model schema.
No fabricated quotations, regex-only semantic approval, capture synthesis or training.
Exact feature-definition table/line excerpts are retained with document SHA256.
Found excerpts are NOT equivalent to human-reviewed provenance/attack approval.
"""
import hashlib
import io
import json
import re
import subprocess
import sys
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import requests
try:
    from bs4 import BeautifulSoup
except ImportError:
    subprocess.check_call([sys.executable,'-m','pip','install','--quiet','beautifulsoup4'])
    from bs4 import BeautifulSoup

ROOT=Path('/kaggle/working')
BASE=ROOT/'fresh_all_datasets_v1'
OUT=ROOT/'group_B_verified_document_excerpts_v2'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
SOURCES={
 'CICIoT2023':[
    ('published_article','https://pmc.ncbi.nlm.nih.gov/articles/PMC10346235/'),
    ('official_dataset_page','https://www.unb.ca/cic/datasets/iotdataset-2023.html')],
 'CICIoMT2024':[
    ('official_dataset_page','https://www.unb.ca/cic/datasets/iomt-dataset-2024.html'),
    ('published_article','https://www.sciencedirect.com/science/article/pii/S2542660524002920')],
 'CSE':[
    ('extractor_documentation','https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/ReadMe.txt')],
 'NSL':[
    ('KDD_feature_dictionary','https://kdd.ics.uci.edu/databases/kddcup99/task.html'),
    ('NSL_official_dataset_page','https://www.unb.ca/cic/datasets/nsl.html')],
 'TONIoT':[
    ('official_dataset_page','https://research.unsw.edu.au/projects/toniot-datasets')],
}
# Spelling/abbreviation equivalences only, never cross-dataset definitions.
ALIASES={
 'magnitue':'magnitude','protocoltype':'protocoltype',
 'minpacketlength':'packetlengthmin','maxpacketlength':'packetlengthmax',
 'fwdpktlenmax':'fwdpacketlengthmax','fwdpktlenmin':'fwdpacketlengthmin',
 'fwdpktlenmean':'fwdpacketlengthmean','fwdpktlenstd':'fwdpacketlengthstd',
 'bwdpktlenmax':'bwdpacketlengthmax','bwdpktlenmin':'bwdpacketlengthmin',
 'bwdpktlenmean':'bwdpacketlengthmean','bwdpktlenstd':'bwdpacketlengthstd',
 'pktlenmin':'packetlengthmin','pktlenmax':'packetlengthmax',
 'pktlenmean':'packetlengthmean','pktlenstd':'packetlengthstd',
 'pktlenvar':'packetlengthvariance',
}
MAX_DOCUMENT_BYTES=20*1024**2
EXPECTED={
 'CICIoT2023':'29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88',
 'CICIoMT2024':'7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473',
 'CSE':'df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3',
 'NSL':'cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29',
 'TONIoT':'bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf'}


def sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as handle:
        for block in iter(lambda:handle.read(8*1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def normalized(value):
    return ''.join(character for character in str(value).lower() if character.isalnum())


def canonical(value):
    value=normalized(value)
    return ALIASES.get(value,value)


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def retrieve(dataset,role,url):
    name=hashlib.sha256(url.encode()).hexdigest()[:16]
    directory=OUT/'documents'/dataset;directory.mkdir(parents=True,exist_ok=True)
    payload_path=directory/f'{name}.source'
    receipt_path=directory/f'{name}.json'
    if payload_path.exists() and receipt_path.exists():
        receipt=json.loads(receipt_path.read_text())
        if sha(payload_path)!=receipt['document_sha256']:raise AssertionError('Cached publisher document changed.')
        return payload_path.read_bytes(),receipt
    with requests.get(url,timeout=(20,90),stream=True) as response:
        response.raise_for_status()
        chunks=[];total=0
        for chunk in response.iter_content(1024*1024):
            total+=len(chunk)
            if total>MAX_DOCUMENT_BYTES:raise RuntimeError('Document exceeded size limit.')
            chunks.append(chunk)
        payload=b''.join(chunks)
        content_type=response.headers.get('Content-Type','')
    text=payload.decode('utf-8',errors='replace')
    soup=BeautifulSoup(text,'html.parser')
    title=soup.title.get_text(' ',strip=True) if soup.title else role
    if re.search(r'^(access denied|just a moment|captcha|verify you are human)',title,re.I):
        raise RuntimeError('Access-challenge page, not documentary evidence.')
    if len(payload)<100:raise RuntimeError('Document response too short.')
    payload_path.write_bytes(payload)
    receipt={'dataset':dataset,'role':role,'source_url':url,'document_title':title,
             'document_sha256':sha(payload_path),'document_bytes':len(payload),
             'retrieved_utc':datetime.now(timezone.utc).isoformat(),'content_type':content_type,
             'status':'DOCUMENT_RETRIEVED_CONTENT_NOT_YET_HUMAN_APPROVED'}
    receipt_path.write_text(json.dumps(receipt,indent=2))
    return payload,receipt


def definition_rows(payload,receipt):
    text=payload.decode('utf-8',errors='replace')
    soup=BeautifulSoup(text,'html.parser')
    records=[]
    for table_index,table in enumerate(soup.find_all('table')):
        rows=table.find_all('tr')
        header=' '.join(row.get_text(' ',strip=True) for row in rows[:2]).lower()
        if not (any(word in header for word in ['description','definition','meaning'])
                and any(word in header for word in ['feature','attribute','field','name'])):
            continue
        for row_index,row in enumerate(rows):
            cells=[cell.get_text(' ',strip=True) for cell in row.find_all(['th','td'])]
            if len(cells)<2:continue
            if canonical(cells[0]) in ['feature','featurename','attribute','name','field']:continue
            records.append({**receipt,'document_feature':cells[0],
                            'definition_text':' | '.join(cells[1:]),
                            'exact_quote':' | '.join(cells),'locator':f'HTML table {table_index}, row {row_index}',
                            'definition_format':'feature_definition_table'})
    if receipt['role']=='extractor_documentation':
        # Plain-text extractor README. Match feature-name first fields only.
        for index,line in enumerate(text.splitlines()):
            line=line.strip().strip('|').strip()
            parts=re.split(r'\t+|\s*\|\s*|\s*:\s*',line,maxsplit=1)
            if len(parts)==2 and parts[0] and parts[1]:
                records.append({**receipt,'document_feature':parts[0],
                    'definition_text':parts[1],'exact_quote':line,'locator':f'text line {index+1}',
                    'definition_format':'extractor_readme_line'})
    return records


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    recovery=ROOT/'runtime_recovery_verification_v1'/'recovery_receipt.json'
    if not recovery.exists() or not json.loads(recovery.read_text()).get('five_bundle_recovery_verified'):
        raise RuntimeError('Verified recovery receipt missing or unsuccessful.')
    source_records=[];definitions=[];ledger=[];profiles=[]
    for dataset in DATASETS:
        for role,url in SOURCES[dataset]:
            try:
                payload,receipt=retrieve(dataset,role,url)
                source_records.append(receipt)
                definitions.extend(definition_rows(payload,receipt))
                print(dataset,role,'ACTUAL DOCUMENT SAVED',flush=True)
            except Exception as error:
                source_records.append({'dataset':dataset,'role':role,'source_url':url,
                                       'status':'RETRIEVAL_FAILED_OR_UNUSABLE','detail':str(error)})
                print(dataset,role,'not retrieved:',str(error),flush=True)
        bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
        if sha(bundle_path)!=EXPECTED[dataset]:raise AssertionError(f'{dataset}: frozen bundle changed.')
        bundle=joblib.load(bundle_path)
        current_views={feature:view for view,features in bundle['semantic_views'].items() for feature in features}
        encoding=bundle.get('encoding',{})
        for feature in bundle['primary_features']:
            raw=feature.split('__category_')[0]
            matches=[row for row in definitions
                     if row['dataset']==dataset and canonical(row['document_feature'])==canonical(raw)]
            # Do not choose between conflicting descriptions automatically.
            descriptions=sorted(set(row['definition_text'] for row in matches))
            chosen=matches[0] if len(descriptions)==1 else None
            quote=chosen['exact_quote'] if chosen else ''
            duration_flag=''
            if normalized(raw)=='duration':
                if chosen and re.search(r'\bttl\b|time\s*[- ]?to\s*[- ]?live',quote,re.I):
                    duration_flag='SOURCE_SAYS_TTL: REVIEW_CURRENT_TIMING_VIEW; NO_TIMING_ACTION_APPROVED'
                elif not chosen:
                    duration_flag='DURATION_UNRESOLVED: DO_NOT_INFER_SECONDS_OR_TTL_FROM_NAME'
            status=('EXACT_DEFINITION_EXCERPT_FOUND_REVIEW_REQUIRED' if chosen else
                    'CONFLICTING_DEFINITION_EXCERPTS_REVIEW_REQUIRED' if matches else
                    'NO_EXACT_DEFINITION_EXCERPT_FOUND')
            ledger.append({'dataset':dataset,'model_feature':feature,'raw_feature':raw,
                'current_semantic_view':current_views.get(feature,'primary_only'),
                'currently_mutable':int(feature in bundle['mutable_columns']),
                'encoding_kind':encoding.get(raw,{}).get('kind','unknown'),
                'definition_status':status,'matching_excerpts':len(matches),
                'official_definition_source':chosen['source_url'] if chosen else '',
                'official_definition_quote':quote,
                'document_sha256':chosen['document_sha256'] if chosen else '',
                'source_locator':chosen['locator'] if chosen else '',
                'duration_semantics_alert':duration_flag,
                'final_primitive_source':'REVIEW_REQUIRED','final_derived_from':'REVIEW_REQUIRED',
                'final_validity_rule':'REVIEW_REQUIRED','recomputation_formula_verified':False,
                'extractor_version_pinned':False,'capture_to_row_mapping_verified':False,
                'reviewer_initials':'','approved_for_confirmatory_attack':False})
            if '__category_' not in feature:
                values=pd.to_numeric(bundle['train_df'][feature],errors='coerce').to_numpy(dtype=float)
                values=values[np.isfinite(values)]
                profiles.append({'dataset':dataset,'feature':feature,'finite_training_values':len(values),
                    'training_min':float(values.min()) if len(values) else np.nan,
                    'training_median':float(np.median(values)) if len(values) else np.nan,
                    'training_max':float(values.max()) if len(values) else np.nan,
                    'observed_integer_fraction':float(np.isclose(values,np.round(values),atol=1e-8).mean()) if len(values) else np.nan,
                    'interpretation':'Observed values are not proof of physical units or mutability'})
    save_csv(source_records,OUT/'source_retrieval_results.csv')
    save_csv(definitions,OUT/'all_actual_definition_excerpts.csv')
    result=pd.DataFrame(ledger)
    save_csv(result,OUT/'feature_definition_evidence.csv')
    save_csv(profiles,OUT/'training_only_numeric_feature_profiles.csv')
    summary=result.groupby(['dataset','definition_status']).size().rename('model_features').reset_index()
    save_csv(summary,OUT/'definition_coverage_summary.csv')
    alerts=result[result.duration_semantics_alert!='']
    save_csv(alerts,OUT/'duration_semantics_alerts.csv')
    a1=ROOT/'group_A1_development_source_freeze_v1'/'A1_freeze_receipt.json'
    protocol={'group':'B','phase':'Actual field-definition excerpt retrieval after recovery',
              'A1_receipt_present':a1.exists(),'models_retrained':False,'data_modified':False,
              'source_quotes':'Copied from successfully retrieved definition tables/README lines, never synthesized',
              'review_rule':'Exact text match is evidence, not automatic approval',
              'no_cross_dataset_definition_transfer':True,
              'limitations':['CICFlowMeter documentation version may differ from the dataset extractor',
                             'KDD documentation is inherited context for NSL, not raw-packet mapping',
                             'Dataset overview pages may not contain field-level definitions',
                             'Missing/conflicting definitions remain unresolved',
                             'Numeric profiles do not establish units or primitive control'],
              'group_B_complete':False,'group_C_approved':False}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    print('\nACTUAL DEFINITION COVERAGE\n'+summary.to_string(index=False),flush=True)
    print('\nDURATION SEMANTICS ALERTS\n'+alerts[['dataset','model_feature','definition_status','duration_semantics_alert']].to_string(index=False),flush=True)
    print('\nA1 receipt present:',a1.exists())
    print('No attacks approved. Next decision must inspect actual quotations, formulas and capture linkage.')
    return summary

if __name__=='__main__':
    SOURCE_DEFINITION_STATUS=main()
