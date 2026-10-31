"""Fix field-definition extraction without inventing definitions or bypassing 403.
Inspect cached responses, search exact feature cells anywhere in definition tables,
use an authorized OA XML copy of the CICIoT2023 paper and a separately labelled
IoMT author preprint, and discover local TON feature-description files.
No models/data/labels are modified. No primitive attacks are approved.
"""
import hashlib
import json
import re
import zipfile
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import urlparse
import joblib
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup

ROOT=Path('/kaggle/working')
BASE=ROOT/'fresh_all_datasets_v1'
PREVIOUS=ROOT/'group_B_verified_document_excerpts_v2'
OUT=ROOT/'group_B_definition_parser_repair_v3'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
MAX_BYTES=25*1024**2
ALIASES={'magnitue':'magnitude','minpacketlength':'packetlengthmin','maxpacketlength':'packetlengthmax',
         'fwdpktlenmin':'fwdpacketlengthmin','fwdpktlenmax':'fwdpacketlengthmax',
         'fwdpktlenmean':'fwdpacketlengthmean','fwdpktlenstd':'fwdpacketlengthstd',
         'bwdpktlenmin':'bwdpacketlengthmin','bwdpktlenmax':'bwdpacketlengthmax',
         'bwdpktlenmean':'bwdpacketlengthmean','bwdpktlenstd':'bwdpacketlengthstd',
         'pktlenmin':'packetlengthmin','pktlenmax':'packetlengthmax',
         'pktlenmean':'packetlengthmean','pktlenstd':'packetlengthstd','pktlenvar':'packetlengthvariance'}
TYPE_WORDS={'continuous','categorical','binary','float','int','integer','numeric','real','string','discrete'}


def norm(value):
    key=re.sub(r'[^a-z0-9]','',str(value).lower())
    return ALIASES.get(key,key)


def sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as handle:
        for block in iter(lambda:handle.read(8*1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def save_csv(rows,path,columns=None):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows,columns=columns)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def definition_like(value):
    return len(value.strip())>=8 and bool(re.search(r'[a-zA-Z]',value)) and norm(value) not in TYPE_WORDS


def feature_names(cell,expected):
    if norm(cell) in expected:return [expected[norm(cell)]]
    # Explicit grouped names only; never substring-match prose/formulas.
    parts=re.split(r'[,;\n]+',cell)
    return list(dict.fromkeys(expected[norm(part)] for part in parts if norm(part) in expected))


def parse_tables(text,meta,expected):
    soup=BeautifulSoup(text,'html.parser')
    records=[]
    tables=soup.find_all('table')
    for table_index,table in enumerate(tables):
        caption=table.find('caption')
        parent=table.find_parent(['table-wrap','figure','section'])
        context=(caption.get_text(' ',strip=True) if caption else '')
        if parent is not None and not context:
            label=parent.find(['caption','figcaption','h3','h4'])
            if label:context=label.get_text(' ',strip=True)
        all_rows=table.find_all('tr')
        pairs=[]
        for row_index,row in enumerate(all_rows):
            if row.find_parent('thead') is not None:continue
            cells=[cell.get_text(' ',strip=True) for cell in row.find_all(['td','th'],recursive=False)]
            if len(cells)<2:continue
            for cell_index,cell in enumerate(cells[:-1]):
                matched=feature_names(cell,expected)
                if not matched:continue
                tail=' | '.join(cells[cell_index+1:])
                if not definition_like(tail):continue
                for raw in matched:
                    pairs.append((raw,row_index,cells,tail))
        # Definition-header evidence OR at least three exact feature-name rows.
        header=' '.join(row.get_text(' ',strip=True) for row in all_rows[:2]).lower()
        clearly_definition=any(word in (header+' '+context.lower()) for word in ['description','definition','extracted features'])
        distinct=len({pair[0] for pair in pairs})
        if not clearly_definition and distinct<3:continue
        for raw,row_index,cells,tail in pairs:
            records.append({**meta,'raw_feature':raw,'definition_text':tail,
                            'exact_quote':' | '.join(cells),
                            'locator':f'table {table_index}, row {row_index}',
                            'table_context':context,'matching_method':'exact feature cell; descriptive cells to its right'})
    return records,len(tables)


def parse_plain(text,meta,expected):
    records=[]
    for index,line in enumerate(text.splitlines()):
        stripped=line.strip().strip('|').strip()
        parts=re.split(r'\t+|\s*\|\s*|\s*:\s*|\s*;\s*',stripped,maxsplit=1)
        if len(parts)==2:
            names=feature_names(parts[0],expected)
            if names and definition_like(parts[1]):
                for raw in names:
                    records.append({**meta,'raw_feature':raw,'definition_text':parts[1],
                                    'exact_quote':stripped,'locator':f'text line {index+1}',
                                    'table_context':'','matching_method':'anchored feature-name line'})
    return records


def download(dataset,url,scope,required_marker=None):
    directory=OUT/'additional_sources'/dataset;directory.mkdir(parents=True,exist_ok=True)
    stem=hashlib.sha256(url.encode()).hexdigest()[:16]
    path=directory/f'{stem}.source'
    receipt=directory/f'{stem}.json'
    if path.exists() and receipt.exists():
        meta=json.loads(receipt.read_text())
        if sha(path)!=meta['document_sha256']:raise AssertionError('Cached additional source changed.')
        return path.read_text(encoding='utf-8',errors='replace'),meta
    with requests.get(url,stream=True,timeout=(20,90)) as response:
        if response.status_code!=200:raise RuntimeError(f'HTTP {response.status_code}; no access controls bypassed')
        chunks=[];total=0
        for chunk in response.iter_content(1024*1024):
            total+=len(chunk)
            if total>MAX_BYTES:raise RuntimeError('Document size limit exceeded.')
            chunks.append(chunk)
        payload=b''.join(chunks)
    text=payload.decode('utf-8',errors='replace')
    if required_marker and required_marker.lower() not in text.lower():
        raise ValueError('Alternate source does not contain the expected article identity.')
    if re.search(r'<title>\s*(access denied|just a moment|checking your browser|captcha)',text,re.I):
        raise RuntimeError('Browser/access challenge, not article content.')
    path.write_bytes(payload)
    meta={'dataset':dataset,'source_url':url,'source_scope':scope,
          'document_sha256':sha(path),'document_path':str(path),
          'retrieved_utc':datetime.now(timezone.utc).isoformat()}
    receipt.write_text(json.dumps(meta,indent=2))
    return text,meta


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    old_ledger=PREVIOUS/'feature_definition_evidence.csv'
    if not old_ledger.exists():raise FileNotFoundError('Run the previous Group B definition cell first.')
    ledger=pd.read_csv(old_ledger).fillna('')
    expected={dataset:{norm(raw):raw for raw in ledger.loc[ledger.dataset==dataset,'raw_feature'].unique()}
              for dataset in DATASETS}
    excerpts=[];diagnostics=[]
    for dataset in DATASETS:
        document_dir=PREVIOUS/'documents'/dataset
        for receipt_path in sorted(document_dir.glob('*.json')):
            try:
                receipt=json.loads(receipt_path.read_text())
                source=receipt_path.with_suffix('.source')
                if not source.exists():continue
                if sha(source)!=receipt['document_sha256']:raise AssertionError('Old source hash changed.')
                text=source.read_text(encoding='utf-8',errors='replace')
                soup=BeautifulSoup(text,'html.parser')
                title=soup.title.get_text(' ',strip=True) if soup.title else receipt.get('role','')
                challenge=bool(re.search(r'(checking your browser|just a moment|access denied|verify you are human)',title,re.I))
                meta={'dataset':dataset,'source_url':receipt['source_url'],
                      'source_scope':'previous official/reference source; dataset-extractor alignment still requires review',
                      'document_sha256':sha(source),'document_path':str(source)}
                rows,tables=([],len(soup.find_all('table'))) if challenge else parse_tables(text,meta,expected[dataset])
                if not challenge and receipt.get('role')=='extractor_documentation':
                    rows+=parse_plain(text,meta,expected[dataset])
                excerpts.extend(rows)
                diagnostics.append({'dataset':dataset,'source_url':receipt['source_url'],
                    'document_title':title,'bytes':source.stat().st_size,'tables_detected':tables,
                    'exact_feature_excerpts':len(rows),'challenge_page_detected':challenge,
                    'status':'REPARSED_NOT_APPROVED' if not challenge else 'UNUSABLE_ACCESS_CHALLENGE'})
            except Exception as error:
                diagnostics.append({'dataset':dataset,'source_file':str(receipt_path),'status':'CACHE_PARSE_FAILED','detail':str(error)})
    # Authorized alternate representation of the SAME open-access CICIoT paper.
    alternatives=[
        ('CICIoT2023','https://www.ebi.ac.uk/europepmc/webservices/rest/PMC10346235/fullTextXML',
         'published open-access article via Europe PMC XML','10.3390/s23135941'),
        ('CICIoMT2024','https://www.preprints.org/manuscript/202402.0898',
         'author preprint; agreement with final published/extractor version NOT verified',None)]
    for dataset,url,scope,marker in alternatives:
        try:
            text,meta=download(dataset,url,scope,marker)
            rows,tables=parse_tables(text,meta,expected[dataset]);excerpts.extend(rows)
            diagnostics.append({'dataset':dataset,'source_url':url,'tables_detected':tables,
                                'exact_feature_excerpts':len(rows),'status':'AUTHORIZED_ALTERNATE_PARSED_NOT_APPROVED'})
        except Exception as error:
            diagnostics.append({'dataset':dataset,'source_url':url,'status':'ALTERNATE_UNAVAILABLE','detail':str(error)})
    # Locate existing feature-description material without downloading full datasets.
    local_descriptions=[]
    input_root=Path('/kaggle/input')
    if input_root.exists():
        for path in input_root.rglob('*'):
            if not path.is_file() or path.is_symlink():continue
            name=path.name.lower()
            if any(word in name for word in ['feature','description','dictionary','field names']):
                if path.suffix.lower() in ['.csv','.txt','.html','.htm','.xlsx','.xls','.pdf','.docx']:
                    local_descriptions.append({'path':str(path),'bytes':path.stat().st_size,
                         'sha256':sha(path) if path.stat().st_size<=MAX_BYTES else '',
                         'authority_status':'NOT_VERIFIED_FROM_FILENAME','auto_attack_approval':False})
    # Literal quotes from earlier successfully matched fields are preserved.
    for row in ledger.to_dict('records'):
        if row.get('official_definition_quote') and row.get('official_definition_source'):
            excerpts.append({'dataset':row['dataset'],'raw_feature':row['raw_feature'],
                'source_url':row['official_definition_source'],'source_scope':'previous matched excerpt',
                'document_sha256':row.get('document_sha256',''),'exact_quote':row['official_definition_quote'],
                'definition_text':row['official_definition_quote'],'locator':row.get('source_locator',''),
                'matching_method':'preserved earlier literal match'})
    if excerpts:
        evidence=pd.DataFrame(excerpts).drop_duplicates(['dataset','raw_feature','source_url','exact_quote'])
    else:
        evidence=pd.DataFrame(columns=['dataset','raw_feature','source_url','exact_quote'])
    save_csv(evidence,OUT/'actual_recovered_definition_excerpts.csv')
    save_csv(diagnostics,OUT/'parser_and_source_diagnostics.csv')
    save_csv(pd.DataFrame(local_descriptions,columns=['path','bytes','sha256','authority_status','auto_attack_approval']),
             OUT/'local_feature_description_candidates.csv')
    rows=[]
    for item in ledger.to_dict('records'):
        matches=evidence[(evidence.dataset==item['dataset'])&(evidence.raw_feature==item['raw_feature'])]
        quoted=' '.join(matches.exact_quote.astype(str)) if len(matches) else ''
        alert=''
        if norm(item['raw_feature'])=='duration':
            alert=('LITERAL_SOURCE_MENTIONS_TTL: REVIEW_TIMING_VIEW' if re.search(r'\bttl\b|time\s*[- ]?to\s*[- ]?live',quoted,re.I)
                   else 'UNRESOLVED_DURATION_UNITS' if not quoted else 'DEFINITION_FOUND_UNITS_AND_EXTRACTOR_REVIEW_REQUIRED')
        item.update({'repaired_definition_status':'EXCERPTS_FOUND_REVIEW_REQUIRED' if len(matches) else 'NO_DEFINITION_EVIDENCE',
                     'repaired_excerpt_count':len(matches),'duration_semantics_alert':alert,
                     'approved_for_confirmatory_attack':False,'human_source_review_complete':False})
        rows.append(item)
    repaired=pd.DataFrame(rows)
    save_csv(repaired,OUT/'repaired_feature_definition_ledger.csv')
    summary=repaired.groupby(['dataset','repaired_definition_status']).agg(
        encoded_model_features=('model_feature','size'),distinct_raw_features=('raw_feature','nunique')).reset_index()
    save_csv(summary,OUT/'repaired_definition_coverage.csv')
    instructions={
       'ScienceDirect_403':'Access denial retained; no spoofing, credential bypass or repeated forbidden fetch.',
       'CICIoT2023':'Use source-identity-checked OA XML and robust exact-feature table parsing if available.',
       'CICIoMT2024':'Author preprint evidence must be compared with final paper and actual extractor version.',
       'TONIoT':'Official UNSW page points to Description_stats_datasets for field descriptions; overview alone is not a field dictionary.',
       'NSL':'Report 41 raw predictors separately from 112 encoded model inputs.',
       'approval':'Literal source excerpts do not approve transformations, formulas, capture linkage or Group C.'}
    (OUT/'repair_scope.json').write_text(json.dumps(instructions,indent=2))
    print('\nREPAIRED DEFINITION COVERAGE\n'+summary.to_string(index=False),flush=True)
    print('\nSOURCE / PARSER DIAGNOSTICS\n'+pd.DataFrame(diagnostics).to_string(index=False),flush=True)
    print('\nDURATION ALERTS\n'+repaired[repaired.duration_semantics_alert!=''][
        ['dataset','model_feature','repaired_definition_status','duration_semantics_alert']].to_string(index=False),flush=True)
    print('\nLOCAL DESCRIPTION FILES\n'+pd.DataFrame(local_descriptions).to_string(index=False),flush=True)
    print('\nNo models retrained, no labels changed, and no attacks approved.',flush=True)
    return summary

if __name__=='__main__':
    DEFINITION_REPAIR_STATUS=main()
