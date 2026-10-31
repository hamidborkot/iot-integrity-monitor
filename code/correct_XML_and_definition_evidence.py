"""Group B evidence-quality correction: true XML parsing and numerical-table rejection.
No network requests, training, label changes or attack approval.
Repairs cached definition evidence; a source statistics row documents a field's
reported values, not its semantic definition. Mathematical/preprint conformance
and actual extractor/trace mapping remain separate review requirements.
"""
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import urljoin
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup
try:
    import lxml
except ImportError:
    subprocess.check_call([sys.executable,'-m','pip','install','--quiet','lxml'])
    import lxml

ROOT=Path('/kaggle/working')
PREVIOUS=ROOT/'group_B_definition_parser_repair_v3'
OLDER=ROOT/'group_B_verified_document_excerpts_v2'
OUT=ROOT/'group_B_evidence_quality_correction_v4'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
ALIASES={'magnitue':'magnitude','minpacketlength':'packetlengthmin','maxpacketlength':'packetlengthmax',
         'fwdpktlenmin':'fwdpacketlengthmin','fwdpktlenmax':'fwdpacketlengthmax',
         'fwdpktlenmean':'fwdpacketlengthmean','fwdpktlenstd':'fwdpacketlengthstd',
         'bwdpktlenmin':'bwdpacketlengthmin','bwdpktlenmax':'bwdpacketlengthmax',
         'bwdpktlenmean':'bwdpacketlengthmean','bwdpktlenstd':'bwdpacketlengthstd',
         'pktlenmin':'packetlengthmin','pktlenmax':'packetlengthmax',
         'pktlenmean':'packetlengthmean','pktlenstd':'packetlengthstd','pktlenvar':'packetlengthvariance'}
NUMERIC=re.compile(r'^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?%?$')
TYPE_WORDS={'integer','int','float','real','numeric','continuous','categorical','binary','discrete','string'}


def norm(value):
    key=re.sub(r'[^a-z0-9]','',str(value).lower());return ALIASES.get(key,key)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def save_csv(rows,path,columns=None):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows,columns=columns)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def numeric_only(value):
    tokens=[token.strip().replace(',','') for token in re.split(r'\||\t|\s+',value) if token.strip()]
    missing={'nan','na','n/a','none','-','—'}
    return bool(tokens) and all(NUMERIC.fullmatch(token) or token.lower() in missing for token in tokens)


def definition_text(value):
    if numeric_only(value):return False
    words=re.findall(r'[A-Za-z]{2,}',value)
    meaningful=[word for word in words if word.lower() not in TYPE_WORDS]
    return len(meaningful)>=2


def match_names(value,expected):
    if norm(value) in expected:return [expected[norm(value)]]
    return list(dict.fromkeys(expected[norm(part)] for part in re.split(r'[,;\n]+',value)
                              if norm(part) in expected))


def parse_document(payload,url,expected):
    text=payload.decode('utf-8',errors='replace')
    xml=url.endswith('fullTextXML') or text.lstrip().startswith('<?xml')
    soup=BeautifulSoup(text,'xml' if xml else 'html.parser')
    rows=[];rejected=[]
    for table_index,table in enumerate(soup.find_all('table')):
        table_rows=table.find_all('tr')
        header=' '.join(row.get_text(' ',strip=True) for row in table_rows[:2]).lower()
        # Explicit numerical descriptive-statistics headers.
        statistics_table=('feature' in header and
                          sum(bool(re.search(r'\b'+word+r'\b',header)) for word in ['mean','std','min','max'])>=3
                          and not any(word in header for word in ['description','definition','meaning']))
        for row_index,row in enumerate(table_rows):
            if row.find_parent('thead') is not None:continue
            cells=[cell.get_text(' ',strip=True) for cell in row.find_all(['td','th'],recursive=False)]
            if len(cells)<2:continue
            for position,value in enumerate(cells[:-1]):
                names=match_names(value,expected)
                if not names:continue
                description=' | '.join(cells[position+1:])
                for name in names:
                    record={'raw_feature':name,'exact_quote':' | '.join(cells),
                            'definition_text':description,'locator':f'table {table_index}, row {row_index}'}
                    if statistics_table or numeric_only(description):
                        rejected.append({**record,'reason':'NUMERIC_DESCRIPTIVE_STATISTICS_NOT_A_DEFINITION'})
                    elif definition_text(description):rows.append(record)
                    else:rejected.append({**record,'reason':'TYPE_OR_NONDESCRIPTIVE_ROW_NOT_A_DEFINITION'})
    # CICFlowMeter plaintext documentation has anchored name/description lines.
    if 'CICFlowMeter' in url and url.endswith('ReadMe.txt'):
        for index,line in enumerate(text.splitlines()):
            parts=re.split(r'\t+|\s*\|\s*|\s*:\s*',line.strip(),maxsplit=1)
            if len(parts)==2 and definition_text(parts[1]):
                for name in match_names(parts[0],expected):
                    rows.append({'raw_feature':name,'definition_text':parts[1],
                                 'exact_quote':line.strip(),'locator':f'text line {index+1}'})
    return soup,rows,rejected,'xml/lxml' if xml else 'html.parser'


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    ledger_path=PREVIOUS/'repaired_feature_definition_ledger.csv'
    if not ledger_path.exists():raise FileNotFoundError(ledger_path)
    ledger=pd.read_csv(ledger_path).fillna('')
    expected={dataset:{norm(raw):raw for raw in ledger.loc[ledger.dataset==dataset,'raw_feature'].unique()}
              for dataset in DATASETS}
    evidence=[];rejected=[];diagnostics=[];document_links=[];source_files=[]
    for root in [OLDER/'documents',PREVIOUS/'additional_sources']:
        if not root.exists():continue
        for dataset in DATASETS:
            directory=root/dataset
            for receipt_path in sorted(directory.glob('*.json')):
                try:
                    meta=json.loads(receipt_path.read_text())
                    source=receipt_path.with_suffix('.source')
                    if not source.exists():continue
                    document_hash=sha(source)
                    if document_hash!=meta['document_sha256']:raise AssertionError('Source document hash mismatch.')
                    url=meta['source_url']
                    soup,rows,bad,parser=parse_document(source.read_bytes(),url,expected[dataset])
                    title=soup.title.get_text(' ',strip=True) if soup.title else meta.get('role','')
                    challenge=bool(re.search(r'checking your browser|recaptcha|just a moment|access denied',title,re.I))
                    common={'dataset':dataset,'source_url':url,'source_sha256':document_hash,
                            'source_file':str(source),'source_scope':meta.get('source_scope',meta.get('role',''))}
                    if challenge:
                        rows=[]
                    evidence.extend({**common,**row} for row in rows)
                    rejected.extend({**common,**row} for row in bad)
                    diagnostics.append({**common,'parser':parser,'document_title':title,
                                        'definition_rows':len(rows),'rejected_numerical_or_type_rows':len(bad),
                                        'challenge_page':challenge})
                    source_files.append((source,receipt_path))
                    if dataset=='TONIoT':
                        for anchor in soup.find_all('a',href=True):
                            label=anchor.get_text(' ',strip=True)
                            target=urljoin(url,anchor['href'])
                            context=(label+' '+target).lower()
                            if any(term in context for term in ['description','feature','dataset','download','cloudstor','sharepoint']):
                                document_links.append({'dataset':dataset,'anchor_text':label,'link':target,
                                     'action':'Inspect official description/source material; no automatic access bypass or data download'})
                except Exception as error:
                    diagnostics.append({'dataset':dataset,'receipt':str(receipt_path),'status':'SOURCE_PARSE_FAILED','detail':str(error)})
    definitions=pd.DataFrame(evidence)
    if definitions.empty:
        definitions=pd.DataFrame(columns=['dataset','raw_feature','source_url','exact_quote','source_sha256','definition_text','locator','source_scope'])
    else:
        definitions=definitions.drop_duplicates(['dataset','raw_feature','source_url','exact_quote'])
    save_csv(definitions,OUT/'nonstatistical_definition_excerpts.csv')
    save_csv(pd.DataFrame(rejected),OUT/'rejected_statistics_and_type_rows.csv')
    save_csv(diagnostics,OUT/'parser_diagnostics.csv')
    save_csv(pd.DataFrame(document_links,columns=['dataset','anchor_text','link','action']),OUT/'TON_official_description_links.csv')
    reviewed=[]
    for row in ledger.to_dict('records'):
        found=definitions[(definitions.dataset==row['dataset'])&(definitions.raw_feature==row['raw_feature'])]
        status='NONSTATISTICAL_SOURCE_EXCERPT_FOUND_REVIEW_REQUIRED' if len(found) else 'NO_SEMANTIC_DEFINITION_EVIDENCE'
        quotes=' '.join(found.exact_quote.astype(str))
        ttl=norm(row['raw_feature'])=='duration' and bool(re.search(r'\bttl\b|time\s*[- ]?to\s*[- ]?live',quotes,re.I))
        reviewed.append({**row,'quality_corrected_status':status,'nonstatistical_excerpts':len(found),
            'ttl_quote_found_for_this_dataset':ttl,
            'recommended_review_action':('KEEP_OUT_OF_PRIMITIVE_TIMING_DELAY: SOURCE_SAYS_TTL'
                                         if ttl else 'SOURCE_AND_EXTRACTOR_REVIEW_REQUIRED'),
            'approved_for_confirmatory_attack':False,'group_C_approved':False})
    result=pd.DataFrame(reviewed)
    save_csv(result,OUT/'quality_corrected_feature_ledger.csv')
    summary=result.groupby(['dataset','quality_corrected_status']).agg(
        encoded_model_features=('model_feature','size'),distinct_raw_features=('raw_feature','nunique')).reset_index()
    save_csv(summary,OUT/'semantic_definition_coverage.csv')
    missing=result[result.quality_corrected_status=='NO_SEMANTIC_DEFINITION_EVIDENCE'][
        ['dataset','raw_feature','current_semantic_view','currently_mutable']].drop_duplicates()
    save_csv(missing,OUT/'exact_missing_raw_feature_names.csv')
    mutable_review=result[result.currently_mutable.astype(str).isin(['1','1.0','True','true'])][
        ['dataset','model_feature','quality_corrected_status','recommended_review_action']]
    save_csv(mutable_review,OUT/'current_attack_feature_review.csv')
    # Small review package contains documentation/excerpts, not models or raw tables.
    package=ROOT/'PRIVATE_Group_B_Actual_Definition_Review.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1) as archive:
        for path in OUT.iterdir():
            if path.is_file():archive.write(path,'review/'+path.name)
        for index,(source,receipt) in enumerate(source_files):
            archive.write(source,f'sources/{index:03d}_{source.name}')
            archive.write(receipt,f'sources/{index:03d}_{receipt.name}')
    with zipfile.ZipFile(package,'r') as archive:
        if archive.testzip() is not None:raise RuntimeError('Review ZIP integrity failure.')
    (OUT/'scope.json').write_text(json.dumps({
        'fix':'Proper XML parsing; reject numerical statistics as semantic definitions',
        'numeric_E_notation_bug':'Scientific-notation E was previously mistaken for descriptive text; these rows are now rejected',
        'source_quotes':'Literal cached document rows only',
        'group_B_complete':False,'group_C_approved':False,
        'remaining':['Review exact definitions/formulas','Resolve remaining raw-feature names',
                     'Pin extractor version','Establish original capture/label/row correspondence']},indent=2))
    print('\nQUALITY-CORRECTED DEFINITION COVERAGE\n'+summary.to_string(index=False),flush=True)
    print('\nEXACT MISSING RAW FEATURES\n'+missing.to_string(index=False),flush=True)
    print('\nCURRENT ATTACK FEATURE REVIEW\n'+mutable_review.to_string(index=False),flush=True)
    print('\nDURATION SOURCE QUOTATIONS')
    duration_definitions=definitions[definitions.raw_feature.astype(str).str.lower()=='duration']
    for row in duration_definitions.to_dict('records'):
        print(row['dataset'],row['source_url'],row['exact_quote'],sep='\n')
    print('\nPRIVATE REVIEW PACKAGE:',package)
    print('No models/data/labels changed. No attacks approved.')
    return {'summary':summary,'missing':missing,'package':package}

if __name__=='__main__':
    B_EVIDENCE_REVIEW=main()
