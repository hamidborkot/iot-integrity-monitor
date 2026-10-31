"""Resolve three CICIoT source-name truncations corroborated in the supplied report.
Verify the cached XML hash, preserve literal quotes, record label-dependent
published preprocessing, and freeze documentary policy WITHOUT traffic approval.
No training, rows, labels, existing models, or earlier results are changed.
"""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin
import joblib
import pandas as pd
from bs4 import BeautifulSoup

ROOT=Path('/kaggle/working')
BASE=ROOT/'fresh_all_datasets_v1'
B3=ROOT/'group_B_definition_parser_repair_v3'
B4=ROOT/'group_B_evidence_quality_correction_v4'
OUT=ROOT/'group_B_CICIoT_documentary_review_v5'
DATASET='CICIoT2023'
SOURCE_SHA='18be213ca8ec8e9878ce47233390b53fa62e7fa5cd3194c1a160c2e07ff309dd'
BUNDLE_SHA='29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88'
URL='https://www.ebi.ac.uk/europepmc/webservices/rest/PMC10346235/fullTextXML'
ALIASES={
 'psh_flag_number':{'document_name':'psh flag numbe','row_number':'12','description_pattern':r'psh\s+flag\s+value'},
 'ece_flag_number':{'document_name':'ece flag numbe','row_number':'14','description_pattern':r'ece\s+flag\s+value'},
 'urg_count':{'document_name':'urg coun','row_number':'19','description_pattern':r'packets.*urg\s+flag'},
}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def norm(value):return re.sub(r'[^a-z0-9]','',str(value).lower())


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    sources=[path for path in (B3/'additional_sources'/DATASET).glob('*.source') if sha(path)==SOURCE_SHA]
    if not sources:raise FileNotFoundError('The exact reviewed Europe PMC XML was not found; no guessed definitions will be substituted.')
    source=sources[0]
    soup=BeautifulSoup(source.read_bytes(),'xml')
    if '10.3390/s23135941' not in source.read_text(encoding='utf-8',errors='replace'):
        raise AssertionError('Published article identity mismatch.')
    bundle_path=BASE/DATASET/f'{DATASET}_bundle.joblib'
    if sha(bundle_path)!=BUNDLE_SHA:raise AssertionError('Frozen CICIoT model bundle changed.')
    bundle=joblib.load(bundle_path)
    old=pd.read_csv(B4/'quality_corrected_feature_ledger.csv').fillna('')
    excerpts=pd.read_csv(B4/'nonstatistical_definition_excerpts.csv').fillna('')
    new=[]
    for model_name,rule in ALIASES.items():
        matches=[];canonical_seen=False
        for table_index,table in enumerate(soup.find_all('table')):
            for row_index,row in enumerate(table.find_all('tr')):
                cells=[cell.get_text(' ',strip=True) for cell in row.find_all(['td','th'],recursive=False)]
                if any(norm(cell)==norm(model_name) for cell in cells[:2]):canonical_seen=True
                if (len(cells)>=3 and cells[0].strip()==rule['row_number']
                    and norm(cells[1])==norm(rule['document_name'])
                    and re.search(rule['description_pattern'],' '.join(cells[2:]),re.I)):
                    matches.append({'dataset':DATASET,'raw_feature':model_name,'source_url':URL,
                        'source_sha256':SOURCE_SHA,'source_file':str(source),
                        'source_scope':'Published article definition, explicit truncated-name reconciliation',
                        'exact_quote':' | '.join(cells),'definition_text':' | '.join(cells[2:]),
                        'locator':f'table {table_index}, row {row_index}',
                        'document_name':cells[1],
                        'matching_method':'Only this reviewed truncation; table row number and description checked'})
        if len(matches)!=1 or not canonical_seen:
            raise AssertionError(f'{model_name}: definition or same-document canonical spelling corroboration failed.')
        new.extend(matches)
    combined=pd.concat([excerpts,pd.DataFrame(new)],ignore_index=True).drop_duplicates(
        ['dataset','raw_feature','source_url','exact_quote'])
    save_csv(new,OUT/'three_reviewed_source_name_reconciliations.csv')
    save_csv(combined,OUT/'definition_excerpts_with_explicit_reconciliation.csv')
    views={feature:view for view,features in bundle['semantic_views'].items() for feature in features}
    records=[]
    for feature in bundle['primary_features']:
        found=combined[(combined.dataset==DATASET)&(combined.raw_feature==feature)]
        if found.empty:
            raise AssertionError(f'Remaining undocumented model predictor: {feature}')
        records.append({'dataset':DATASET,'model_feature':feature,'current_view':views.get(feature,'primary_only'),
            'published_definition_excerpt_present':True,
            'documentary_review_role':'AI-assisted source review of supplied report; not traffic-action approval',
            'source_name_reconciled':feature in ALIASES,
            'current_mutable_feature':feature in bundle['mutable_columns'],
            'Duration_policy':'TTL/header field; not a primitive timing-delay control' if feature=='Duration' else '',
            'direct_CSV_edit_allowed_for_group_C':False,
            'operational_extractor_formula_verified':False,'capture_row_mapping_verified':False,
            'physical_transform_approved':False,
            'operational_detail_note':('Paper row only repeats Header Length; exact implementation/aggregation remains unresolved'
                                       if feature=='Header_Length' else
                                       'Packet length wording does not specify window/flow-state implementation'
                                       if feature=='Tot size' else
                                       'Published description does not alone pin the extraction and aggregation implementation')})
    save_csv(records,OUT/'CICIoT_documentary_provenance_review.csv')
    methods=[]
    links=[]
    for section in soup.find_all('sec'):
        title=section.find('title',recursive=False)
        if title and 'feature extraction' in title.get_text(' ',strip=True).lower():
            methods.append(section.get_text(' ',strip=True))
            for link in section.find_all('ext-link'):
                href=link.get('xlink:href') or link.get('href')
                if href:links.append({'context':link.parent.get_text(' ',strip=True)[:1200],
                    'url':href,'exact_dataset_extractor_identity_verified':False})
    if not methods:raise AssertionError('Reviewed feature-extraction section absent.')
    text='\n\n'.join(methods)
    if not ('window sizes of 10' in text and '100' in text and 'mean values' in text):
        raise AssertionError('Reviewed published window/mean-processing statements absent.')
    (OUT/'published_extraction_section.txt').write_text(text,encoding='utf-8')
    policy={'dataset':DATASET,'source_sha256':SOURCE_SHA,
        'published_representation':'Mean aggregation of extracted values in scenario-dependent packet windows',
        'published_window_sizes_packets':[10,100],
        'scenario_dependent_preprocessing':True,
        'interpretation':'Benchmark-construction dependence; not automatically proof of train/test label leakage',
        'do_not_infer_packet_window_length_from_Number':True,
        'do_not_recompute_packet_statistics_from_averaged_CSV_row_as_if_it_were_raw_packets':True,
        'future_reextraction_design':'Use a prespecified label-independent window policy for a deployment-style sensitivity test',
        'deployment_policy_changed_or_test_executed':False,
        'Header_Length_exact_formula_unresolved':True,'Tot_size_exact_state/window_formula_unresolved':True,
        'three_truncated_names_resolved':list(ALIASES),
        'all_frozen_predictors_documentary_matched':len(records),
        'full_Group_B_complete':False,'Group_C_approved':False,
        'remaining':['Locate and pin exact dataset-specific extractor, not merely DPKT',
                     'Obtain authorized original capture and labeling information',
                     'Verify extraction/window/flow-state reproduction and record mapping',
                     'Resolve IoMT-specific definitions without copying CICIoT descriptions']}
    (OUT/'published_preprocessing_and_action_policy.json').write_text(json.dumps(policy,indent=2))
    save_csv(pd.DataFrame(links,columns=['context','url','exact_dataset_extractor_identity_verified']),OUT/'article_link_candidates.csv')
    receipt={'CICIoT2023_documentary_predictors_matched':len(records),
             'audited_name_truncations_resolved':len(new),'models_retrained':False,'dataset_rows_changed':False,
             'old_results_modified':False,'capture_or_primitive_attacks_approved':False,
             'status':'CICIoT_DOCUMENTARY_MATCHING_RECONCILED_OPERATIONAL_PROVENANCE_PENDING'}
    (OUT/'review_receipt.json').write_text(json.dumps(receipt,indent=2))
    print('\nDOCUMENTARY REVIEW RECEIPT\n'+json.dumps(receipt,indent=2),flush=True)
    print('\nRESOLVED EXACT SOURCE NAMES\n'+pd.DataFrame(new)[['raw_feature','document_name','exact_quote','locator']].to_string(index=False),flush=True)
    print('\nPUBLISHED PREPROCESSING / ACTION POLICY\n'+json.dumps(policy,indent=2),flush=True)
    return receipt

if __name__=='__main__':
    DOCUMENTARY_REVIEW_STATUS=main()
