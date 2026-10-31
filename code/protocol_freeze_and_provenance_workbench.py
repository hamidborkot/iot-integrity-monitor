"""Protocol freeze and provenance-workbench bootstrap.
No attack, model training, data transformation, or result generation.
Builds a REVIEW_REQUIRED source-of-truth schema for the predictors actually used by the frozen bundles.
"""
import hashlib
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
OUT=BASE/'confirmatory_preflight_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']


def norm(value):
    return ''.join(char for char in str(value).lower() if char.isalnum())


def classify(dataset,feature,mutable):
    name=norm(feature)
    if any(token in name for token in ['flowid','timestamp','srcip','dstip','sourceip','destinationip','uuid']):
        return ('identifier_or_metadata','identifier_or_metadata','immutable_exclude',
                'EXCLUDE_FROM_ATTACK','not_a_mutable_telemetry_predictor')
    if any(token in name for token in ['protocol','service','port','proto','http','https','dns','smtp','ssh','telnet','arp','icmp','tcp','udp']):
        return ('protocol_or_application_state','primitive_or_indicator','constrained',
                'REVIEW_REQUIRED','protocol_or_application_semantics_required')
    if any(token in name for token in ['flag','syn','ack','fin','rst','psh','urg','ece','cwr','connstate']):
        return ('transport_state','derived_or_state_indicator','constrained',
                'REVIEW_REQUIRED','valid_state_transition_or_recompute_required')
    if any(token in name for token in ['duration','iat','idle','active','time','rate','bytess','pktss']):
        return ('timing_rate','derived_timing_statistic','constrained',
                'REVIEW_REQUIRED','derive_from_packet_timestamps_or_leave_unchanged')
    if any(token in name for token in ['mean','avg','std','variance','var','min','max','radius','covariance','magnitude','weight']):
        return ('aggregate_statistic','derived_statistic','do_not_directly_perturb',
                'REVIEW_REQUIRED','recompute_from_primitive_packets_or_leave_unchanged')
    if any(token in name for token in ['byte','length','size','payload','packet','pkt','tot','sum','volume','header']):
        return ('size_volume','primitive_or_aggregate_unknown','review_required',
                'REVIEW_REQUIRED','official_feature_definition_required')
    if any(token in name for token in ['count','number','bulk','subflow','window']):
        return ('count_burst','primitive_or_aggregate_unknown','review_required',
                'REVIEW_REQUIRED','primitive_event_definition_required')
    return ('unassigned','unknown','review_required','REVIEW_REQUIRED','official_feature_definition_required')


def model_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    settings={'datasets':DATASETS,'purpose':'freeze development and create manual provenance workbench',
              'automatic_semantics':'candidate-only; no candidate mapping authorizes an attack'}
    digest=hashlib.sha256(json.dumps(settings,sort_keys=True).encode()).hexdigest()
    (OUT/'preflight_settings.json').write_text(json.dumps({'sha256':digest,'settings':settings},indent=2))
    ledger=[]; rows=[]; manifests=[]
    for dataset in DATASETS:
        bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
        if not bundle_path.exists():
            ledger.append({'dataset':dataset,'task':'bundle_integrity','status':'BLOCKED','detail':'bundle missing'})
            continue
        bundle=joblib.load(bundle_path)
        required=['train_df','source_test_df','primary_features','mutable_columns','semantic_views','encoding']
        missing=[key for key in required if key not in bundle]
        if missing:
            ledger.append({'dataset':dataset,'task':'bundle_integrity','status':'BLOCKED','detail':'missing '+','.join(missing)})
            continue
        source=set(bundle['source_test_df']['_row_id'])
        train=set(bundle['train_df']['_row_id'])
        if source&train:
            raise AssertionError(f'{dataset}: train/source row overlap')
        views={feature:view for view,features in bundle['semantic_views'].items() for feature in features}
        if len(views)!=sum(len(v) for v in bundle['semantic_views'].values()):
            raise AssertionError(f'{dataset}: view feature overlap')
        mutable=set(bundle['mutable_columns'])
        for feature in bundle['primary_features']:
            raw_feature=feature.split('__category_')[0]
            view=views.get(feature,'primary_only')
            semantic,derived,mutability,action,rule=classify(dataset,raw_feature,feature in mutable)
            encoding=bundle['encoding'].get(raw_feature,{})
            rows.append({
                'dataset':dataset,'model_feature':feature,'raw_feature':raw_feature,
                'semantic_view':view,'encoding_kind':encoding.get('kind','unknown'),
                'candidate_primitive_channel':semantic,'candidate_derived_status':derived,
                'currently_mutable_feature':int(feature in mutable),'candidate_mutability':mutability,
                'candidate_attack_action':action,'candidate_validity_rule':rule,
                'official_definition_source':'REVIEW_REQUIRED',
                'official_definition_quote':'REVIEW_REQUIRED',
                'final_primitive_source':'REVIEW_REQUIRED',
                'final_derived_from':'REVIEW_REQUIRED',
                'final_mutability':'REVIEW_REQUIRED',
                'final_attack_action':'REVIEW_REQUIRED',
                'final_validity_rule':'REVIEW_REQUIRED',
                'reviewer_initials':'REVIEW_REQUIRED','review_date':'REVIEW_REQUIRED',
                'approved_for_confirmatory_attack':False,'notes':''})
        manifests.append({'dataset':dataset,'bundle_sha256':model_hash(bundle_path),
                          'train_rows':len(bundle['train_df']),'source_test_rows':len(bundle['source_test_df']),
                          'primary_features':len(bundle['primary_features']),
                          'mutable_features':len(bundle['mutable_columns']),
                          'views':json.dumps(bundle['semantic_views'],sort_keys=True),
                          'train_source_overlap':0})
        ledger.extend([
            {'dataset':dataset,'task':'development_artifact_freeze','status':'COMPLETE','detail':'bundle fingerprint written'},
            {'dataset':dataset,'task':'official_feature_provenance_review','status':'REQUIRES_HUMAN_SOURCE_REVIEW','detail':'all final provenance fields REVIEW_REQUIRED'},
            {'dataset':dataset,'task':'primitive_recomputation_attack','status':'BLOCKED_BY_PROVENANCE','detail':'do not perturb derived features directly'},
            {'dataset':dataset,'task':'validity_rate_and_damage_retention','status':'BLOCKED_BY_PROVENANCE','detail':'requires approved primitive transformations'},
            {'dataset':dataset,'task':'faithful_MD3_and_other_published_baselines','status':'NOT_IMPLEMENTED','detail':'must be independently implemented/verified'},
            {'dataset':dataset,'task':'formal_nonidentifiability_theorem','status':'NOT_IMPLEMENTED','detail':'proof task; not a numerical experiment'},
            {'dataset':dataset,'task':'fresh_confirmatory_replication','status':'BLOCKED_BY_PROTOCOL_AND_PROVENANCE','detail':'requires frozen approved protocol'},
            {'dataset':dataset,'task':'untouched_boundary_dataset','status':'NOT_IMPLEMENTED','detail':'must be genuinely unused during development'},
            {'dataset':dataset,'task':'paper_and_repository','status':'BLOCKED_BY_COMPLETION_AUDIT','detail':'not ready'}])
    schema=pd.DataFrame(rows)
    schema.to_csv(OUT/'feature_provenance_schema_WORKING_COPY.csv',index=False)
    pd.DataFrame(manifests).to_csv(OUT/'frozen_bundle_manifest.csv',index=False)
    pd.DataFrame(ledger).to_csv(OUT/'completion_ledger.csv',index=False)
    summary=(schema.groupby(['dataset','candidate_attack_action']).size().rename('features').reset_index()
             if not schema.empty else pd.DataFrame())
    summary.to_csv(OUT/'provenance_candidate_summary.csv',index=False)
    protocol={
      'status':'development artifacts frozen; confirmatory protocol NOT frozen',
      'rule':'No confirmatory attack can run while approved_for_confirmatory_attack is false for any modified feature.',
      'provenance_source_requirement':'Official dataset/feature-extractor documentation or verified source code; do not infer physical semantics from a feature name.',
      'next_gate':'Manually complete final_* columns, archive cited source excerpts, and obtain feature-by-feature approval before attack code is written.'}
    (OUT/'README_NEXT_GATE.json').write_text(json.dumps(protocol,indent=2))
    print('\nFROZEN BUNDLE MANIFEST\n',pd.DataFrame(manifests).to_string(index=False))
    print('\nCOMPLETION LEDGER\n',pd.DataFrame(ledger).to_string(index=False))
    print('\nFILES WRITTEN\n',*[path.name for path in sorted(OUT.iterdir())],sep='- ')
    return OUT

if __name__=='__main__':
    PREFLIGHT_OUT=main()
