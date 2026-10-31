# Fresh Capture-48 follow-up: identity, merge accounting, and alarm witnesses.
# No replay, training, sampling, threshold changes, or historical-result overwrite.
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import hashlib, json, traceback, zipfile
import numpy as np
import pandas as pd
import joblib
from threadpoolctl import threadpool_limits

W=Path('/kaggle/working')
OUT=W/('CAPTURE48_MERGE_WITNESS_AUDIT_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
F=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','proto']
R={'status':'STARTED','new_PCAP_replays':0,'models_trained':False,'old_membership_results_overwritten':False,
   'injection_control_completed':False,'independent_confirmation':False,'output_directory':str(OUT)}
class Stop(Exception):pass

def js(p,x):p.write_text(json.dumps(x,indent=2,default=str),encoding='utf-8')
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(4*1024**2),b''):h.update(b)
    return h.hexdigest()

def boolean(s):
    v=s.astype(str).str.lower()
    if not v.isin(['true','false','1','0']).all():raise Stop('Invalid Boolean '+str(s.name))
    return v.isin(['true','1']).to_numpy(bool)

def normalize(df):
    df=df.copy()
    if not set(F).issubset(df.columns):raise Stop('Feature columns missing')
    for c in F[:-1]:
        df[c]=pd.to_numeric(df[c].replace({'-':'0','':'0'}),errors='raise').astype(float)
        if not np.isfinite(df[c]).all() or df[c].lt(0).any():raise Stop('Invalid feature '+c)
    df['proto']=df.proto.str.lower()
    if not df.proto.isin(['tcp','udp','icmp']).all():raise Stop('Invalid protocol')
    return df

def encode(df,protocol):
    p=np.column_stack([df.proto.eq(x).to_numpy(float) for x in ['tcp','udp','icmp']])
    return p if protocol else np.column_stack([np.log1p(df[F[:-1]].to_numpy(float)),p])

def classify_witness(complete,positive_pure_witness,any_overlap_alarm):
    # Positive evidence does not require every other descendant to be pure.
    if positive_pure_witness:return 'DETECTED_WITH_PURE_RECORD_WITNESS'
    if complete and not any_overlap_alarm:return 'NO_ASSOCIATED_RECORD_ALARM'
    return 'ATTRIBUTION_UNRESOLVED'

try:
    found=[]
    for p in W.glob('FRESH_RAW_CAPTURE48_*'):
        rp=p/'receipt.json'
        if rp.is_file():
            r=json.loads(rp.read_text())
            if r.get('status')=='FRESH_CAPTURE48_CLEAN_1S_10S_COMPLETE':found.append((p,r))
    if not found:raise Stop('Completed fresh Capture-48 batch missing')
    base,previous=max(found,key=lambda x:x[0].name)
    clean=normalize(pd.read_csv(base/'fresh_clean_target_sample.csv.gz',dtype={'ks':str}))
    if clean.ks.duplicated().any() or len(clean)!=1024:raise Stop('Unexpected original cohort')
    y=pd.to_numeric(clean.y).to_numpy(int);keys=list(clean.loc[y==1,'ks']);cohort=set(keys)
    if len(keys)!=512:raise Stop('Expected 512 selected malicious original units')
    models=joblib.load(base/'fresh_source_models.joblib')
    if len(models)!=9:raise Stop('Expected the nine fresh source-trained models')
    baseline=pd.read_csv(base/'packet_uid_mapping_0s.csv.gz',dtype={'original_ks':str,'uid':str})
    if baseline.packet_index.duplicated().any():raise Stop('Duplicate baseline packet occurrences')
    canonical=baseline[['packet_index','original_ks']].sort_values('packet_index').reset_index(drop=True)
    baseline_counts=canonical.groupby('original_ks').size().reindex(keys).to_numpy(int)
    input_hashes={'clean':sha(base/'fresh_clean_target_sample.csv.gz'),'models':sha(base/'fresh_source_models.joblib')}
    identities=[];uid_summaries=[];model_rows=[];unit_rows=[]
    print('[1/3] Checking that exactly the same original packet occurrences are tracked.',flush=True)
    with threadpool_limits(limits=2):
        for delay in [0,1,10]:
            mp=base/f'packet_uid_mapping_{delay}s.csv.gz';cp=base/f'descendant_features_{delay}s.csv.gz';ap=base/f'membership_{delay}s.csv';ep=base/f'condition_{delay}s_events.txt'
            for path in [mp,cp,ap,ep]:
                if not path.is_file():raise Stop('Required completed-run artifact missing: '+str(path))
            mapping=pd.read_csv(mp,dtype={'original_ks':str,'uid':str})
            audit=pd.read_csv(ap,dtype={'ks':str})
            records=normalize(pd.read_csv(cp,dtype={'uid':str},keep_default_na=False))
            if mapping.packet_index.duplicated().any() or records.uid.duplicated().any():raise Stop('Duplicate packet occurrence or UID feature record')
            if set(mapping.original_ks)!=cohort or set(audit.ks)!=cohort:raise Stop('Original-unit population differs')
            same=mapping[['packet_index','original_ks']].sort_values('packet_index').reset_index(drop=True).equals(canonical)
            if not same:raise Stop('Original packet occurrence/owner mapping differs between conditions')
            if set(mapping.uid)!=set(records.uid):raise Stop('UID feature coverage differs from the packet ledger')
            if not np.array_equal(audit.set_index('ks').loc[keys,'expected_packets'].to_numpy(int),baseline_counts):raise Stop('Expected source packet counts changed')
            event_counts=Counter()
            with open(ep) as f:
                for line in f:
                    if not line.startswith('PACKET|'):continue
                    fields=line.rstrip('\r\n').split('|')
                    if len(fields)!=12:raise Stop('Unexpected retained event format')
                    event_counts[fields[2]]+=1
            selected_counts=mapping.groupby('uid').size()
            owner_counts=mapping.groupby('uid').original_ks.nunique()
            original_to_uid=mapping.groupby('original_ks').uid.agg(lambda x:tuple(sorted(set(x)))).to_dict()
            rec=records.set_index('uid')
            uid_rows=[]
            for uid in records.uid:
                total=float(rec.loc[uid,'orig_pkts']+rec.loc[uid,'resp_pkts'])
                if not total.is_integer():raise Stop('Noninteger extracted packet count')
                total=int(total);tracked=int(selected_counts.loc[uid]);owners=int(owner_counts.loc[uid]);events=int(event_counts[uid])
                pure=(owners==1 and total==tracked and events==total)
                uid_rows.append({'uid':uid,'selected_original_owners':owners,'selected_packet_occurrences':tracked,
                    'extractor_packet_count':total,'instrumented_packet_events':events,
                    'record_minus_selected_packets':total-tracked,'event_minus_selected_packets':events-tracked,
                    'counter_matches_event_count':total==events,'pure_selected_original_witness_record':pure})
            uid_table=pd.DataFrame(uid_rows).set_index('uid')
            uid_table.to_csv(OUT/f'UID_contributions_{delay}s.csv')
            union_count=int(uid_table.extractor_packet_count.sum())
            repeated_count=sum(int(uid_table.loc[list(original_to_uid[k]),'extractor_packet_count'].sum()) for k in keys)
            original_sum=int(audit.descendant_packet_sum.sum())
            if repeated_count!=original_sum:raise Stop('The previous repeated descendant counter sum does not reproduce')
            mixed=int(uid_table.selected_original_owners.gt(1).sum())
            outside=int(uid_table.record_minus_selected_packets.clip(lower=0).sum())
            double_count=repeated_count-union_count
            summary={'delay_seconds':delay,'original_units':len(keys),'selected_packet_occurrences':len(mapping),
                'unique_descendant_UIDs':len(uid_table),'sum_UID_records_over_original_units':int(audit.descendant_records.sum()),
                'mixed_selected_owner_UIDs':mixed,'UIDs_with_unselected_packet_contributions':int(uid_table.record_minus_selected_packets.gt(0).sum()),
                'UID_counter_event_mismatches':int((~uid_table.counter_matches_event_count).sum()),
                'UIDs_with_more_tracked_packets_than_counter':int(uid_table.record_minus_selected_packets.lt(0).sum()),
                'pure_witness_UIDs':int(uid_table.pure_selected_original_witness_record.sum()),
                'old_strictly_validated_units':int(boolean(audit.membership_validated).sum()),
                'previous_per_original_packet_sum':repeated_count,'deduplicated_UID_packet_sum':union_count,
                'shared_UID_double_count_contribution':double_count,
                'net_unselected_or_counter_difference':union_count-len(mapping),
                'positive_unselected_packet_contribution':outside,
                'excess_decomposition_matches':repeated_count-len(mapping)==double_count+(union_count-len(mapping))}
            uid_summaries.append(summary)
            identities.append({'delay_seconds':delay,'same_packet_indices_and_owners_as_clean':same,'packet_occurrences':len(mapping)})
            input_hashes[str(delay)]={str(p.name):sha(p) for p in [mp,cp,ap,ep]}
            # Reproduce the old model results and compute separate evidence-witness bounds.
            selected=normalize(pd.read_csv(base/f'selected_features_{delay}s.csv.gz',dtype={'ks':str}))
            if selected.ks.duplicated().any() or set(selected.ks)!=set(clean.ks):raise Stop('Selected-record membership differs')
            selected=selected.set_index('ks').loc[clean.ks].reset_index()
            complete=all(x==0 for x in audit.unresolved_packets.to_numpy(int))
            for (family,seed),model in sorted(models.items()):
                protocol=family=='PROTOCOL_ONLY_LR'
                if list(model.classes_)!=[0,1]:raise Stop('Unexpected model class order')
                probability=model.predict_proba(encode(records,protocol))[:,1]
                alarms=dict(zip(records.uid,probability>=.5))
                clean_detected=model.predict_proba(encode(clean,protocol))[:,1]>=.5
                matched_detected=model.predict_proba(encode(selected,protocol))[:,1]>=.5
                positive=negative=uncertain=overlap_alarms=0
                for i,k in enumerate(keys):
                    uu=original_to_uid[k]
                    local_complete=(same and complete and all(u in alarms for u in uu))
                    any_alarm=any(alarms[u] for u in uu)
                    witnesses=[u for u in uu if bool(uid_table.loc[u,'pure_selected_original_witness_record']) and alarms[u]]
                    state=classify_witness(local_complete,bool(witnesses),any_alarm)
                    positive+=int(state=='DETECTED_WITH_PURE_RECORD_WITNESS')
                    negative+=int(state=='NO_ASSOCIATED_RECORD_ALARM')
                    uncertain+=int(state=='ATTRIBUTION_UNRESOLVED')
                    overlap_alarms+=int(any_alarm)
                    unit_rows.append({'delay_seconds':delay,'family':family,'seed':int(seed),'ks':k,
                        'old_strict_membership_validated':bool(boolean(audit.set_index('ks').loc[[k],'membership_validated'])[0]),
                        'descendant_UIDs':len(uu),'pure_positive_witness_UIDs':len(witnesses),
                        'alarm_in_any_overlapping_record':bool(any_alarm),'witness_classification':state})
                model_rows.append({'delay_seconds':delay,'family':family,'seed':int(seed),'original_units':len(keys),
                    'clean_detected_units':int(clean_detected[y==1].sum()),'selected_record_detected_units':int(matched_detected[y==1].sum()),
                    'detected_with_pure_record_witness':positive,'no_associated_record_alarm':negative,
                    'strict_attribution_unresolved':uncertain,'pure_witness_detection_lower':positive/len(keys),
                    'pure_witness_detection_upper':(positive+uncertain)/len(keys),
                    'any_overlap_alarm_units':overlap_alarms,'any_overlap_alarm_fraction':overlap_alarms/len(keys),
                    'any_overlap_is_an_explicit_policy_not_causal_attribution':True})
    ids=pd.DataFrame(identities);summary=pd.DataFrame(uid_summaries);models_out=pd.DataFrame(model_rows)
    ids.to_csv(OUT/'test1_packet_occurrence_identity.csv',index=False)
    summary.to_csv(OUT/'test2_UID_mixing_and_counter_decomposition.csv',index=False)
    models_out.to_csv(OUT/'test3_alarm_witness_results.csv',index=False)
    pd.DataFrame(unit_rows).to_csv(OUT/'per_original_alarm_witnesses.csv.gz',index=False,compression='gzip')
    js(OUT/'input_hashes.json',input_hashes)
    js(OUT/'policy.json',{'strict_positive_witness':'an alarm-bearing record whose complete counted and instrumented packet set maps to one selected original unit',
        'strict_negative':'complete mapped membership and no alarm in any containing record',
        'unresolved':'alarm only in records that lack a pure positive witness, or incomplete evidence',
        'any_overlap_policy':'separate operational sensitivity: any alarm-bearing record containing an original packet',
        'descendant_ground_truth_labels_assigned':False,'old_membership_rule_retained_in_outputs':True,
        'new_witness_analysis_post_exposure':True,'application_functionality_proved':False})
    print('\nTEST 1 — EXACT PACKET-OCCURRENCE IDENTITY\n'+ids.to_string(index=False),flush=True)
    print('\nTEST 2 — WHY DESCENDANT COUNTERS EXCEED THE COHORT TOTAL\n'+summary.to_string(index=False),flush=True)
    print('\nTEST 3 — PURE-RECORD WITNESSES AND SEPARATE OVERLAP POLICY\n'+models_out.to_string(index=False),flush=True)
    R.update({'status':'CAPTURE48_MERGE_AND_ALARM_WITNESS_AUDIT_COMPLETE','source_run':str(base),
        'descendant_labels_assigned':False,'any_overlap_policy_reported_separately':True,
        'all_membership_unresolved_units_forced_detected':False,
        'interpretation':'This refines what the retained packet/UID evidence supports; it does not change traffic, models, or thresholds. Record overlap is not causal attribution or malicious-functionality validation.'})
except Exception as e:
    R['status']='BLOCKED' if isinstance(e,Stop) else 'FAILED';R['reason']=str(e)
    (OUT/'error.txt').write_text(traceback.format_exc());print('\n'+R['status']+': '+str(e),flush=True)
finally:
    js(OUT/'receipt.json',R)
    package=OUT/'merge_witness_results.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for p in OUT.iterdir():
            if p.is_file() and p!=package:z.write(p,arcname=p.name)
    print('\nRECEIPT\n'+json.dumps(R,indent=2),flush=True)
    print('\nResult package:',package,flush=True)
