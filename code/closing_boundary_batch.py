"""Closing boundary batch (design data only: Captures 1-1, 3-1, 8-1).
E1 budget escalation (10x) of the attackability upper bound; E2 detector-family robustness (LOSO HGB/LR + within-scenario HGB);
E3 analysis-protocol record. The gate rule is declared below BEFORE results. This is NOT prospective confirmation.
"""
import glob,hashlib,itertools,json,warnings
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_EVEN
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings('ignore')
WORK=Path('/kaggle/working');SEED=7;TRAIN_PER_CLASS=40000;ATTACK_N=30000;GATE_DROP=0.05
NUM=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes'];PROTOS=['tcp','udp','icmp']
GRIDS={'declared_original':([0.0,0.1,1.0,10.0],[0,100,500,1200],[0,1,3]),'escalated_10x':([0.0,1.0,10.0,100.0],[0,500,1200,1460],[0,3,10,30])}
DESIGN_ONLY=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1']
OUT=WORK/('TRACE_BOUNDARY_CLOSING_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
GATE_RULE='NO_ATTACKABLE_REGIME if every conservative-eligibility, escalated-grid ALL9-detector upper-bound recall drop is < 0.05; otherwise ATTACKABLE_REGIME_REQUIRES_PACKET_VALIDITY_SUITES'
def clean(df):
 df=df.copy();df['proto']=df['proto'].astype(str).str.lower();df['label']=df['published_label'].astype(str).str.lower()
 df=df[df.label.isin(['benign','malicious'])]
 for c in NUM:df[c]=pd.to_numeric(df[c].replace('-',np.nan),errors='coerce').fillna(0.0)
 df['y']=(df.label=='malicious').astype(int);return df[NUM+['proto','y']].reset_index(drop=True)
def load_linked(s):
 files=sorted(glob.glob(str(WORK/f'TRACE_LINKAGE_BATCH_v1/{s}/*/linked_records.csv')),key=lambda p:Path(p).stat().st_size,reverse=True)
 return clean(pd.read_csv(files[0],usecols=NUM+['proto','published_label'],dtype=str))
def parse_zeek(path):
 fields=None;rows=[]
 with open(path,encoding='utf-8')as f:
  for line in f:
   if line.startswith('#fields'):fields=line.strip().split()[1:];continue
   if line.startswith('#')or not line.strip():continue
   rows.append(dict(zip(fields,line.rstrip().split())))
 return pd.DataFrame(rows)
def load_8_1():
 dirs=[Path(p).parent for p in glob.glob(str(WORK/'TRACE_CLEAN_REPLAY_*/smoke_selection.json')) if json.loads(Path(p).read_text()).get('scenario')=='CTU-IoT-Malware-Capture-8-1']
 if len(dirs)!=1:raise RuntimeError('Expected one Capture-8-1 clean replay.')
 d=dirs[0];gen=parse_zeek(d/'clean_replay/conn.log');mp=pd.read_csv(d/'unique_exact_key_mapping.csv',dtype=str)
 key=lambda ts:int((Decimal(ts)*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN))
 gen['k']=list(zip(gen.ts.map(key),gen['id.orig_h'],gen['id.orig_p'],gen['id.resp_h'],gen['id.resp_p'],gen.proto.str.lower()))
 labels={(int(a),b,c,e,f,g.lower()):l for a,b,c,e,f,g,l in zip(mp.timestamp_microseconds,mp.orig_h,mp.orig_p,mp.resp_h,mp.resp_p,mp.proto,mp.published_label)}
 gen['published_label']=gen.k.map(labels)
 if gen.published_label.isna().any():raise RuntimeError('Unlabeled replay row.')
 return clean(gen[NUM+['proto','published_label']])
def load_all():return {s:(load_8_1() if s.endswith('8-1') else load_linked(s)) for s in DESIGN_ONLY}
def matrix(df,fs,log=False):
 parts=[]
 if fs in('ALL9','NO_PROTO'):
  x=df[NUM].to_numpy(float);parts.append(np.log1p(x) if log else x)
 if fs in('ALL9','ONLY_PROTO'):parts.append(np.column_stack([(df.proto==p).to_numpy(float) for p in PROTOS]))
 return np.hstack(parts)
def sample_train(frames):
 parts=[]
 for df in frames:
  for y in(0,1):
   part=df[df.y==y];parts.append(part.sample(min(TRAIN_PER_CLASS,len(part)),random_state=SEED))
 return pd.concat(parts,ignore_index=True)
def make_predictor(kind,fs,train):
 if kind=='HGB':
  clf=HistGradientBoostingClassifier(max_iter=100,learning_rate=0.1,random_state=SEED).fit(matrix(train,fs),train.y)
  return lambda d:clf.predict(matrix(d,fs))
 sc=StandardScaler().fit(matrix(train,fs,True));clf=LogisticRegression(max_iter=300,class_weight='balanced').fit(sc.transform(matrix(train,fs,True)),train.y)
 return lambda d:clf.predict(sc.transform(matrix(d,fs,True)))
def bound(predict,mal,grid,variant):
 base=mal[NUM].to_numpy(float);idx={c:i for i,c in enumerate(NUM)}
 def run(arr):
  d=pd.DataFrame(arr,columns=NUM);d['proto']=mal.proto.values;return predict(d)
 detected=run(base)==1
 pace=(base[:,idx['orig_pkts']]+base[:,idx['resp_pkts']]>=2)
 pad=(base[:,idx['orig_pkts']]>=1) if variant=='liberal' else (base[:,idx['orig_bytes']]>0)
 inj=(base[:,idx['orig_pkts']]>=1) if variant=='liberal' else (base[:,idx['orig_pkts']]>=2)
 DUR,PAD,INJ=grid;combos=list(itertools.product(DUR,PAD,INJ));preds=[]
 for d,b,k in combos:
  arr=base.copy();arr[:,idx['duration']]+=d*pace;arr[:,idx['orig_bytes']]+=b*pad
  arr[:,idx['orig_ip_bytes']]+=b*pad+40*k*inj;arr[:,idx['orig_pkts']]+=k*inj;preds.append(run(arr))
 preds=np.array(preds);out={}
 for name,keep in[('pacing_only',lambda c:c[1]==0 and c[2]==0),('padding_only',lambda c:c[0]==0 and c[2]==0),('injection_only',lambda c:c[0]==0 and c[1]==0),('all_combined',lambda c:True)]:
  rows=[i for i,c in enumerate(combos)if keep(c)];evaded=((preds[rows]==0).any(axis=0))&detected
  out[name]=detected.mean()*evaded.sum()/max(detected.sum(),1)
 return detected.mean(),out,float(pace.mean()),float(pad.mean()),float(inj.mean())

scenarios=load_all();records=[]
for target,test in scenarios.items():
 train_loso=sample_train([v for k,v in scenarios.items()if k!=target])
 a,b=train_test_split(test,test_size=0.5,stratify=test.y,random_state=SEED)
 train_within=sample_train([a.reset_index(drop=True)])
 specs=[('LOSO_HGB_ALL9','HGB','ALL9',train_loso,test),('LOSO_HGB_NO_PROTO','HGB','NO_PROTO',train_loso,test),('LOSO_LR_ALL9','LR','ALL9',train_loso,test),
  ('WITHIN_HGB_ALL9','HGB','ALL9',train_within,b),('WITHIN_HGB_NO_PROTO','HGB','NO_PROTO',train_within,b)]
 for name,kind,fs,train,evalset in specs:
  predict=make_predictor(kind,fs,train);mal=evalset[evalset.y==1];mal=mal.sample(min(ATTACK_N,len(mal)),random_state=SEED).reset_index(drop=True)
  for gname,grid in GRIDS.items():
   for variant in['liberal','conservative']:
    recall,drops,pace,pad,inj=bound(predict,mal,grid,variant)
    for primitive,drop in drops.items():
     records.append({'held_out_target':target,'detector':name,'features':fs,'grid':gname,'eligibility':variant,'primitive_set':primitive,
      'baseline_malicious_recall':recall,'upper_bound_recall_drop':drop,'eligible_pacing':pace,'eligible_padding':pad,'eligible_injection':inj})
res=pd.DataFrame(records);res.to_csv(OUT/'E1_E2_attackability_bounds_full.csv',index=False)
core=res[res.primitive_set=='all_combined']
pivot=core.pivot_table(index=['detector','grid','eligibility'],columns='held_out_target',values='upper_bound_recall_drop').round(4)
pivot.to_csv(OUT/'E1_E2_all_combined_pivot.csv')
base_recall=core[(core.grid=='declared_original')&(core.eligibility=='conservative')].pivot_table(index='detector',columns='held_out_target',values='baseline_malicious_recall').round(4)
eligible=res[(res.eligibility=='conservative')&(res.detector=='LOSO_HGB_ALL9')&(res.grid=='declared_original')&(res.primitive_set=='all_combined')][['held_out_target','eligible_pacing','eligible_padding','eligible_injection']].round(4)
all9=core[(core.features=='ALL9')&(core.grid=='escalated_10x')&(core.eligibility=='conservative')]
attackable=bool((all9.upper_bound_recall_drop>=GATE_DROP).any());gate='ATTACKABLE_REGIME_REQUIRES_PACKET_VALIDITY_SUITES' if attackable else 'NO_ATTACKABLE_REGIME'
sensitivity=core[(core.features=='ALL9')&(core.eligibility=='liberal')&(core.grid=='escalated_10x')].upper_bound_recall_drop.max()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def latest(pattern):
 files=sorted(glob.glob(str(WORK/pattern)));return files[-1] if files else None
gate_csv=latest('TRACE_DESIGN_GATE_*/B_attackable_damage_upper_bounds.csv');inv_csv=latest('TRACE_SCENARIO_INVENTORY_*/inference_feasibility.csv')
contract=latest('TRACE_PUBLIC_SOURCE_FIX_*/B_canonical_Conn_Info_contract.csv');quar=WORK/'TRACE_LINKAGE_BATCH_v1/QUARANTINE_NOTICE.json'
inv=pd.read_csv(inv_csv) if inv_csv else pd.DataFrame()
record={'created_utc':datetime.now(timezone.utc).isoformat(),'status':'POST_DESIGN_GATE_TRANSPARENCY_RECORD_NOT_PROSPECTIVE_CONFIRMATION',
 'label_policy':'Use supplied published labels; v2 publisher rules are diagnostic only; v1 aggregate counts reconciled for scenarios 1-1,3-1,7-1,8-1,9-1.',
 'design_scenarios_ineligible_as_blind_targets':DESIGN_ONLY,'features':{'numeric':NUM,'protocol':'proto (immutable)','unstable_excluded':['conn_state','history','service','local_orig','local_resp','tunnel_parents']},
 'primitive_budget_grids':{k:{'duration_s':v[0],'padding_bytes':v[1],'dummy_header_packets':v[2]} for k,v in GRIDS.items()},
 'eligibility_rules':{'pacing':'orig_pkts+resp_pkts>=2','padding_liberal':'orig_pkts>=1','padding_conservative':'orig_bytes>0','injection_liberal':'orig_pkts>=1','injection_conservative':'orig_pkts>=2'},
 'declared_gate_rule':GATE_RULE,'gate_threshold_recall_drop':GATE_DROP,'gate_result':gate,'max_liberal_ALL9_escalated_drop_sensitivity':float(sensitivity),
 'inference_feasibility':inv.to_dict('records'),'partial_files_quarantined':json.loads(quar.read_text()) if quar.is_file() else None,
 'input_hashes':{k:(sha(v) if v else None) for k,v in {'design_gate_bounds':gate_csv,'inventory_feasibility':inv_csv,'canonical_contract':contract}.items()},
 'reporting_rules':['Report all detectors/grids/eligibility variants.','No packet-validity claim beyond byte/order-preserving timestamp pilot.','No significance claim when independent pairs < required.','Monitor outcomes on trace data are not part of this boundary study.'],
 'prospective_confirmation':False}
(OUT/'TRACE_BOUNDARY_ANALYSIS_PROTOCOL_v1.json').write_text(json.dumps(record,indent=2))
receipt={'output_directory':str(OUT),'gate_result':gate,'gate_rule':GATE_RULE,'detectors':sorted(res.detector.unique()),'grids':list(GRIDS),'models_for_confirmatory_use_trained':False,
 'attacks_on_real_packets_executed':False,'NF_changed':False,'prospective_confirmation':False}
(OUT/'receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt,indent=2))
print('\nE1/E2 - ALL-COMBINED UPPER-BOUND RECALL DROP (rows: detector/grid/eligibility; columns: held-out design scenario)');print(pivot.to_string())
print('\nBASELINE MALICIOUS RECALL (conservative / declared grid)');print(base_recall.to_string())
print('\nCONSERVATIVE ELIGIBILITY FRACTIONS (LOSO_HGB_ALL9)');print(eligible.to_string(index=False))
print('\nE3 - PROTOCOL RECORD GATE RESULT:',gate,'| liberal ALL9 escalated max drop:',round(float(sensitivity),4))
