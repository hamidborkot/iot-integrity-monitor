"""Attack-surface localisation on DESIGN data (Captures 1-1, 3-1, 8-1). Not prospective confirmation.
E4: union-grid (declared U escalated) bound by primitive + cheapest-evasion profile -> tells which primitives need packet-level validity suites.
E5: random-perturbation baseline vs worst-case (is fragility generic or adversarial-only?).
E6: amended gate record (the previous escalated grid was not a superset of the declared grid)."""
import glob,itertools,json,warnings
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
DUR=[0.0,0.1,1.0,10.0,100.0];PAD=[0,100,500,1200,1460];INJ=[0,1,3,10,30]
DESIGN_ONLY=['CTU-IoT-Malware-Capture-1-1','CTU-IoT-Malware-Capture-3-1','CTU-IoT-Malware-Capture-8-1']
OUT=WORK/('TRACE_ATTACK_SURFACE_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));OUT.mkdir(exist_ok=False)
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
COMBOS=list(itertools.product(DUR,PAD,INJ))
COST=np.array([d/100+b/1460+k/30 for d,b,k in COMBOS]);NPRIM=np.array([(d>0)+(b>0)+(k>0) for d,b,k in COMBOS])
def analyse(predict,mal,variant,rng):
 base=mal[NUM].to_numpy(float);idx={c:i for i,c in enumerate(NUM)}
 def run(arr):
  d=pd.DataFrame(arr,columns=NUM);d['proto']=mal.proto.values;return predict(d)
 detected=run(base)==1
 pace=(base[:,idx['orig_pkts']]+base[:,idx['resp_pkts']]>=2)
 pad=(base[:,idx['orig_pkts']]>=1) if variant=='liberal' else (base[:,idx['orig_bytes']]>0)
 inj=(base[:,idx['orig_pkts']]>=1) if variant=='liberal' else (base[:,idx['orig_pkts']]>=2)
 preds=[]
 for d,b,k in COMBOS:
  arr=base.copy();arr[:,idx['duration']]+=d*pace;arr[:,idx['orig_bytes']]+=b*pad
  arr[:,idx['orig_ip_bytes']]+=b*pad+40*k*inj;arr[:,idx['orig_pkts']]+=k*inj;preds.append(run(arr))
 evade=(np.array(preds)==0)&detected[None,:]
 sets={'pacing_only':[i for i,c in enumerate(COMBOS)if c[1]==0 and c[2]==0],'padding_only':[i for i,c in enumerate(COMBOS)if c[0]==0 and c[2]==0],
  'injection_only':[i for i,c in enumerate(COMBOS)if c[0]==0 and c[1]==0],'all_combined':list(range(len(COMBOS)))}
 base_recall=detected.mean();drops={k:base_recall*(evade[v].any(axis=0).sum()/max(detected.sum(),1)) for k,v in sets.items()}
 anyev=evade.any(axis=0);profile=None
 if anyev.any():
  cost=np.where(evade,COST[:,None]+0.001*NPRIM[:,None],np.inf);best=cost.argmin(axis=0)[anyev];chosen=[COMBOS[i] for i in best]
  profile={'evaded_fraction_of_detected':anyev.sum()/max(detected.sum(),1),
   'share_cheapest_uses_pacing':np.mean([c[0]>0 for c in chosen]),'share_cheapest_uses_padding':np.mean([c[1]>0 for c in chosen]),'share_cheapest_uses_injection':np.mean([c[2]>0 for c in chosen]),
   'median_duration_s':float(np.median([c[0] for c in chosen])),'median_padding_bytes':float(np.median([c[1] for c in chosen])),'median_dummy_packets':float(np.median([c[2] for c in chosen])),
   'p90_duration_s':float(np.percentile([c[0] for c in chosen],90)),'p90_padding_bytes':float(np.percentile([c[1] for c in chosen],90)),'p90_dummy_packets':float(np.percentile([c[2] for c in chosen],90))}
 choice=rng.integers(0,len(COMBOS),size=base.shape[0]);random_evade=evade[choice,np.arange(base.shape[0])]
 random_drop=base_recall*(random_evade.sum()/max(detected.sum(),1))
 return base_recall,drops,profile,random_drop,float(pace.mean()),float(pad.mean()),float(inj.mean())
scenarios=load_all();rng=np.random.default_rng(SEED);rows=[];profiles=[];randoms=[]
for target,test in scenarios.items():
 train_loso=sample_train([v for k,v in scenarios.items()if k!=target])
 a,b=train_test_split(test,test_size=0.5,stratify=test.y,random_state=SEED);train_within=sample_train([a.reset_index(drop=True)])
 specs=[('LOSO_HGB_ALL9','HGB','ALL9',train_loso,test),('LOSO_HGB_NO_PROTO','HGB','NO_PROTO',train_loso,test),('LOSO_LR_ALL9','LR','ALL9',train_loso,test),
  ('WITHIN_HGB_ALL9','HGB','ALL9',train_within,b),('WITHIN_HGB_NO_PROTO','HGB','NO_PROTO',train_within,b)]
 for name,kind,fs,train,evalset in specs:
  predict=make_predictor(kind,fs,train);mal=evalset[evalset.y==1];mal=mal.sample(min(ATTACK_N,len(mal)),random_state=SEED).reset_index(drop=True)
  for variant in['conservative','liberal']:
   recall,drops,profile,random_drop,pace,pad,inj=analyse(predict,mal,variant,rng)
   for primitive,drop in drops.items():
    rows.append({'held_out_target':target,'detector':name,'features':fs,'eligibility':variant,'primitive_set':primitive,'baseline_recall':recall,'upper_bound_recall_drop':drop,'eligible_pacing':pace,'eligible_padding':pad,'eligible_injection':inj})
   randoms.append({'held_out_target':target,'detector':name,'eligibility':variant,'worst_case_all_combined_drop':drops['all_combined'],'random_choice_drop':random_drop})
   if profile:profiles.append({'held_out_target':target,'detector':name,'eligibility':variant,**profile})
res=pd.DataFrame(rows);prof=pd.DataFrame(profiles);rand=pd.DataFrame(randoms)
res.to_csv(OUT/'E4_union_grid_bounds_full.csv',index=False);prof.to_csv(OUT/'E4_cheapest_evasion_profiles.csv',index=False);rand.to_csv(OUT/'E5_random_vs_worst_case.csv',index=False)
cons=res[res.eligibility=='conservative']
pivot=cons.pivot_table(index=['detector','primitive_set'],columns='held_out_target',values='upper_bound_recall_drop').round(4)
attackable=cons[(cons.primitive_set=='all_combined')&(cons.upper_bound_recall_drop>=GATE_DROP)]
attackable_all9=attackable[attackable.features=='ALL9']
gate='ATTACKABLE_REGIME_REQUIRES_PACKET_VALIDITY_SUITES' if len(attackable_all9) else 'NO_ATTACKABLE_REGIME'
amend={'created_utc':datetime.now(timezone.utc).isoformat(),'amends':'TRACE_BOUNDARY_ANALYSIS_PROTOCOL_v1','reason':'The escalated 10x grid was not a superset of the declared grid (e.g. 0.1 s, 100 B, 1 packet were absent), so bounds were non-monotone; gate re-evaluated on the union grid.',
 'union_grid':{'duration_s':DUR,'padding_bytes':PAD,'dummy_header_packets':INJ},'gate_rule':'ATTACKABLE if any conservative-eligibility ALL9 all_combined upper-bound drop >= 0.05','gate_threshold':GATE_DROP,
 'gate_result':gate,'attackable_cases':attackable_all9[['held_out_target','detector','upper_bound_recall_drop']].round(4).to_dict('records'),'prospective_confirmation':False,
 'interpretation':'Upper bounds on re-extracted counters under eligibility assumptions; packet-level validity not shown.'}
(OUT/'TRACE_BOUNDARY_ANALYSIS_PROTOCOL_v1_AMENDMENT_UNION_GRID.json').write_text(json.dumps(amend,indent=2))
(OUT/'receipt.json').write_text(json.dumps({'output_directory':str(OUT),'gate_result_union_grid':gate,'attackable_ALL9_cases':len(attackable_all9),'models_for_confirmatory_use_trained':False,'attacks_on_real_packets_executed':False,'prospective_confirmation':False},indent=2))
print(json.dumps({'output_directory':str(OUT),'gate_result_union_grid':gate,'attackable_ALL9_cases':len(attackable_all9)},indent=2))
print('\nE4 - UNION-GRID UPPER-BOUND RECALL DROP BY PRIMITIVE (conservative eligibility)');print(pivot.to_string())
print('\nE4 - CHEAPEST-EVASION PROFILES (conservative; cases with any evasion)');print(prof[prof.eligibility=='conservative'].round(4).to_string(index=False) if not prof.empty else 'None')
print('\nE5 - RANDOM CHOICE vs WORST CASE (conservative)');print(rand[rand.eligibility=='conservative'].round(4).to_string(index=False))
print('\nE6 - AMENDED GATE:',gate);print(attackable_all9[['held_out_target','detector','upper_bound_recall_drop']].round(4).to_string(index=False) if len(attackable_all9) else 'No ALL9 attackable case')
