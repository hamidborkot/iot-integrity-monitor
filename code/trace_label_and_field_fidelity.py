"""Reuse completed clean replay: full-field fidelity + concrete rule applicability.
No Zeek rerun, model fitting, label replacement, attack, or outcome-driven selection.
Rule evaluation is a documented equality-only diagnostic, not certified publisher-tool reproduction.
"""
import hashlib,json,re,zipfile
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,InvalidOperation,ROUND_HALF_EVEN
from pathlib import Path
import pandas as pd

ROOT=Path('/kaggle/working/TRACE_CLEAN_REPLAY_20261011T161846072286Z')
RECOVERY=Path('/kaggle/working/TRACE_LABEL_RECOVERY_20261011T153846517131Z')
WORK=Path('/kaggle/working')
OUT=WORK/('TRACE_LABEL_FIDELITY_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(exist_ok=False)

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(8*1024**2),b''):h.update(b)
 return h.hexdigest()
def save_json(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False),encoding='utf-8')
def read_log(p):
 fields=None;rows=[]
 with p.open('r',encoding='utf-8') as f:
  for lineno,line in enumerate(f,1):
   if line.startswith('#fields'):
    fields=line.strip().split()[1:];continue
   if line.startswith('#') or not line.strip():continue
   if fields is None:raise ValueError('Missing #fields: '+str(p))
   values=line.rstrip().split()
   if len(values)!=len(fields):raise ValueError(f'Field count mismatch: {p}:{lineno}')
   row=dict(zip(fields,values));row['_line']=lineno;rows.append(row)
 return fields,rows

def key(row):
 ts=int((Decimal(row['ts'])*Decimal(1000000)).to_integral_value(rounding=ROUND_HALF_EVEN))
 return (ts,row['id.orig_h'],row['id.orig_p'],row['id.resp_h'],row['id.resp_p'],row['proto'].lower())
def typed_equal(name,a,b):
 numeric={'ts','duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_ip_bytes','resp_ip_bytes','missed_bytes','id.orig_p','id.resp_p'}
 if name in numeric and a!='-' and b!='-':
  try:return Decimal(a)==Decimal(b)
  except InvalidOperation:return False
 return a==b

selection=json.loads((ROOT/'smoke_selection.json').read_text())
receipt0=json.loads((ROOT/'receipt.json').read_text())
if receipt0.get('status')!='CLEAN_REPLAY_AND_MAPPING_SMOKE_COMPUTED':raise RuntimeError('Previous clean replay is not complete.')
reference=Path(selection['reference']);capture=Path(selection['capture']);generated=ROOT/'clean_replay/conn.log'
if not reference.is_file() or sha(reference)!=selection['reference_log_sha256']:raise RuntimeError('Reference log changed.')
if not generated.is_file():raise FileNotFoundError(generated)
ref_fields,ref=read_log(reference);gen_fields,gen=read_log(generated)
ref_map=defaultdict(list);gen_counts=Counter(key(r) for r in gen)
for r in ref:ref_map[key(r)].append(r)
if len(ref)!=receipt0['reference_scan']['records_scanned'] or len(gen)!=receipt0['generated_scan']['records_scanned']:raise RuntimeError('Log record counts changed.')

common=[f for f in ref_fields if f in gen_fields and f not in {'uid','label','detailed-label'}]
counts={f:{'string_differences':0,'typed_differences':0} for f in common}
examples=[];pairs=[]
for g in gen:
 found=ref_map.get(key(g),[])
 if len(found)!=1 or gen_counts[key(g)]!=1:raise RuntimeError('Exact key is unmatched or ambiguous; do not transfer labels.')
 r=found[0];pairs.append((r,g))
 for field in common:
  if r[field]!=g[field]:counts[field]['string_differences']+=1
  if not typed_equal(field,r[field],g[field]):
   counts[field]['typed_differences']+=1
   if len([x for x in examples if x['field']==field])<5:
    examples.append({'field':field,'reference_line':r['_line'],'generated_line':g['_line'],'published_value':r[field],'replayed_value':g[field]})
pd.DataFrame([{'field':f,'records':len(pairs),**v} for f,v in counts.items()]).to_csv(OUT/'all_shared_field_fidelity.csv',index=False)
pd.DataFrame(examples).to_csv(OUT/'field_difference_examples.csv',index=False)

sources=pd.read_csv(RECOVERY/'publisher_retrieval_receipts.csv',keep_default_na=False)
rows=sources[(sources.kind=='publisher_rules')&(sources.scenario==selection['scenario'])]
if len(rows)!=1:raise RuntimeError('Exactly one publisher rule file required for this replayed scenario.')
source=rows.iloc[0];rule_path=Path(source['path'])
if not rule_path.is_file() or sha(rule_path)!=source['sha256']:raise RuntimeError('Publisher rule checksum mismatch.')
rule_text=rule_path.read_text()
active=[s.split('#',1)[0].strip() for s in rule_text.splitlines()]
active=[s for s in active if s]
if any(re.search(r'xxx\.xxx\.xxx\.xxx|(?:srcPort|dstPort)\s*=\s*xx\b',s,re.I) for s in active):raise RuntimeError('Placeholder template cannot be applied.')
field_map={'srcIP':'id.orig_h','dstIP':'id.resp_h','srcPort':'id.orig_p','dstPort':'id.resp_p','Proto':'proto'}
rules=[];current=None
for line in active:
 if not line.startswith('-'):
  if not line.endswith(':') or line.endswith('::'):raise RuntimeError('Unsupported heading syntax; no silent rule repair: '+line)
  heading=line[:-1].strip();parts=heading.split(',',1);binary=parts[0].strip()
  if binary not in {'Background','Benign','Malicious'}:raise RuntimeError('Unsupported label: '+heading)
  current={'generic':binary,'detail':parts[1].strip() if len(parts)>1 else ''};continue
 if current is None:raise RuntimeError('Rule has no label heading.')
 terms=[]
 for atom in line[1:].strip().split('&'):
  match=re.fullmatch(r'\s*([A-Za-z]+)\s*=\s*([^\s&]+)\s*',atom)
  if not match or match.group(1) not in field_map:raise RuntimeError('Unsupported rule term; no guessed semantics: '+atom)
  terms.append((match.group(1),match.group(2)))
 rules.append({**current,'conditions':terms})
save_json(OUT/'parsed_concrete_rules.json',{'source_sha256':source['sha256'],'source_url':source['url_final'],
 'semantics':'AND terms; OR lines; sequential last-match overwrites, as stated in downloaded file; equality only; protocol case-insensitive',
 'published_tool_fidelity_verified':False,'rules':rules})

def evaluate(row):
 assigned='UNMATCHED';detail='';winner=None;hits=0
 for number,rule in enumerate(rules):
  ok=True
  for field,value in rule['conditions']:
   actual=row[field_map[field]]
   if value.lower()=='all':continue
   if field=='Proto':equal=actual.lower()==value.lower()
   elif field in {'srcPort','dstPort'}:
    try:equal=int(actual)==int(value)
    except ValueError:equal=False
   else:equal=actual==value
   if not equal:ok=False;break
  if ok:assigned=rule['generic'];detail=rule['detail'];winner=number;hits+=1
 return assigned,detail,winner,hits

comparison=[];confusion=Counter();prediction_invariance=0;published_counts=Counter();unrecognized=0
linked=[]
for r,g in pairs:
 published=r.get('label','').strip().lower()
 if published not in {'benign','malicious'}:unrecognized+=1
 published_counts[published]+=1
 rp,rd,rule_number,hit_count=evaluate(r);gp,gd,grule,ghits=evaluate(g)
 agree=rp.lower()==published;confusion[(published,rp.lower())]+=1
 if (rp,rd)!=(gp,gd):prediction_invariance+=1
 comparison.append({'reference_line':r['_line'],'generated_line':g['_line'],'published_label':r.get('label',''),
  'published_detailed_label':r.get('detailed-label',''),'rule_predicted_generic':rp,'rule_predicted_detail':rd,
  'binary_agrees':agree,'winning_rule':rule_number,'matched_rule_count':hit_count,
  'same_rule_result_on_reextracted_fields':(rp,rd)==(gp,gd)})
 # Keep supplied labels, never replace them with rule predictions.
 linked.append({**{f:g[f] for f in gen_fields},'published_label':r.get('label',''),
  'published_detailed_label':r.get('detailed-label',''),'reference_line':r['_line'],'generated_line':g['_line'],
  'source_scenario':selection['scenario'],'source_pcap_sha256':selection['pcap_sha256'],
  'reference_log_sha256':selection['reference_log_sha256'],'replayed_log_sha256':sha(generated) if not linked else linked[0]['replayed_log_sha256']})
pd.DataFrame(comparison).to_csv(OUT/'rule_vs_published_labels.csv',index=False)
pd.DataFrame([{'published_label':k[0],'rule_predicted_generic':k[1],'records':v} for k,v in sorted(confusion.items())]).to_csv(OUT/'rule_binary_confusion.csv',index=False)
pd.DataFrame(linked).to_csv(OUT/'trace_linked_published_label_records.csv',index=False)
agreements=sum(x['binary_agrees'] for x in comparison)
receipt={'output_directory':str(OUT),'scenario':selection['scenario'],'rows':len(pairs),
 'all_unique_exact_keys_verified':True,'shared_fields_checked':len(common),
 'typed_field_difference_counts':{f:v['typed_differences'] for f,v in counts.items() if v['typed_differences']},
 'published_binary_label_counts':dict(published_counts),'unsupported_published_label_rows':unrecognized,
 'concrete_rules_evaluated':len(rules),'binary_rule_agreements':agreements,'binary_rule_disagreements':len(pairs)-agreements,
 'binary_rule_agreement_fraction':agreements/len(pairs) if pairs else None,
 'rule_result_changes_on_reextracted_fields':prediction_invariance,'published_labels_replaced':False,
 'publisher_tool_fidelity_verified':False,'label_semantics_final_approved':False,
 'packet_validity_approved':False,'confirmatory_scenario_selected':False,'models_trained':False,'attacks_executed':False,
 'clean_replay_repeated':False,'NF_changed':False,
 'next_step':'Review binary-rule disagreements and service/version differences; then expand linkage to remaining predetermined concrete-rule scenarios, with no target performance selection.'}
save_json(OUT/'receipt.json',receipt)
package=WORK/(OUT.name+'_PRIVATE_REVIEW.zip')
with zipfile.ZipFile(package,'w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(OUT.iterdir()):
  if p.is_file():z.write(p,p.name)
with zipfile.ZipFile(package) as z:
 if z.testzip() is not None:raise RuntimeError('Review ZIP integrity failure.')
print(json.dumps({**receipt,'private_review_zip':str(package),'review_zip_sha256':sha(package)},indent=2))
print('\nALL SHARED FIELD FIDELITY');print(pd.read_csv(OUT/'all_shared_field_fidelity.csv').to_string(index=False))
print('\nBINARY RULE / PUBLISHED LABEL CONFUSION');print(pd.read_csv(OUT/'rule_binary_confusion.csv').to_string(index=False))
print('\nFIRST LABEL DISAGREEMENTS');print(pd.DataFrame([r for r in comparison if not r['binary_agrees']]).head(15).to_string(index=False))
print('\nSERVICE DIFFERENCE EXAMPLES');print(pd.DataFrame([e for e in examples if e['field']=='service']).to_string(index=False))
