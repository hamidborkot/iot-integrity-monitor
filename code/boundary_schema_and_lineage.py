"""Boundary schema and lineage workbench. Reads no NF record values."""
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq
ROOT=Path('/kaggle/input/datasets/dhoogla/nftoniotv2')
OUT=Path('/kaggle/working')/('boundary_design_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
OUT.mkdir(exist_ok=False)
rows=[]
for path in sorted(ROOT.rglob('*.parquet')):
    schema=pq.read_schema(path)
    for index,field in enumerate(schema):
        rows.append({'file':str(path),'position':index+1,'feature':field.name,'arrow_type':str(field.type),
            'role_review':'REQUIRED','semantic_view':'','units':'','definition_source':'',
            'source_group_role_review':'REQUIRED','reviewed':False})
if not rows:raise FileNotFoundError('No NF Parquet schema found.')
pd.DataFrame(rows).to_csv(OUT/'NF_feature_review.csv',index=False)
lineage={
    'dataset':'NF-ToN-IoT-v2','parent_corpus':'ToN-IoT','ToN_used_in_development':True,
    'independent_corpus_claim_allowed':False,'uninspected_representation_not_equivalent_to_independent_source':True,
    'source_group_overlap_resolution':'REQUIRED_BEFORE_INDEPENDENCE_CLAIM',
    'boundary_prediction_threshold':.80,'boundary_results_used_to_tune':False,
    'record_values_loaded':False,'boundary_evaluation_completed':False,
    'eligible_source_group_definition':None,'train_calibration_target_allocation':None,
    'decision_needed':'Verify an eligible nonoverlapping source-group split, or preregister the narrower same-parent representation-transfer scope before outcomes.'}
(OUT/'lineage_and_boundary_design.json').write_text(json.dumps(lineage,indent=2))
print(json.dumps({'output_directory':str(OUT),'schema_fields':len(rows),'NF_records_loaded':False,
    'boundary_evaluation_completed':False},indent=2))
