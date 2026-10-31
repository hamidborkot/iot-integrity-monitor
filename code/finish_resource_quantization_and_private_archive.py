"""Finish resource/INT8 fidelity computations and create a PRIVATE development snapshot.
All evaluations use existing real source-test records. No model training or attacks.
Non-neural models are not falsely reported as INT8 converted.
This does NOT finish missing raw-packet/extractor/mapping experiments or confirmation.
The snapshot may contain embedded dataset records and is NOT for automatic public upload.
"""
import hashlib
import io
import json
import os
import platform
import shutil
import time
import traceback
import warnings
import zipfile
from datetime import datetime,timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import torch
from torch import nn
from threadpoolctl import threadpool_limits

BASE=Path('/kaggle/working/fresh_all_datasets_v1')
CAL=BASE/'reference_mixture_calibration_audit_v1'
OUT=BASE/'resource_quantization_and_private_freeze_v1'
DATASETS=['CICIoT2023','CICIoMT2024','CSE','NSL','TONIoT']
BANKS=[('logistic_existing',10)]+[('MLP',s) for s in [10,11,12]]+[('GBDT',s) for s in [10,11,12]]
NEURAL_TARGETS=[f'MLP32_16_seed_{seed}' for seed in [901,902,903]]
SAMPLE_ROWS=1000
REPEATS=5
THREADS=4
WINDOW_SIZE=128
CREATE_PRIVATE_ARCHIVE=True


def save_csv(rows,path):
    frame=rows if isinstance(rows,pd.DataFrame) else pd.DataFrame(rows)
    temporary=path.with_suffix('.tmp');frame.to_csv(temporary,index=False);temporary.replace(path)


def sha(path):
    value=hashlib.sha256()
    with open(path,'rb') as handle:
        for block in iter(lambda:handle.read(1024*1024),b''): value.update(block)
    return value.hexdigest()


def number(value):
    value=pd.to_numeric(pd.Series([value]),errors='coerce').iloc[0]
    return np.nan if pd.isna(value) else float(value)


def milliseconds(function,n):
    function()
    times=[]
    for _ in range(REPEATS):
        started=time.perf_counter();function();times.append(time.perf_counter()-started)
    return float(np.median(times)*1000*1000/n)


def classifier_module(classifier):
    if hasattr(classifier,'coefs_'):
        if classifier.out_activation_!='logistic' or list(classifier.classes_)!=[0,1]:
            raise ValueError('Only saved binary MLP classifiers are supported.')
        matrices=classifier.coefs_;biases=classifier.intercepts_
        hidden={'relu':nn.ReLU,'tanh':nn.Tanh,'logistic':nn.Sigmoid,'identity':nn.Identity}[classifier.activation]
    elif hasattr(classifier,'coef_') and classifier.coef_.shape[0]==1:
        matrices=[classifier.coef_.T];biases=[classifier.intercept_];hidden=nn.Identity
    else:
        return None,None,None
    layers=[]
    for index,(matrix,bias) in enumerate(zip(matrices,biases)):
        layer=nn.Linear(matrix.shape[0],matrix.shape[1],bias=True)
        with torch.no_grad():
            layer.weight.copy_(torch.as_tensor(matrix.T,dtype=torch.float32))
            layer.bias.copy_(torch.as_tensor(bias,dtype=torch.float32))
        layers.append(layer)
        if index<len(matrices)-1: layers.append(hidden())
    layers.append(nn.Sigmoid())
    model=nn.Sequential(*layers).cpu().eval()
    for parameter in model.parameters(): parameter.requires_grad_(False)
    weight_count=sum(matrix.size for matrix in matrices)
    bias_count=sum(bias.size for bias in biases)
    return model,int(weight_count),int(bias_count)


def prepare(bundle,estimator,columns,frame,bare=False):
    if bare:
        pipeline=bundle['primary_model']
    else:
        pipeline=estimator
    values=pipeline.named_steps['imputer'].transform(frame[columns])
    values=pipeline.named_steps['scaler'].transform(values)
    if not np.isfinite(values).all(): raise ValueError('Nonfinite preprocessed real input.')
    return values


def original_probability(bundle,estimator,columns,frame,bare=False):
    if bare: return estimator.predict_proba(prepare(bundle,estimator,columns,frame,True))[:,1]
    return estimator.predict_proba(frame[columns])[:,1]


def torch_probability(module,values):
    tensor=torch.as_tensor(values,dtype=torch.float32)
    with torch.inference_mode(): return module(tensor).reshape(-1).cpu().numpy()


def state_bytes(module):
    buffer=io.BytesIO();torch.save(module.state_dict(),buffer);return len(buffer.getvalue())


def primary_neural_directory(dataset):
    receipt=json.loads((BASE/'neural_target_and_coordinated_attacks_v1'/dataset/'input_fingerprint.json').read_text())
    candidates=[]
    for root in BASE.glob('aline_gde_published_equations_v1*'):
        directory=root/dataset
        if all((directory/f'{name}.joblib').exists() and sha(directory/f'{name}.joblib')==receipt['model_sha256'][name]
               for name in NEURAL_TARGETS): candidates.append(directory)
    if not candidates: raise FileNotFoundError(f'{dataset}: saved neural target bank not found by hashes.')
    return min(candidates,key=lambda path:len(str(path)))


def signature(bundle,thresholds,p,v):
    n=len(p)//WINDOW_SIZE
    p=p[:n*WINDOW_SIZE].reshape(n,WINDOW_SIZE)
    v=v[:,:n*WINDOW_SIZE].reshape(len(v),n,WINDOW_SIZE)
    pd=p>bundle['primary_threshold'];vd=v>np.asarray(thresholds)[:,None,None]
    columns=[pd.mean(axis=1),np.maximum(p,1-p).mean(axis=1)]
    for j in range(len(v)):
        columns.extend([vd[j].mean(axis=1),np.maximum(v[j],1-v[j]).mean(axis=1),
                        (vd[j]==pd).mean(axis=1)])
    for j in range(len(v)):
        for k in range(j+1,len(v)): columns.append((vd[j]==vd[k]).mean(axis=1))
    return np.column_stack(columns)


def gate(bundle,bank,p,v):
    matrix=signature(bundle,bank['thresholds'],p,v)
    scores=[]
    for name in ['normal','known']:
        center,scale,threshold=bank['profiles'][name]
        scores.append(np.abs((matrix-center)/scale).mean(axis=1)/threshold)
    return np.min(np.vstack(scores),axis=0)


def private_snapshot():
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target=OUT/f'PRIVATE_development_snapshot_{stamp}.zip'
    temporary=target.with_suffix('.partial')
    # Exclude previous snapshots/current output entirely, then add current
    # resource tables explicitly. This prevents recursive archive inclusion.
    files=[path for path in BASE.rglob('*') if path.is_file()
           and OUT not in path.parents and path.suffix not in ['.tmp','.partial']]
    files += [path for path in OUT.iterdir() if path.is_file()
              and path.suffix in ['.csv','.json']]
    total=sum(path.stat().st_size for path in files)
    free=shutil.disk_usage(OUT).free
    if total*1.05>free:
        return {'status':'BLOCKED_INSUFFICIENT_FREE_DISK','input_bytes':total,'free_bytes':free}
    manifest=[]
    try:
        with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as archive:
            for path in sorted(set(files)):
                before=path.stat()
                archive_name=str(Path('development')/path.relative_to(BASE))
                digest=hashlib.sha256();written=0
                with open(path,'rb') as source,archive.open(archive_name,'w',force_zip64=True) as destination:
                    for block in iter(lambda:source.read(1024*1024),b''):
                        destination.write(block);digest.update(block);written+=len(block)
                after=path.stat()
                if before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns:
                    raise RuntimeError(f'File changed during archive creation: {path}')
                manifest.append({'archive_member':archive_name,'source':str(path),
                                 'bytes':written,'sha256':digest.hexdigest()})
            archive.writestr('PRIVATE_ARCHIVE_README.txt',
                'LOCAL DEVELOPMENT BACKUP ONLY. May contain embedded real dataset records in bundles and reference files. '
                'Do not upload publicly without dataset-license and privacy review. No packet-validity or confirmatory claim.')
            archive.writestr('snapshot_manifest.json',json.dumps(manifest,indent=2))
        # Verify every member digest against the exact bytes that were copied.
        with zipfile.ZipFile(temporary,'r') as archive:
            for entry in manifest:
                digest=hashlib.sha256()
                with archive.open(entry['archive_member']) as source:
                    for block in iter(lambda:source.read(1024*1024),b''): digest.update(block)
                if digest.hexdigest()!=entry['sha256']:
                    raise AssertionError('Snapshot member hash mismatch.')
        temporary.replace(target)
        save_csv(manifest,OUT/f'snapshot_manifest_{stamp}.csv')
        return {'status':'PRIVATE_SNAPSHOT_CREATED_AND_HASH_VERIFIED','archive':str(target),
                'archive_sha256':sha(target),'archived_files':len(manifest),
                'private_only':True,'public_redistribution_approved':False}
    except Exception:
        if temporary.exists(): temporary.unlink()
        raise


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    torch.set_num_threads(THREADS)
    engines=torch.backends.quantized.supported_engines
    engine=next((value for value in ['fbgemm','x86','qnnpack'] if value in engines),None)
    if engine is not None: torch.backends.quantized.engine=engine
    environment={'python':platform.python_version(),'platform':platform.platform(),
                 'torch':str(torch.__version__),'pandas':pd.__version__,
                 'threads':THREADS,'quantization_engine':engine,
                 'sample_rows':SAMPLE_ROWS,'repeats':REPEATS,
                 'timing_scope':'Local CPU; not energy or measured target-edge hardware'}
    settings_path=OUT/'environment.json'
    if settings_path.exists() and json.loads(settings_path.read_text())!=environment:
        raise RuntimeError('Measurement environment changed. Use a new OUT directory.')
    settings_path.write_text(json.dumps(environment,indent=2))
    resources=[];monitor_rows=[];statuses=[]
    for dataset in DATASETS:
        directory=OUT/dataset;directory.mkdir(parents=True,exist_ok=True)
        try:
            bundle_path=BASE/dataset/f'{dataset}_bundle.joblib'
            bundle=joblib.load(bundle_path)
            source=bundle['source_test_df']
            order=np.random.default_rng(1002).permutation(len(source))[:min(SAMPLE_ROWS,len(source))]
            frame=source.iloc[order].reset_index(drop=True)
            y=frame.label.to_numpy(dtype=int)
            jobs=[{'name':'frozen_logistic_primary','estimator':bundle['primary_model'],
                   'columns':bundle['primary_features'],'threshold':bundle['primary_threshold'],
                   'bare':False,'family':'logistic_primary','view_seed':np.nan}]
            banks={}
            for family,seed in BANKS:
                path=CAL/dataset/f'{family}_seed_{seed}'/'aligned_view_bank.joblib'
                bank=joblib.load(path);banks[(family,seed)]=bank
                for j,(view,columns) in enumerate(bundle['semantic_views'].items()):
                    jobs.append({'name':f'{family}_{seed}_{view}','estimator':bank['models'][view],
                        'columns':columns,'threshold':bank['thresholds'][j],'bare':False,
                        'family':family,'view_seed':seed,'view':view})
            neural_dir=primary_neural_directory(dataset)
            for name in NEURAL_TARGETS:
                jobs.append({'name':name,'estimator':joblib.load(neural_dir/f'{name}.joblib'),
                    'columns':bundle['primary_features'],'threshold':.5,'bare':True,
                    'family':'full_feature_neural_primary','view_seed':int(name.rsplit('_',1)[-1])})
            representations={};dataset_rows=[]
            with threadpool_limits(limits=THREADS):
                for job in jobs:
                    estimator=job['estimator'];columns=job['columns'];bare=job['bare']
                    classifier=estimator if bare else estimator.named_steps['classifier']
                    original=original_probability(bundle,estimator,columns,frame,bare)
                    X=prepare(bundle,estimator,columns,frame,bare)
                    baseline_time=milliseconds(lambda:original_probability(bundle,estimator,columns,frame,bare),len(frame))
                    payload=io.BytesIO();joblib.dump(estimator,payload,compress=3)
                    common={'dataset':dataset,'model_name':job['name'],'model_family':job['family'],
                        'view_seed':job['view_seed'],'records':len(frame),
                        'features':len(columns),'threshold':number(job['threshold']),
                        'compressed_sklearn_bytes':payload.tell()}
                    module,weights,biases=classifier_module(classifier)
                    original_accuracy=float(((original>job['threshold'])==y).mean())
                    dataset_rows.append({**common,'representation':'original_sklearn',
                        'accuracy':original_accuracy,'decision_flip_fraction_vs_original':0.,
                        'max_probability_difference_vs_original':0.,'end_to_end_ms_per_1000':baseline_time,
                        'trainable_scalar_parameters':number(weights+biases) if weights is not None else np.nan,
                        'estimated_coefficient_FP32_bytes':number(4*(weights+biases)) if weights is not None else np.nan,
                        'estimated_coefficient_INT8_bytes':number(weights+4*biases) if weights is not None else np.nan,
                        'coefficient_byte_estimates_include_preprocessing':False})
                    local={'original':original,'fp32':original,'int8':original,'quantizable':False}
                    if module is None:
                        dataset_rows.append({**common,'representation':'INT8_NOT_IMPLEMENTED_FOR_TREE_MODEL',
                            'status':'NOT_APPLICABLE_TO_THIS_CONVERTER'})
                    else:
                        fp32=torch_probability(module,X)
                        fp32_time=milliseconds(lambda:torch_probability(module,prepare(bundle,estimator,columns,frame,bare)),len(frame))
                        dataset_rows.append({**common,'representation':'torch_FP32_classifier',
                            'accuracy':float(((fp32>job['threshold'])==y).mean()),
                            'decision_flip_fraction_vs_original':float(((fp32>job['threshold'])!=(original>job['threshold'])).mean()),
                            'max_probability_difference_vs_original':float(np.max(np.abs(fp32-original))),
                            'end_to_end_ms_per_1000':fp32_time,'torch_state_dict_bytes':state_bytes(module)})
                        local['fp32']=fp32
                        if engine is not None:
                            try:
                                with warnings.catch_warnings(record=True) as captured:
                                    warnings.simplefilter('always')
                                    quantized=torch.ao.quantization.quantize_dynamic(module,{nn.Linear},dtype=torch.qint8,inplace=False)
                                int8=torch_probability(quantized,X)
                                int8_time=milliseconds(lambda:torch_probability(quantized,prepare(bundle,estimator,columns,frame,bare)),len(frame))
                                dataset_rows.append({**common,'representation':'torch_dynamic_INT8_classifier',
                                    'accuracy':float(((int8>job['threshold'])==y).mean()),
                                    'decision_flip_fraction_vs_original':float(((int8>job['threshold'])!=(original>job['threshold'])).mean()),
                                    'max_probability_difference_vs_original':float(np.max(np.abs(int8-original))),
                                    'end_to_end_ms_per_1000':int8_time,'torch_state_dict_bytes':state_bytes(quantized),
                                    'quantization_warnings':' | '.join(str(w.message) for w in captured)})
                                local['int8']=int8;local['quantizable']=True
                            except Exception as error:
                                dataset_rows.append({**common,'representation':'INT8_CONVERSION_FAILED','status':'FAILED','detail':str(error)})
                        else:
                            dataset_rows.append({**common,'representation':'INT8_BACKEND_UNAVAILABLE','status':'NOT_RUN'})
                    representations[job['name']]=local
                    save_csv(dataset_rows,directory/'model_resource_and_fidelity.csv')
                    print(dataset,job['name'],'RESOURCE / PRECISION AUDIT COMPUTED',flush=True)
            p=representations['frozen_logistic_primary']['original']
            for (family,seed),bank in banks.items():
                view_names=list(bundle['semantic_views'])
                quantized_views=sum(representations[f'{family}_{seed}_{view}']['quantizable'] for view in view_names)
                original_views=np.vstack([representations[f'{family}_{seed}_{view}']['original'] for view in view_names])
                original_scores=gate(bundle,bank,p,original_views)
                for mode in ['original','fp32','int8']:
                    views=np.vstack([representations[f'{family}_{seed}_{view}'][mode] for view in view_names])
                    scores=gate(bundle,bank,p,views)
                    monitor_rows.append({'dataset':dataset,'family':family,'view_seed':seed,'mode':mode,
                        'primary_detector_unchanged':True,'profiles_recalibrated':False,
                        'trusted_coverage':float((scores<=1).mean()),
                        'gate_flip_fraction_vs_original':float(((scores<=1)!=(original_scores<=1)).mean()),
                        'max_support_score_difference_vs_original':float(np.max(np.abs(scores-original_scores))),
                        'INT8_converted_view_count':quantized_views if mode=='int8' else 0,
                        'all_views_INT8':bool(quantized_views==len(view_names)) if mode=='int8' else False,
                        'mode_scope':'Eligible classifier conversions; trees remain original; primary remains original'})
            resources.extend(dataset_rows)
            statuses.append({'dataset':dataset,'status':'RESOURCE_FIDELITY_COMPUTED',
                             'INT8_failed_or_unavailable_rows':sum(row.get('representation') in ['INT8_CONVERSION_FAILED','INT8_BACKEND_UNAVAILABLE'] for row in dataset_rows),
                             'detail':'See explicit tree exclusions and any conversion failures.'})
        except Exception as error:
            statuses.append({'dataset':dataset,'status':'FAILED','INT8_failed_or_unavailable_rows':np.nan,'detail':str(error)})
            (directory/'error.txt').write_text(traceback.format_exc())
            print(dataset,'FAILED',str(error),flush=True)
        save_csv(statuses,OUT/'dataset_status.csv')
    save_csv(resources,OUT/'all_model_resources_and_precision.csv')
    save_csv(monitor_rows,OUT/'quantized_view_gate_fidelity.csv')
    capture_requirements=[]
    for dataset in DATASETS:
        capture_requirements.append({'dataset':dataset,
            'in_original_six_test_primary_family':dataset in ['CICIoT2023','CICIoMT2024'],
            'physical_attack_claim_status':'NOT_ESTABLISHED',
            'required_for_physical_claim':'Raw captures + exact original extractor/version/config + unambiguous CSV-to-trace mapping + approved primitive action rules',
            'permitted_current_scope':'Explicitly labeled exploratory tabular feature-space evidence'})
    save_csv(capture_requirements,OUT/'remaining_packet_requirements_by_claim.csv')
    protocol={'computations':['CPU resource/FP32/INT8 fidelity','Frozen-profile quantized-view gate fidelity','Private development snapshot'],
        'data':'Existing real records only; no training or synthetic data',
        'INT8':'Actual dynamic quantization for eligible linear/MLP classifiers; trees excluded explicitly',
        'memory':'Coefficient-byte estimates and serialized-state sizes are not runtime peak RAM measurements',
        'hardware':'Current CPU only; no energy or target-edge-device claim',
        'gate':'Primary and calibrated profiles unchanged; no test-based recalibration',
        'remaining':['Packet inputs/extractor/record mapping','Provenance-approved primitive attacks',
                     'Fresh independent source-pair confirmation','Untouched boundary data','Proof/claim and baseline-method review'],
        'study_complete':False,'private_snapshot_public_upload_approved':False}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2))
    try:
        archive_status=private_snapshot() if CREATE_PRIVATE_ARCHIVE else {'status':'NOT_REQUESTED'}
    except Exception as error:
        archive_status={'status':'FAILED','detail':str(error)}
        (OUT/'snapshot_error.txt').write_text(traceback.format_exc())
    (OUT/'private_snapshot_receipt.json').write_text(json.dumps(archive_status,indent=2))
    print('\nRESOURCE AUDIT STATUS\n'+pd.DataFrame(statuses).to_string(index=False),flush=True)
    print('\nPRIVATE SNAPSHOT STATUS\n'+json.dumps(archive_status,indent=2),flush=True)
    return statuses,archive_status

if __name__=='__main__':
    RESOURCE_STATUS,ARCHIVE_STATUS=main()
