"""Paired development statistics; never relabel inspected results as confirmation."""
import argparse,itertools,json
from pathlib import Path
import numpy as np
import pandas as pd
FAMILY={(d,a) for d in ['CICIoT2023','CICIoMT2024'] for a in ['whitebox','transfer','sparse']}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--units',required=True);ap.add_argument('--out',required=True)
    args=ap.parse_args();out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    df=pd.read_csv(args.units)
    required=['dataset','attack','pair_id','model_seed','baseline','baseline_error','monitor_error']
    if not set(required).issubset(df):raise ValueError('Required columns: '+','.join(required))
    if df[required].isna().any().any():raise ValueError('Missing unit metadata or errors.')
    keys=['dataset','attack','pair_id','model_seed']
    if df.duplicated(keys).any():raise ValueError('Multiple rows per pair x model-seed unit. Aggregate only by your predeclared rule.')
    if set(zip(df.dataset,df.attack))!=FAMILY:raise ValueError('Input must contain exactly the six dataset/attack cells.')
    for d,g in df.groupby('dataset'):
        if g.baseline.nunique()!=1:raise ValueError('Baseline changes across attack cells for '+d)
    for c in ['baseline_error','monitor_error']:
        df[c]=pd.to_numeric(df[c],errors='raise')
        if not np.isfinite(df[c]).all() or (df[c]<0).any():raise ValueError('Invalid '+c)
    rng=np.random.default_rng(481516);rows=[]
    for (d,a),g in df.groupby(['dataset','attack'],sort=True):
        gain=(g.baseline_error-g.monitor_error).to_numpy(float);n=len(gain)
        if n<2:raise ValueError('At least two units required in '+d+'/'+a)
        boots=[]
        for start in range(0,19999,1000):
            count=min(1000,19999-start)
            boots.extend(gain[rng.integers(0,n,size=(count,n))].mean(axis=1))
        mean=float(gain.mean())
        if n<=16:
            null=np.asarray([np.dot(sign,gain)/n for sign in itertools.product([-1,1],repeat=n)])
            p=float(np.mean(null>=mean-1e-14));method='EXACT_PAIRED_SIGN_FLIP_UNDER_SYMMETRY'
        else:
            exceed=0;count_total=19999
            for start in range(0,count_total,1000):
                count=min(1000,count_total-start)
                null=(rng.choice([-1,1],size=(count,n))*gain).mean(axis=1)
                exceed+=int((null>=mean-1e-14).sum())
            p=(exceed+1)/(count_total+1);method='MONTE_CARLO_PAIRED_SIGN_FLIP_UNDER_SYMMETRY'
        rows.append({'dataset':d,'attack':a,'baseline':g.baseline.iloc[0],'units':n,
            'distinct_pairs':g.pair_id.nunique(),'distinct_model_seeds':g.model_seed.nunique(),
            'mean_gain':mean,'bootstrap_gain_low':float(np.quantile(boots,.025)),
            'bootstrap_gain_high':float(np.quantile(boots,.975)),'one_sided_p':p,'p_method':method,
            'confirmatory_evidence':False})
    result=pd.DataFrame(rows);order=np.argsort(result.one_sided_p.to_numpy());adjusted=np.zeros(6);running=0
    for rank,index in enumerate(order):
        running=max(running,(6-rank)*result.loc[index,'one_sided_p']);adjusted[index]=min(1,running)
    result['holm_p']=adjusted;result.to_csv(out/'six_test_development_statistics.csv',index=False)
    (out/'scope.json').write_text(json.dumps({'scope':'Exploratory/conditional unless prospective design is independently established',
        'bootstrap_unit':'pair x model_seed','sign_flip_assumption':'Joint paired differences are sign-symmetric under the null',
        'independence_not_established_by_identifiers':True,'study_complete':False},indent=2))
    print(result.to_string(index=False))
if __name__=='__main__':main()
