1\. 

====================================================================================================

E1-CORRECTED-v2: TON-IoT SEMANTIC VIEW SCREENING

====================================================================================================

SOURCE

&#x20;type

ddos        20000

dos         20000

password    20000

scanning    20000

HELDOUT

&#x20;type

backdoor      20000

injection     20000

mitm           1043

ransomware    20000

xss           20000

NORMAL: 300000



SPLIT MANIFEST

&#x20;                 split  rows  attack\_fraction        row\_id\_sha256

&#x20;                train 40000              0.5 78025dbe5ed3c2dc0a04

&#x20;     normal\_reference 10000              0.0 28aac6ca25d04e85062c

&#x20;      known\_reference 20000              0.5 b0b5c96c1e92e1869024

&#x20;   source\_family\_test 40000              0.5 b1daa47ab0492388e9ce

balanced\_zero\_day\_test 50000              0.5 5da351123e0673dd3b7b



====================================================================================================

PRIMARY IDS RESULTS

====================================================================================================

&#x20;                split  rows  attack\_fraction  threshold  accuracy  balanced\_accuracy     f1  precision  recall  normal\_false\_positive\_rate  attack\_recall  mean\_attack\_probability   model  raw\_feature\_count  transformed\_feature\_count

&#x20;      known\_reference 20000              0.5     0.6995    0.8832             0.8832 0.8748     0.9424  0.8162                      0.0499         0.8162                   0.5009 primary                 30                         76

clean\_normal\_reference 10000              0.0     0.6995    0.9501             0.9501 0.0000     0.0000  0.0000                      0.0499            NaN                   0.1019 primary                 30                         76

&#x20;   source\_family\_test 40000              0.5     0.6995    0.8822             0.8822 0.8738     0.9411  0.8154                      0.0510         0.8154                   0.5019 primary                 30                         76

balanced\_zero\_day\_test 50000              0.5     0.6995    0.6494             0.6494 0.5003     0.8705  0.3510                      0.0522         0.3510                   0.3192 primary                 30                         76



====================================================================================================

SEMANTIC VIEW ELIGIBILITY RESULTS

====================================================================================================

&#x20;             view                                                                                                                                 requested\_columns                                                                                                                                    usable\_columns  raw\_feature\_count status                                                            failure\_reason  threshold  transformed\_feature\_count  clean\_normal\_fpr  source\_accuracy  source\_balanced\_accuracy  source\_attack\_recall  zero\_day\_accuracy  zero\_day\_balanced\_accuracy  zero\_day\_attack\_recall

&#x20;    context\_state                                                                                                                          proto|service|conn\_state                                                                                                                          proto|service|conn\_state                  3   PASS                                                                               0.7021                         21            0.0383           0.8396                    0.8396                0.7153             0.6549                      0.6549                  0.3457

&#x20;           volume                                                                                                src\_bytes|dst\_bytes|missed\_bytes|src\_pkts|dst\_pkts                                                                                                src\_bytes|dst\_bytes|missed\_bytes|src\_pkts|dst\_pkts                  5   FAIL                                       source\_balanced\_accuracy\_below\_0.55     0.4997                          5            0.0011           0.5000                    0.5000                0.0009             0.5014                      0.5014                  0.0038

&#x20;           timing                                                                                                                                          duration                                                                                                                                          duration                  1   FAIL          too\_few\_transformed\_features|source\_balanced\_accuracy\_below\_0.55     0.5003                          1            0.0000           0.5000                    0.5000                0.0000             0.5000                      0.5000                  0.0000

&#x20;        dns\_codes                                                                                  dns\_qclass|dns\_qtype|dns\_rcode|dns\_AA|dns\_RD|dns\_RA|dns\_rejected                                                                                  dns\_qclass|dns\_qtype|dns\_rcode|dns\_AA|dns\_RD|dns\_RA|dns\_rejected                  7   FAIL                                       source\_balanced\_accuracy\_below\_0.55     0.5580                         15            0.0008           0.5346                    0.5346                0.0700             0.5024                      0.5024                  0.0057

&#x20;        tls\_state                                                                                                ssl\_version|ssl\_cipher|ssl\_resumed|ssl\_established                                                                                                ssl\_version|ssl\_cipher|ssl\_resumed|ssl\_established                  4   FAIL                                       source\_balanced\_accuracy\_below\_0.55     0.5005                         12            0.0000           0.5000                    0.5000                0.0000             0.5000                      0.5000                  0.0000

&#x20;       http\_state http\_trans\_depth|http\_method|http\_version|http\_request\_body\_len|http\_response\_body\_len|http\_status\_code|http\_orig\_mime\_types|http\_resp\_mime\_types http\_trans\_depth|http\_method|http\_version|http\_request\_body\_len|http\_response\_body\_len|http\_status\_code|http\_orig\_mime\_types|http\_resp\_mime\_types                  8   FAIL source\_balanced\_accuracy\_below\_0.55|zero\_day\_balanced\_accuracy\_below\_0.50     0.5000                         15            0.0006           0.4999                    0.4999                0.0006             0.4998                      0.4998                  0.0000

zeek\_anomaly\_state                                                                                                                           weird\_name|weird\_notice                                                                                                                           weird\_name|weird\_notice                  2   FAIL                                       source\_balanced\_accuracy\_below\_0.55     0.5011                          7            0.0000           0.5000                    0.5000                0.0000             0.5000                      0.5000                  0.0000



====================================================================================================

E1-CORRECTED-v2 FINAL DECISION

====================================================================================================

{

&#x20; "study": "IoT\_integrity\_monitoring",

&#x20; "experiment": "E1\_corrected\_v2",

&#x20; "dataset": "TON\_IoT",

&#x20; "seed": 10,

&#x20; "pass\_": false,

&#x20; "primary\_threshold": 0.6994734351418557,

&#x20; "primary\_clean\_normal\_fpr": 0.0499,

&#x20; "primary\_source\_balanced\_accuracy": 0.8822,

&#x20; "primary\_zero\_day\_balanced\_accuracy": 0.6494,

&#x20; "accepted\_views": \[

&#x20;   "context\_state"

&#x20; ],

&#x20; "accepted\_view\_count": 1,

&#x20; "required\_minimum\_accepted\_views": 4,

&#x20; "next\_action\_if\_pass": "Proceed to E2 only.",

&#x20; "next\_action\_if\_fail": "Do not run attacks; revise schema or declare TON-IoT a boundary failure."

}





2\. 

====================================================================================================

E7.1-v2 RISK-COVERAGE POSTPROCESSING

====================================================================================================



WINDOW COLUMNS

\['dataset', 'window', 'state', 'selected\_profile', 'support\_score', 'support\_threshold', 'suspect\_view', 'min\_view\_weight', 'primary\_accuracy', 'primary\_attack\_rate', 'attack', 'epsilon', 'model\_seed', 'attack\_view', 'true\_damage', 'validity\_rate', 'changed\_feature\_rate', 'damage\_at\_least\_5pp', 'attribution\_correct']



SUMMARY COLUMNS

\['attack', 'epsilon', 'model\_seeds', 'windows', 'true\_damage', 'damage\_std', 'validity\_rate', 'changed\_feature\_rate', 'trusted\_coverage', 'suspect\_rate', 'abstain\_rate', 'trusted\_risk', 'attribution\_accuracy', 'damage\_at\_least\_5pp']



====================================================================================================

E7.1-v2 ORIGINAL FULL SEMANTIC MONITOR

====================================================================================================

&#x20;                   attack  epsilon  model\_seeds  true\_damage  trusted\_coverage  trusted\_risk  suspect\_rate  abstain\_rate  attribution\_accuracy

genuine\_surrogate\_transfer     0.10            3       0.0215            0.2222        0.1244        0.4248        0.3529                0.9804

genuine\_surrogate\_transfer     0.25            3       0.0812            0.0915        0.1584        0.5556        0.3529                0.9804

genuine\_surrogate\_transfer     0.50            3       0.1493            0.0000           NaN        0.4183        0.5817                0.9804

&#x20;sparse\_surrogate\_transfer     0.10            3       0.0195            0.5098        0.1217        0.2026        0.2876                0.8366

&#x20;sparse\_surrogate\_transfer     0.25            3       0.0717            0.0392        0.1211        0.5490        0.4118                0.9804

&#x20;sparse\_surrogate\_transfer     0.50            3       0.1360            0.0784        0.2148        0.5098        0.4118                0.9804

&#x20;         whitebox\_primary     0.10            3       0.0218            0.2157        0.1257        0.4314        0.3529                0.9804

&#x20;         whitebox\_primary     0.25            3       0.0835            0.0784        0.1582        0.5686        0.3529                0.9804

&#x20;         whitebox\_primary     0.50            3       0.1524            0.0000           NaN        0.3725        0.6275                0.9804



====================================================================================================

E7.1-v2 SEMANTIC RISK-COVERAGE CURVE

====================================================================================================

&#x20;                   attack  epsilon  support\_factor  model\_seeds  true\_damage  trusted\_coverage  trusted\_risk  rejected\_coverage

genuine\_surrogate\_transfer     0.10            0.50            3       0.0215            0.0000           NaN             1.0000

genuine\_surrogate\_transfer     0.10            0.75            3       0.0215            0.0000           NaN             1.0000

genuine\_surrogate\_transfer     0.10            1.00            3       0.0215            0.2222        0.1244             0.7778

genuine\_surrogate\_transfer     0.10            1.25            3       0.0215            0.6209        0.1221             0.3791

genuine\_surrogate\_transfer     0.10            1.50            3       0.0215            0.8824        0.1288             0.1176

genuine\_surrogate\_transfer     0.10            1.75            3       0.0215            0.9608        0.1307             0.0392

genuine\_surrogate\_transfer     0.10            2.00            3       0.0215            0.9804        0.1308             0.0196

genuine\_surrogate\_transfer     0.25            0.50            3       0.0812            0.0000           NaN             1.0000

genuine\_surrogate\_transfer     0.25            0.75            3       0.0812            0.0000           NaN             1.0000

genuine\_surrogate\_transfer     0.25            1.00            3       0.0812            0.0915        0.1584             0.9085

genuine\_surrogate\_transfer     0.25            1.25            3       0.0812            0.4967        0.1814             0.5033

genuine\_surrogate\_transfer     0.25            1.50            3       0.0812            0.8562        0.1864             0.1438

genuine\_surrogate\_transfer     0.25            1.75            3       0.0812            0.9542        0.1910             0.0458

genuine\_surrogate\_transfer     0.25            2.00            3       0.0812            1.0000        0.1916             0.0000

genuine\_surrogate\_transfer     0.50            0.50            3       0.1493            0.0000           NaN             1.0000

genuine\_surrogate\_transfer     0.50            0.75            3       0.1493            0.0000           NaN             1.0000

genuine\_surrogate\_transfer     0.50            1.00            3       0.1493            0.0000           NaN             1.0000

genuine\_surrogate\_transfer     0.50            1.25            3       0.1493            0.0458        0.2222             0.9542

genuine\_surrogate\_transfer     0.50            1.50            3       0.1493            0.5033        0.2462             0.4967

genuine\_surrogate\_transfer     0.50            1.75            3       0.1493            0.8431        0.2539             0.1569

genuine\_surrogate\_transfer     0.50            2.00            3       0.1493            0.9804        0.2596             0.0196

&#x20;sparse\_surrogate\_transfer     0.10            0.50            3       0.0195            0.0000           NaN             1.0000

&#x20;sparse\_surrogate\_transfer     0.10            0.75            3       0.0195            0.1438        0.1130             0.8562

&#x20;sparse\_surrogate\_transfer     0.10            1.00            3       0.0195            0.5098        0.1217             0.4902

&#x20;sparse\_surrogate\_transfer     0.10            1.25            3       0.0195            0.8627        0.1262             0.1373

&#x20;sparse\_surrogate\_transfer     0.10            1.50            3       0.0195            0.9216        0.1268             0.0784

&#x20;sparse\_surrogate\_transfer     0.10            1.75            3       0.0195            0.9869        0.1281             0.0131

&#x20;sparse\_surrogate\_transfer     0.10            2.00            3       0.0195            1.0000        0.1279             0.0000

&#x20;sparse\_surrogate\_transfer     0.25            0.50            3       0.0717            0.0000           NaN             1.0000

&#x20;sparse\_surrogate\_transfer     0.25            0.75            3       0.0717            0.0000           NaN             1.0000

&#x20;sparse\_surrogate\_transfer     0.25            1.00            3       0.0717            0.0392        0.1211             0.9608

&#x20;sparse\_surrogate\_transfer     0.25            1.25            3       0.0717            0.3203        0.1687             0.6797

&#x20;sparse\_surrogate\_transfer     0.25            1.50            3       0.0717            0.7451        0.1735             0.2549

&#x20;sparse\_surrogate\_transfer     0.25            1.75            3       0.0717            0.8889        0.1781             0.1111

&#x20;sparse\_surrogate\_transfer     0.25            2.00            3       0.0717            0.9804        0.1811             0.0196

&#x20;sparse\_surrogate\_transfer     0.50            0.50            3       0.1360            0.0000           NaN             1.0000

&#x20;sparse\_surrogate\_transfer     0.50            0.75            3       0.1360            0.0000           NaN             1.0000

&#x20;sparse\_surrogate\_transfer     0.50            1.00            3       0.1360            0.0784        0.2148             0.9216

&#x20;sparse\_surrogate\_transfer     0.50            1.25            3       0.1360            0.4314        0.2330             0.5686

&#x20;sparse\_surrogate\_transfer     0.50            1.50            3       0.1360            0.7908        0.2381             0.2092

&#x20;sparse\_surrogate\_transfer     0.50            1.75            3       0.1360            0.9608        0.2447             0.0392

&#x20;sparse\_surrogate\_transfer     0.50            2.00            3       0.1360            1.0000        0.2458             0.0000

&#x20;         whitebox\_primary     0.10            0.50            3       0.0218            0.0000           NaN             1.0000

&#x20;         whitebox\_primary     0.10            0.75            3       0.0218            0.0000           NaN             1.0000

&#x20;         whitebox\_primary     0.10            1.00            3       0.0218            0.2157        0.1257             0.7843

&#x20;         whitebox\_primary     0.10            1.25            3       0.0218            0.6078        0.1220             0.3922

&#x20;         whitebox\_primary     0.10            1.50            3       0.0218            0.8824        0.1290             0.1176

&#x20;         whitebox\_primary     0.10            1.75            3       0.0218            0.9608        0.1311             0.0392

&#x20;         whitebox\_primary     0.10            2.00            3       0.0218            0.9804        0.1311             0.0196

&#x20;         whitebox\_primary     0.25            0.50            3       0.0835            0.0000           NaN             1.0000

&#x20;         whitebox\_primary     0.25            0.75            3       0.0835            0.0000           NaN             1.0000

&#x20;         whitebox\_primary     0.25            1.00            3       0.0835            0.0784        0.1582             0.9216

&#x20;         whitebox\_primary     0.25            1.25            3       0.0835            0.5098        0.1836             0.4902

&#x20;         whitebox\_primary     0.25            1.50            3       0.0835            0.8627        0.1889             0.1373

&#x20;         whitebox\_primary     0.25            1.75            3       0.0835            0.9412        0.1919             0.0588

&#x20;         whitebox\_primary     0.25            2.00            3       0.0835            1.0000        0.1941             0.0000

&#x20;         whitebox\_primary     0.50            0.50            3       0.1524            0.0000           NaN             1.0000

&#x20;         whitebox\_primary     0.50            0.75            3       0.1524            0.0000           NaN             1.0000

&#x20;         whitebox\_primary     0.50            1.00            3       0.1524            0.0000           NaN             1.0000

&#x20;         whitebox\_primary     0.50            1.25            3       0.1524            0.0196        0.2188             0.9804

&#x20;         whitebox\_primary     0.50            1.50            3       0.1524            0.4314        0.2475             0.5686

&#x20;         whitebox\_primary     0.50            1.75            3       0.1524            0.7843        0.2533             0.2157

&#x20;         whitebox\_primary     0.50            2.00            3       0.1524            0.9804        0.2623             0.0196



====================================================================================================

E7.1-v2 COLLAPSE-DETECTION SUMMARY

====================================================================================================

&#x20;support\_factor  collapsed\_runs  noncollapsed\_runs  collapse\_recall  false\_alarm\_rate  mean\_alarm\_rate\_collapsed  mean\_alarm\_rate\_noncollapsed

&#x20;          0.50              18                  9           1.0000            1.0000                     1.0000                        1.0000

&#x20;          0.75              18                  9           1.0000            1.0000                     1.0000                        0.9521

&#x20;          1.00              18                  9           1.0000            0.7778                     0.9521                        0.6841

&#x20;          1.25              18                  9           0.7778            0.0000                     0.6961                        0.3028

&#x20;          1.50              18                  9           0.2778            0.0000                     0.3017                        0.1046

&#x20;          1.75              18                  9           0.0000            0.0000                     0.1046                        0.0305

&#x20;          2.00              18                  9           0.0000            0.0000                     0.0098                        0.0131



====================================================================================================

E7.1-v2 WINDOW-LEVEL COLLAPSE AUROC

====================================================================================================

{

&#x20; "dataset": "CICIoT2023",

&#x20; "damage\_collapse\_threshold": 0.05,

&#x20; "window\_level\_support\_auc": 0.7595060779092563,

&#x20; "number\_windows": 1377,

&#x20; "collapsed\_windows": 918,

&#x20; "noncollapsed\_windows": 459

}



3\. 

adaptive\_surrogate\_search seed=10 eps=0.25 lambda=0.0 scale=1.0 damage=0.0823 trusted=0.0784 abstain=0.3529

adaptive\_surrogate\_search seed=10 eps=0.25 lambda=0.25 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.25 lambda=0.5 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.25 lambda=1.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.25 lambda=2.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.25 lambda=5.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.5 lambda=0.0 scale=1.0 damage=0.1509 trusted=0.0000 abstain=0.6078

adaptive\_surrogate\_search seed=10 eps=0.5 lambda=0.25 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.5 lambda=0.5 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.5 lambda=1.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.5 lambda=2.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=10 eps=0.5 lambda=5.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.25 lambda=0.0 scale=1.0 damage=0.0834 trusted=0.0784 abstain=0.3529

adaptive\_surrogate\_search seed=11 eps=0.25 lambda=0.25 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.25 lambda=0.5 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.25 lambda=1.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.25 lambda=2.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.25 lambda=5.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.5 lambda=0.0 scale=1.0 damage=0.1523 trusted=0.0000 abstain=0.6275

adaptive\_surrogate\_search seed=11 eps=0.5 lambda=0.25 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.5 lambda=0.5 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.5 lambda=1.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.5 lambda=2.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=11 eps=0.5 lambda=5.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.25 lambda=0.0 scale=1.0 damage=0.0779 trusted=0.1176 abstain=0.3529

adaptive\_surrogate\_search seed=12 eps=0.25 lambda=0.25 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.25 lambda=0.5 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.25 lambda=1.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.25 lambda=2.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.25 lambda=5.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.5 lambda=0.0 scale=1.0 damage=0.1448 trusted=0.0000 abstain=0.5098

adaptive\_surrogate\_search seed=12 eps=0.5 lambda=0.25 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.5 lambda=0.5 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.5 lambda=1.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.5 lambda=2.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588

adaptive\_surrogate\_search seed=12 eps=0.5 lambda=5.0 scale=0.0 damage=0.0002 trusted=0.8824 abstain=0.0588



====================================================================================================

CICIoT2023 E8 ADAPTIVE ATTACK SUMMARY

====================================================================================================

&#x20;epsilon  lambda  model\_seeds  selected\_scale  true\_damage  damage\_std  trusted\_coverage  suspect\_rate  abstain\_rate  trusted\_risk  attribution\_accuracy  validity\_rate  adaptive\_objective

&#x20;   0.25    0.00            3             1.0       0.0812      0.0029            0.0915        0.5556        0.3529        0.1584                0.9804            1.0              0.0812

&#x20;   0.25    0.25            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              0.2060

&#x20;   0.25    0.50            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              0.4119

&#x20;   0.25    1.00            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              0.8237

&#x20;   0.25    2.00            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              1.6472

&#x20;   0.25    5.00            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              4.1178

&#x20;   0.50    0.00            3             1.0       0.1493      0.0040            0.0000        0.4183        0.5817           NaN                0.9804            1.0              0.1493

&#x20;   0.50    0.25            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              0.2060

&#x20;   0.50    0.50            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              0.4119

&#x20;   0.50    1.00            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              0.8237

&#x20;   0.50    2.00            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              1.6472

&#x20;   0.50    5.00            3             0.0       0.0002      0.0000            0.8824        0.0588        0.0588        0.1073                0.2941            1.0              4.1178



====================================================================================================

CICIoT2023 E8 STEALTH-DAMAGE FRONTIER

====================================================================================================

&#x20;epsilon  lambda  selected\_scale  true\_damage  trusted\_coverage  suspect\_rate  abstain\_rate  trusted\_risk  validity\_rate

&#x20;   0.25    0.00             1.0       0.0812            0.0915        0.5556        0.3529        0.1584            1.0

&#x20;   0.25    0.25             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.25    0.50             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.25    1.00             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.25    2.00             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.25    5.00             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.50    0.00             1.0       0.1493            0.0000        0.4183        0.5817           NaN            1.0

&#x20;   0.50    0.25             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.50    0.50             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.50    1.00             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.50    2.00             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0

&#x20;   0.50    5.00             0.0       0.0002            0.8824        0.0588        0.0588        0.1073            1.0



4\. 

====================================================================================================

NSL-KDD E1.1 MANUAL SEMANTIC VIEW RESULTS

====================================================================================================

dataset               view  raw\_feature\_count status         failure\_reason  threshold  transformed\_feature\_count  clean\_normal\_fpr  source\_balanced\_accuracy  source\_attack\_recall  zero\_day\_balanced\_accuracy  zero\_day\_attack\_recall

NSL-KDD   protocol\_service                  8   PASS                            0.4531                         40            0.0446                    0.9253                0.8808                      0.5147                  0.0584

NSL-KDD        volume\_size                  7   FAIL source\_bacc\_below\_0.55     0.5290                          7            0.0487                    0.5218                0.0820                      0.5470                  0.1364

NSL-KDD  connection\_counts                  7   PASS                            0.8408                          7            0.0487                    0.5823                0.2098                      0.5855                  0.2178

NSL-KDD   error\_rate\_state                  8   PASS                            0.8722                          8            0.0487                    0.7392                0.5129                      0.5276                  0.1010

NSL-KDD host\_service\_rates                  7   PASS                            0.7669                          7            0.0487                    0.6567                0.3668                      0.5874                  0.2277



DECISION

{

&#x20; "dataset": "NSL-KDD",

&#x20; "source\_families": \[

&#x20;   "apache2",

&#x20;   "back",

&#x20;   "guess\_passwd",

&#x20;   "ipsweep",

&#x20;   "mscan",

&#x20;   "neptune",

&#x20;   "nmap",

&#x20;   "portsweep",

&#x20;   "processtable"

&#x20; ],

&#x20; "heldout\_families": \[

&#x20;   "satan",

&#x20;   "smurf",

&#x20;   "teardrop",

&#x20;   "warezclient",

&#x20;   "warezmaster"

&#x20; ],

&#x20; "primary\_source\_bacc": 0.941747572815534,

&#x20; "primary\_zero\_day\_bacc": 0.6077372262773723,

&#x20; "accepted\_views": \[

&#x20;   "protocol\_service",

&#x20;   "connection\_counts",

&#x20;   "error\_rate\_state",

&#x20;   "host\_service\_rates"

&#x20; ],

&#x20; "accepted\_view\_count": 4,

&#x20; "pass": true

}



====================================================================================================

CSE + NSL E1.1 COMPLETE

====================================================================================================

&#x20;       dataset                                                                                                source\_families                                                         heldout\_families  primary\_source\_bacc  primary\_zero\_day\_bacc                                                              accepted\_views  accepted\_view\_count  pass

CSE-CIC-IDS2018 \[Bot, Brute Force -Web, DDOS attack-HOIC, DDOS attack-LOIC-UDP, DDoS attacks-LOIC-HTTP, DoS attacks-GoldenEye] \[DoS attacks-Hulk, DoS attacks-Slowloris, Infilteration, SSH-Bruteforce]             0.961988               0.689481                     \[timing\_rate, volume\_size, directionality, count\_burst]                    4  True

&#x20;       NSL-KDD                          \[apache2, back, guess\_passwd, ipsweep, mscan, neptune, nmap, portsweep, processtable]                       \[satan, smurf, teardrop, warezclient, warezmaster]             0.941748               0.607737 \[protocol\_service, connection\_counts, error\_rate\_state, host\_service\_rates]                    4  True




5. 

CICIoT2023 logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0569 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0569 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0606 trusted=0.9524 hidden\_collapse=0.5952

CICIoT2023 logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0606 trusted=0.9524 hidden\_collapse=0.5952

CICIoT2023 logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0603 trusted=0.9524 hidden\_collapse=0.5952

CICIoT2023 logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0603 trusted=0.9524 hidden\_collapse=0.5952

CICIoT2023 logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0610 trusted=0.9524 hidden\_collapse=0.4762

CICIoT2023 logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0610 trusted=0.9524 hidden\_collapse=0.4762

CICIoT2023 logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0592 trusted=0.9524 hidden\_collapse=0.4524

CICIoT2023 logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0592 trusted=0.9524 hidden\_collapse=0.4524

CICIoT2023 logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0592 trusted=0.9762 hidden\_collapse=0.4524

CICIoT2023 logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0592 trusted=0.9762 hidden\_collapse=0.4524

CICIoT2023 MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0707 trusted=0.9762 hidden\_collapse=0.7619

CICIoT2023 MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0707 trusted=0.9762 hidden\_collapse=0.7619

CICIoT2023 MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0709 trusted=0.9762 hidden\_collapse=0.7619

CICIoT2023 MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0709 trusted=0.9762 hidden\_collapse=0.7619

CICIoT2023 MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0716 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0716 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0958 trusted=0.9762 hidden\_collapse=0.8095

CICIoT2023 MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0958 trusted=0.9762 hidden\_collapse=0.8095

CICIoT2023 MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0952 trusted=0.9762 hidden\_collapse=0.8810

CICIoT2023 MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0952 trusted=0.9762 hidden\_collapse=0.8810

CICIoT2023 MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0982 trusted=0.9762 hidden\_collapse=0.8333

CICIoT2023 MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0982 trusted=0.9762 hidden\_collapse=0.8333

CICIoT2023 MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0699 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0699 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0686 trusted=0.9762 hidden\_collapse=0.7381

CICIoT2023 MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0686 trusted=0.9762 hidden\_collapse=0.7381

CICIoT2023 MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0718 trusted=0.9762 hidden\_collapse=0.8095

CICIoT2023 MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0718 trusted=0.9762 hidden\_collapse=0.8095

CICIoT2023 MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0779 trusted=0.9762 hidden\_collapse=0.7381

CICIoT2023 MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0779 trusted=0.9762 hidden\_collapse=0.7381

CICIoT2023 MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0844 trusted=0.9762 hidden\_collapse=0.8095

CICIoT2023 MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0844 trusted=0.9762 hidden\_collapse=0.8095

CICIoT2023 MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0830 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0830 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0698 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0698 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0703 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0703 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0703 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0703 trusted=0.9762 hidden\_collapse=0.7857

CICIoT2023 MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.1097 trusted=0.9762 hidden\_collapse=0.8333

CICIoT2023 MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.1097 trusted=0.9762 hidden\_collapse=0.8333

CICIoT2023 MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.1099 trusted=0.9762 hidden\_collapse=0.8571

CICIoT2023 MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.1099 trusted=0.9762 hidden\_collapse=0.8571

CICIoT2023 MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.1101 trusted=0.9762 hidden\_collapse=0.8571

CICIoT2023 MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.1101 trusted=0.9762 hidden\_collapse=0.8571

CICIoT2023 GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0543 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0543 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0545 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0545 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0539 trusted=0.9762 hidden\_collapse=0.5476

CICIoT2023 GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0539 trusted=0.9762 hidden\_collapse=0.5476

CICIoT2023 GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0718 trusted=0.9524 hidden\_collapse=0.6429

CICIoT2023 GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0718 trusted=0.9524 hidden\_collapse=0.6429

CICIoT2023 GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0664 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0664 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0696 trusted=0.9762 hidden\_collapse=0.6190

CICIoT2023 GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0696 trusted=0.9762 hidden\_collapse=0.6190

CICIoT2023 GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0543 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0543 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0545 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0545 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0539 trusted=0.9762 hidden\_collapse=0.5476

CICIoT2023 GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0539 trusted=0.9762 hidden\_collapse=0.5476

CICIoT2023 GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0718 trusted=0.9524 hidden\_collapse=0.6429

CICIoT2023 GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0718 trusted=0.9524 hidden\_collapse=0.6429

CICIoT2023 GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0664 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0664 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0696 trusted=0.9762 hidden\_collapse=0.6190

CICIoT2023 GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0696 trusted=0.9762 hidden\_collapse=0.6190

CICIoT2023 GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0543 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0543 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0545 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0545 trusted=0.9524 hidden\_collapse=0.5238

CICIoT2023 GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0539 trusted=0.9762 hidden\_collapse=0.5476

CICIoT2023 GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0539 trusted=0.9762 hidden\_collapse=0.5476

CICIoT2023 GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0718 trusted=0.9524 hidden\_collapse=0.6429

CICIoT2023 GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0718 trusted=0.9524 hidden\_collapse=0.6429

CICIoT2023 GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0664 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0664 trusted=0.9762 hidden\_collapse=0.5952

CICIoT2023 GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0696 trusted=0.9762 hidden\_collapse=0.6190

CICIoT2023 GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0696 trusted=0.9762 hidden\_collapse=0.6190

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0012 trusted=0.9487 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0012 trusted=0.9487 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0012 trusted=0.9487 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0012 trusted=0.9487 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0012 trusted=0.9487 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0012 trusted=0.9487 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0078 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0078 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0078 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0078 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0078 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0078 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0008 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0008 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0008 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0008 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0008 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0008 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0002 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0002 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0002 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0002 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0002 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0002 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0022 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0022 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0022 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0022 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0022 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0022 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0038 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0038 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0038 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0038 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0038 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0038 trusted=0.9744 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0012 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CICIoMT2024 GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0076 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

CSE GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9091 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

NSL GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=1.0000 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT logistic\_existing view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0016 trusted=0.8333 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0020 trusted=0.9167 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT MLP view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0020 trusted=0.8750 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=10 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=11 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.25 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.25 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.25 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.5 search\_seed=10 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.5 search\_seed=11 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=0.25 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000

TONIoT GBDT view\_seed=12 eps=0.5 search\_seed=12 lambda=1.0 damage=0.0000 trusted=0.9167 hidden\_collapse=0.0000



==========================================================================================

ALIGNED-GATE ADAPTIVE EVALUATION

==========================================================================================

&#x20;   dataset            family  view\_seed  epsilon  lambda  clean\_calibration\_pass  objective\_selected\_damage  trusted\_coverage  trusted\_candidate\_fraction  best\_observed\_trusted\_damage  hidden\_collapse\_fraction  box\_unreachable\_fraction  searched\_window\_fraction  max\_window\_oracle\_evaluations

CICIoMT2024              GBDT         10     0.25    0.25                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         10     0.25    1.00                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         10     0.50    0.25                       1                     0.0076            1.0000                      1.0000                        0.0076                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         10     0.50    1.00                       1                     0.0076            1.0000                      1.0000                        0.0076                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         11     0.25    0.25                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         11     0.25    1.00                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         11     0.50    0.25                       1                     0.0076            1.0000                      1.0000                        0.0076                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         11     0.50    1.00                       1                     0.0076            1.0000                      1.0000                        0.0076                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         12     0.25    0.25                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         12     0.25    1.00                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         12     0.50    0.25                       1                     0.0076            1.0000                      1.0000                        0.0076                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024              GBDT         12     0.50    1.00                       1                     0.0076            1.0000                      1.0000                        0.0076                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         10     0.25    0.25                       1                     0.0008            0.9744                      0.9744                        0.0008                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         10     0.25    1.00                       1                     0.0008            0.9744                      0.9744                        0.0008                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         10     0.50    0.25                       1                     0.0002            0.9744                      0.9744                        0.0000                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         10     0.50    1.00                       1                     0.0002            0.9744                      0.9744                        0.0000                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         11     0.25    0.25                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         11     0.25    1.00                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         11     0.50    0.25                       1                     0.0022            0.9744                      0.9744                        0.0023                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         11     0.50    1.00                       1                     0.0022            0.9744                      0.9744                        0.0023                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         12     0.25    0.25                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         12     0.25    1.00                       1                     0.0012            1.0000                      1.0000                        0.0012                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         12     0.50    0.25                       1                     0.0038            0.9744                      0.9744                        0.0039                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024               MLP         12     0.50    1.00                       1                     0.0038            0.9744                      0.9744                        0.0039                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024 logistic\_existing         10     0.25    0.25                       1                     0.0012            0.9487                      0.9487                        0.0013                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024 logistic\_existing         10     0.25    1.00                       1                     0.0012            0.9487                      0.9487                        0.0013                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024 logistic\_existing         10     0.50    0.25                       1                     0.0078            0.9744                      0.9744                        0.0080                    0.0000                    1.0000                    0.0000                              2

CICIoMT2024 logistic\_existing         10     0.50    1.00                       1                     0.0078            0.9744                      0.9744                        0.0080                    0.0000                    1.0000                    0.0000                              2

&#x20;CICIoT2023              GBDT         10     0.25    0.25                       1                     0.0543            0.9603                      0.9603                        0.0522                    0.5317                    0.0952                    0.9048                            182

&#x20;CICIoT2023              GBDT         10     0.25    1.00                       1                     0.0543            0.9603                      0.9603                        0.0522                    0.5317                    0.0952                    0.9048                            182

&#x20;CICIoT2023              GBDT         10     0.50    0.25                       1                     0.0693            0.9683                      0.9683                        0.0665                    0.6190                    0.0000                    1.0000                            182

&#x20;CICIoT2023              GBDT         10     0.50    1.00                       1                     0.0693            0.9683                      0.9683                        0.0665                    0.6190                    0.0000                    1.0000                            182

&#x20;CICIoT2023              GBDT         11     0.25    0.25                       1                     0.0543            0.9603                      0.9603                        0.0522                    0.5317                    0.0952                    0.9048                            182

&#x20;CICIoT2023              GBDT         11     0.25    1.00                       1                     0.0543            0.9603                      0.9603                        0.0522                    0.5317                    0.0952                    0.9048                            182

&#x20;CICIoT2023              GBDT         11     0.50    0.25                       1                     0.0693            0.9683                      0.9683                        0.0665                    0.6190                    0.0000                    1.0000                            182

&#x20;CICIoT2023              GBDT         11     0.50    1.00                       1                     0.0693            0.9683                      0.9683                        0.0665                    0.6190                    0.0000                    1.0000                            182

&#x20;CICIoT2023              GBDT         12     0.25    0.25                       1                     0.0543            0.9603                      0.9603                        0.0522                    0.5317                    0.0952                    0.9048                            182

&#x20;CICIoT2023              GBDT         12     0.25    1.00                       1                     0.0543            0.9603                      0.9603                        0.0522                    0.5317                    0.0952                    0.9048                            182

&#x20;CICIoT2023              GBDT         12     0.50    0.25                       1                     0.0693            0.9683                      0.9683                        0.0665                    0.6190                    0.0000                    1.0000                            182

&#x20;CICIoT2023              GBDT         12     0.50    1.00                       1                     0.0693            0.9683                      0.9683                        0.0665                    0.6190                    0.0000                    1.0000                            182

&#x20;CICIoT2023               MLP         10     0.25    0.25                       1                     0.0711            0.9762                      0.9762                        0.0700                    0.7698                    0.0952                    0.9048                            182

&#x20;CICIoT2023               MLP         10     0.25    1.00                       1                     0.0711            0.9762                      0.9762                        0.0700                    0.7698                    0.0952                    0.9048                            182

&#x20;CICIoT2023               MLP         10     0.50    0.25                       1                     0.0964            0.9762                      0.9762                        0.0951                    0.8413                    0.0000                    1.0000                            182

&#x20;CICIoT2023               MLP         10     0.50    1.00                       1                     0.0964            0.9762                      0.9762                        0.0951                    0.8413                    0.0000                    1.0000                            182

&#x20;CICIoT2023               MLP         11     0.25    0.25                       1                     0.0701            0.9762                      0.9762                        0.0692                    0.7778                    0.0952                    0.9048                            182

&#x20;CICIoT2023               MLP         11     0.25    1.00                       1                     0.0701            0.9762                      0.9762                        0.0692                    0.7778                    0.0952                    0.9048                            182

&#x20;CICIoT2023               MLP         11     0.50    0.25                       1                     0.0818            0.9762                      0.9762                        0.0803                    0.7778                    0.0000                    1.0000                            182

&#x20;CICIoT2023               MLP         11     0.50    1.00                       1                     0.0818            0.9762                      0.9762                        0.0803                    0.7778                    0.0000                    1.0000                            182

&#x20;CICIoT2023               MLP         12     0.25    0.25                       1                     0.0701            0.9762                      0.9762                        0.0690                    0.7857                    0.0952                    0.9048                            182

&#x20;CICIoT2023               MLP         12     0.25    1.00                       1                     0.0701            0.9762                      0.9762                        0.0690                    0.7857                    0.0952                    0.9048                            182

&#x20;CICIoT2023               MLP         12     0.50    0.25                       1                     0.1099            0.9762                      0.9762                        0.1090                    0.8492                    0.0000                    1.0000                            182

&#x20;CICIoT2023               MLP         12     0.50    1.00                       1                     0.1099            0.9762                      0.9762                        0.1090                    0.8492                    0.0000                    1.0000                            182

&#x20;CICIoT2023 logistic\_existing         10     0.25    0.25                       1                     0.0593            0.9603                      0.9603                        0.0574                    0.5952                    0.0952                    0.9048                            182

&#x20;CICIoT2023 logistic\_existing         10     0.25    1.00                       1                     0.0593            0.9603                      0.9603                        0.0574                    0.5952                    0.0952                    0.9048                            182

&#x20;CICIoT2023 logistic\_existing         10     0.50    0.25                       1                     0.0598            0.9603                      0.9603                        0.0556                    0.4603                    0.0000                    1.0000                            182

&#x20;CICIoT2023 logistic\_existing         10     0.50    1.00                       1                     0.0598            0.9603                      0.9603                        0.0556                    0.4603                    0.0000                    1.0000                            182

&#x20;       CSE              GBDT         10     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         10     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         10     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         10     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         11     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         11     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         11     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         11     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         12     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         12     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         12     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE              GBDT         12     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         10     0.25    0.25                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         10     0.25    1.00                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         10     0.50    0.25                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         10     0.50    1.00                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         11     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         11     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         11     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         11     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         12     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         12     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         12     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE               MLP         12     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE logistic\_existing         10     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE logistic\_existing         10     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE logistic\_existing         10     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       CSE logistic\_existing         10     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         10     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         10     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         10     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         10     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         11     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         11     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         11     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         11     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         12     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         12     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         12     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL              GBDT         12     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         10     0.25    0.25                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         10     0.25    1.00                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         10     0.50    0.25                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         10     0.50    1.00                       1                     0.0000            0.9091                      0.9091                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         11     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         11     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         11     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         11     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         12     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         12     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         12     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL               MLP         12     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL logistic\_existing         10     0.25    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL logistic\_existing         10     0.25    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL logistic\_existing         10     0.50    0.25                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;       NSL logistic\_existing         10     0.50    1.00                       1                     0.0000            1.0000                      1.0000                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         10     0.25    0.25                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         10     0.25    1.00                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         10     0.50    0.25                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         10     0.50    1.00                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         11     0.25    0.25                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         11     0.25    1.00                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         11     0.50    0.25                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         11     0.50    1.00                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         12     0.25    0.25                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         12     0.25    1.00                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         12     0.50    0.25                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT              GBDT         12     0.50    1.00                       1                     0.0000            0.9167                      0.9167                        0.0000                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         10     0.25    0.25                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         10     0.25    1.00                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         10     0.50    0.25                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         10     0.50    1.00                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         11     0.25    0.25                       1                     0.0020            0.9167                      0.9167                        0.0018                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         11     0.25    1.00                       1                     0.0020            0.9167                      0.9167                        0.0018                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         11     0.50    0.25                       1                     0.0020            0.9167                      0.9167                        0.0018                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         11     0.50    1.00                       1                     0.0020            0.9167                      0.9167                        0.0018                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         12     0.25    0.25                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         12     0.25    1.00                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         12     0.50    0.25                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT               MLP         12     0.50    1.00                       1                     0.0020            0.8750                      0.8750                        0.0019                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT logistic\_existing         10     0.25    0.25                       0                     0.0016            0.8333                      0.8333                        0.0016                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT logistic\_existing         10     0.25    1.00                       0                     0.0016            0.8333                      0.8333                        0.0016                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT logistic\_existing         10     0.50    0.25                       0                     0.0016            0.8333                      0.8333                        0.0016                    0.0000                    1.0000                    0.0000                              2

&#x20;    TONIoT logistic\_existing         10     0.50    1.00                       0                     0.0016            0.8333                      0.8333                        0.0016                    0.0000                    1.0000                    0.0000                              2


6. CICIoT2023 logistic\_existing view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CICIoT2023 logistic\_existing view\_seed=10 REAL-ORDER STRESS COMPLETE

CICIoT2023 MLP view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CICIoT2023 MLP view\_seed=10 REAL-ORDER STRESS COMPLETE

CICIoT2023 MLP view\_seed=11 REAL-MIXTURE STRESS COMPLETE

CICIoT2023 MLP view\_seed=11 REAL-ORDER STRESS COMPLETE

CICIoT2023 MLP view\_seed=12 REAL-MIXTURE STRESS COMPLETE

CICIoT2023 MLP view\_seed=12 REAL-ORDER STRESS COMPLETE

CICIoT2023 GBDT view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CICIoT2023 GBDT view\_seed=10 REAL-ORDER STRESS COMPLETE

CICIoT2023 GBDT view\_seed=11 REAL-MIXTURE STRESS COMPLETE

CICIoT2023 GBDT view\_seed=11 REAL-ORDER STRESS COMPLETE

CICIoT2023 GBDT view\_seed=12 REAL-MIXTURE STRESS COMPLETE

CICIoT2023 GBDT view\_seed=12 REAL-ORDER STRESS COMPLETE

CICIoMT2024 logistic\_existing view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CICIoMT2024 logistic\_existing view\_seed=10 REAL-ORDER STRESS COMPLETE

CICIoMT2024 MLP view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CICIoMT2024 MLP view\_seed=10 REAL-ORDER STRESS COMPLETE

CICIoMT2024 MLP view\_seed=11 REAL-MIXTURE STRESS COMPLETE

CICIoMT2024 MLP view\_seed=11 REAL-ORDER STRESS COMPLETE

CICIoMT2024 MLP view\_seed=12 REAL-MIXTURE STRESS COMPLETE

CICIoMT2024 MLP view\_seed=12 REAL-ORDER STRESS COMPLETE

CICIoMT2024 GBDT view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CICIoMT2024 GBDT view\_seed=10 REAL-ORDER STRESS COMPLETE

CICIoMT2024 GBDT view\_seed=11 REAL-MIXTURE STRESS COMPLETE

CICIoMT2024 GBDT view\_seed=11 REAL-ORDER STRESS COMPLETE

CICIoMT2024 GBDT view\_seed=12 REAL-MIXTURE STRESS COMPLETE

CICIoMT2024 GBDT view\_seed=12 REAL-ORDER STRESS COMPLETE

CSE logistic\_existing view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CSE logistic\_existing view\_seed=10 REAL-ORDER STRESS COMPLETE

CSE MLP view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CSE MLP view\_seed=10 REAL-ORDER STRESS COMPLETE

CSE MLP view\_seed=11 REAL-MIXTURE STRESS COMPLETE

CSE MLP view\_seed=11 REAL-ORDER STRESS COMPLETE

CSE MLP view\_seed=12 REAL-MIXTURE STRESS COMPLETE

CSE MLP view\_seed=12 REAL-ORDER STRESS COMPLETE

CSE GBDT view\_seed=10 REAL-MIXTURE STRESS COMPLETE

CSE GBDT view\_seed=10 REAL-ORDER STRESS COMPLETE

CSE GBDT view\_seed=11 REAL-MIXTURE STRESS COMPLETE

CSE GBDT view\_seed=11 REAL-ORDER STRESS COMPLETE

CSE GBDT view\_seed=12 REAL-MIXTURE STRESS COMPLETE

CSE GBDT view\_seed=12 REAL-ORDER STRESS COMPLETE

NSL logistic\_existing view\_seed=10 REAL-MIXTURE STRESS COMPLETE

NSL logistic\_existing view\_seed=10 REAL-ORDER STRESS COMPLETE

NSL MLP view\_seed=10 REAL-MIXTURE STRESS COMPLETE

NSL MLP view\_seed=10 REAL-ORDER STRESS COMPLETE

NSL MLP view\_seed=11 REAL-MIXTURE STRESS COMPLETE

NSL MLP view\_seed=11 REAL-ORDER STRESS COMPLETE

NSL MLP view\_seed=12 REAL-MIXTURE STRESS COMPLETE

NSL MLP view\_seed=12 REAL-ORDER STRESS COMPLETE

NSL GBDT view\_seed=10 REAL-MIXTURE STRESS COMPLETE

NSL GBDT view\_seed=10 REAL-ORDER STRESS COMPLETE

NSL GBDT view\_seed=11 REAL-MIXTURE STRESS COMPLETE

NSL GBDT view\_seed=11 REAL-ORDER STRESS COMPLETE

NSL GBDT view\_seed=12 REAL-MIXTURE STRESS COMPLETE

NSL GBDT view\_seed=12 REAL-ORDER STRESS COMPLETE

TONIoT logistic\_existing view\_seed=10 REAL-MIXTURE STRESS COMPLETE

TONIoT logistic\_existing view\_seed=10 REAL-ORDER STRESS COMPLETE

TONIoT MLP view\_seed=10 REAL-MIXTURE STRESS COMPLETE

TONIoT MLP view\_seed=10 REAL-ORDER STRESS COMPLETE

TONIoT MLP view\_seed=11 REAL-MIXTURE STRESS COMPLETE

TONIoT MLP view\_seed=11 REAL-ORDER STRESS COMPLETE

TONIoT MLP view\_seed=12 REAL-MIXTURE STRESS COMPLETE

TONIoT MLP view\_seed=12 REAL-ORDER STRESS COMPLETE

TONIoT GBDT view\_seed=10 REAL-MIXTURE STRESS COMPLETE

TONIoT GBDT view\_seed=10 REAL-ORDER STRESS COMPLETE

TONIoT GBDT view\_seed=11 REAL-MIXTURE STRESS COMPLETE

TONIoT GBDT view\_seed=11 REAL-ORDER STRESS COMPLETE

TONIoT GBDT view\_seed=12 REAL-MIXTURE STRESS COMPLETE

TONIoT GBDT view\_seed=12 REAL-ORDER STRESS COMPLETE



REAL-RECORD STRESS SUMMARY

&#x20;   dataset            family  view\_seed                experiment                  domain                        ordering  target\_attack\_fraction  evaluated\_windows  observed\_attack\_fraction  primary\_accuracy  mean\_view\_accuracy  trusted\_coverage  clean\_abstain\_rate  trusted\_primary\_risk  mean\_support\_score

CICIoMT2024              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 57                    0.0000            0.9701              0.9471            0.8246              0.1754                0.0319              0.7053

CICIoMT2024              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9664              0.9493            0.0333              0.9667                0.0508              1.2876

CICIoMT2024              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9618              0.9525            0.0000              1.0000                   NaN              1.6770

CICIoMT2024              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.9549              0.9564            0.9833              0.0167                0.0454              0.4955

CICIoMT2024              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.9482              0.9630            0.0000              1.0000                   NaN              1.6894

CICIoMT2024              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.9443              0.9671            0.0000              1.0000                   NaN              2.5357

CICIoMT2024              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 57                    1.0000            0.9397              0.9688            0.0000              1.0000                   NaN              3.0692

CICIoMT2024              GBDT         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 39                    0.5006            0.9553              0.9581            1.0000              0.0000                0.0447              0.6041

CICIoMT2024              GBDT         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 39                    0.5006            0.9553              0.9581            0.1538              0.8462                0.0299              2.9432

CICIoMT2024              GBDT         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 86                    0.4999            0.8191              0.7905            0.0000              1.0000                   NaN              4.6697

CICIoMT2024              GBDT         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 86                    0.4999            0.8191              0.7905            0.1047              0.8953                0.0399              5.4968

CICIoMT2024              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 57                    0.0000            0.9701              0.9471            0.8246              0.1754                0.0319              0.7053

CICIoMT2024              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9664              0.9493            0.0333              0.9667                0.0508              1.2876

CICIoMT2024              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9618              0.9525            0.0000              1.0000                   NaN              1.6770

CICIoMT2024              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.9549              0.9564            0.9833              0.0167                0.0454              0.4955

CICIoMT2024              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.9482              0.9630            0.0000              1.0000                   NaN              1.6894

CICIoMT2024              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.9443              0.9671            0.0000              1.0000                   NaN              2.5357

CICIoMT2024              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 57                    1.0000            0.9397              0.9688            0.0000              1.0000                   NaN              3.0692

CICIoMT2024              GBDT         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 39                    0.5006            0.9553              0.9581            1.0000              0.0000                0.0447              0.6041

CICIoMT2024              GBDT         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 39                    0.5006            0.9553              0.9581            0.1538              0.8462                0.0299              2.9432

CICIoMT2024              GBDT         11  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 86                    0.4999            0.8191              0.7905            0.0000              1.0000                   NaN              4.6697

CICIoMT2024              GBDT         11  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 86                    0.4999            0.8191              0.7905            0.1047              0.8953                0.0399              5.4968

CICIoMT2024              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 57                    0.0000            0.9701              0.9471            0.8246              0.1754                0.0319              0.7053

CICIoMT2024              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9664              0.9493            0.0333              0.9667                0.0508              1.2876

CICIoMT2024              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9618              0.9525            0.0000              1.0000                   NaN              1.6770

CICIoMT2024              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.9549              0.9564            0.9833              0.0167                0.0454              0.4955

CICIoMT2024              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.9482              0.9630            0.0000              1.0000                   NaN              1.6894

CICIoMT2024              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.9443              0.9671            0.0000              1.0000                   NaN              2.5357

CICIoMT2024              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 57                    1.0000            0.9397              0.9688            0.0000              1.0000                   NaN              3.0692

CICIoMT2024              GBDT         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 39                    0.5006            0.9553              0.9581            1.0000              0.0000                0.0447              0.6041

CICIoMT2024              GBDT         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 39                    0.5006            0.9553              0.9581            0.1538              0.8462                0.0299              2.9432

CICIoMT2024              GBDT         12  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 86                    0.4999            0.8191              0.7905            0.0000              1.0000                   NaN              4.6697

CICIoMT2024              GBDT         12  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 86                    0.4999            0.8191              0.7905            0.1047              0.8953                0.0399              5.4968

CICIoMT2024               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 57                    0.0000            0.9701              0.9474            0.8772              0.1228                0.0319              0.6627

CICIoMT2024               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9664              0.9424            0.0167              0.9833                0.0391              1.2536

CICIoMT2024               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9618              0.9370            0.0000              1.0000                   NaN              1.6779

CICIoMT2024               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.9549              0.9260            1.0000              0.0000                0.0451              0.4960

CICIoMT2024               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.9482              0.9159            0.0000              1.0000                   NaN              1.6117

CICIoMT2024               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.9443              0.9118            0.0000              1.0000                   NaN              2.4331

CICIoMT2024               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 57                    1.0000            0.9397              0.9068            0.0000              1.0000                   NaN              2.9790

CICIoMT2024               MLP         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 39                    0.5006            0.9553              0.9269            0.9744              0.0256                0.0454              0.6053

CICIoMT2024               MLP         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 39                    0.5006            0.9553              0.9269            0.0769              0.9231                0.0286              3.2414

CICIoMT2024               MLP         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 86                    0.4999            0.8191              0.7347            0.0000              1.0000                   NaN              3.7698

CICIoMT2024               MLP         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 86                    0.4999            0.8191              0.7347            0.0930              0.9070                0.0361              4.7178

CICIoMT2024               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 57                    0.0000            0.9701              0.9537            0.9123              0.0877                0.0312              0.6800

CICIoMT2024               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9664              0.9489            0.0000              1.0000                   NaN              1.5233

CICIoMT2024               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9618              0.9426            0.0000              1.0000                   NaN              1.7994

CICIoMT2024               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.9549              0.9310            1.0000              0.0000                0.0451              0.4952

CICIoMT2024               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.9482              0.9201            0.0000              1.0000                   NaN              1.7028

CICIoMT2024               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.9443              0.9150            0.0000              1.0000                   NaN              2.5862

CICIoMT2024               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 57                    1.0000            0.9397              0.9094            0.0000              1.0000                   NaN              3.1675

CICIoMT2024               MLP         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 39                    0.5006            0.9553              0.9315            0.9744              0.0256                0.0448              0.6088

CICIoMT2024               MLP         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 39                    0.5006            0.9553              0.9315            0.1538              0.8462                0.0339              3.4101

CICIoMT2024               MLP         11  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 86                    0.4999            0.8191              0.7402            0.0000              1.0000                   NaN              3.9138

CICIoMT2024               MLP         11  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 86                    0.4999            0.8191              0.7402            0.0930              0.9070                0.0361              4.9855

CICIoMT2024               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 57                    0.0000            0.9701              0.9545            0.9474              0.0526                0.0314              0.6429

CICIoMT2024               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9664              0.9497            0.0000              1.0000                   NaN              1.3907

CICIoMT2024               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9618              0.9429            0.0000              1.0000                   NaN              1.7708

CICIoMT2024               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.9549              0.9311            1.0000              0.0000                0.0451              0.4986

CICIoMT2024               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.9482              0.9201            0.0000              1.0000                   NaN              1.6712

CICIoMT2024               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.9443              0.9149            0.0000              1.0000                   NaN              2.5107

CICIoMT2024               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 57                    1.0000            0.9397              0.9097            0.0000              1.0000                   NaN              3.0608

CICIoMT2024               MLP         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 39                    0.5006            0.9553              0.9320            0.9744              0.0256                0.0448              0.6284

CICIoMT2024               MLP         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 39                    0.5006            0.9553              0.9320            0.1538              0.8462                0.0312              3.3864

CICIoMT2024               MLP         12  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 86                    0.4999            0.8191              0.7396            0.0000              1.0000                   NaN              3.5649

CICIoMT2024               MLP         12  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 86                    0.4999            0.8191              0.7396            0.1163              0.8837                0.0750              4.6486

CICIoMT2024 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 57                    0.0000            0.9701              0.9537            0.9123              0.0877                0.0305              0.6763

CICIoMT2024 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9664              0.9185            0.1500              0.8500                0.0278              1.3227

CICIoMT2024 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9618              0.8698            0.0000              1.0000                   NaN              1.9355

CICIoMT2024 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.9549              0.7856            1.0000              0.0000                0.0451              0.5383

CICIoMT2024 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.9482              0.6993            0.0000              1.0000                   NaN              1.8102

CICIoMT2024 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.9443              0.6508            0.0000              1.0000                   NaN              2.7638

CICIoMT2024 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 57                    1.0000            0.9397              0.6157            0.0000              1.0000                   NaN              3.4303

CICIoMT2024 logistic\_existing         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 39                    0.5006            0.9553              0.7841            0.9487              0.0513                0.0456              0.6448

CICIoMT2024 logistic\_existing         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 39                    0.5006            0.9553              0.7841            0.0513              0.9487                0.0352              3.3191

CICIoMT2024 logistic\_existing         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 86                    0.4999            0.8191              0.7421            0.0465              0.9535                0.1680              1.4901

CICIoMT2024 logistic\_existing         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 86                    0.4999            0.8191              0.7421            0.0814              0.9186                0.0915              3.5058

&#x20;CICIoT2023              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 60                    0.0000            0.9551              0.9609            0.9000              0.1000                0.0459              0.6916

&#x20;CICIoT2023              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9401              0.9445            0.2333              0.7667                0.0592              1.1272

&#x20;CICIoT2023              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9172              0.9200            0.0000              1.0000                   NaN              1.7173

&#x20;CICIoT2023              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8822              0.8828            0.9667              0.0333                0.1193              0.5743

&#x20;CICIoT2023              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.8477              0.8433            0.0167              0.9833                0.1562              1.4989

&#x20;CICIoT2023              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.8283              0.8196            0.0000              1.0000                   NaN              2.2676

&#x20;CICIoT2023              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 60                    1.0000            0.8138              0.8050            0.0000              1.0000                   NaN              2.8196

&#x20;CICIoT2023              GBDT         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 42                    0.5015            0.8839              0.8833            0.9524              0.0476                0.1174              0.6594

&#x20;CICIoT2023              GBDT         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 42                    0.5015            0.8839              0.8833            0.9286              0.0714                0.1156              0.6673

&#x20;CICIoT2023              GBDT         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                107                    0.4998            0.8234              0.8013            0.3551              0.6449                0.1608              1.1578

&#x20;CICIoT2023              GBDT         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                107                    0.4998            0.8234              0.8013            0.3364              0.6636                0.1606              1.1661

&#x20;CICIoT2023              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 60                    0.0000            0.9551              0.9609            0.9000              0.1000                0.0459              0.6916

&#x20;CICIoT2023              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9401              0.9445            0.2333              0.7667                0.0592              1.1272

&#x20;CICIoT2023              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9172              0.9200            0.0000              1.0000                   NaN              1.7173

&#x20;CICIoT2023              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8822              0.8828            0.9667              0.0333                0.1193              0.5743

&#x20;CICIoT2023              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.8477              0.8433            0.0167              0.9833                0.1562              1.4989

&#x20;CICIoT2023              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.8283              0.8196            0.0000              1.0000                   NaN              2.2676

&#x20;CICIoT2023              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 60                    1.0000            0.8138              0.8050            0.0000              1.0000                   NaN              2.8196

&#x20;CICIoT2023              GBDT         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 42                    0.5015            0.8839              0.8833            0.9524              0.0476                0.1174              0.6594

&#x20;CICIoT2023              GBDT         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 42                    0.5015            0.8839              0.8833            0.9286              0.0714                0.1156              0.6673

&#x20;CICIoT2023              GBDT         11  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                107                    0.4998            0.8234              0.8013            0.3551              0.6449                0.1608              1.1578

&#x20;CICIoT2023              GBDT         11  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                107                    0.4998            0.8234              0.8013            0.3364              0.6636                0.1606              1.1661

&#x20;CICIoT2023              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 60                    0.0000            0.9551              0.9609            0.9000              0.1000                0.0459              0.6916

&#x20;CICIoT2023              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9401              0.9445            0.2333              0.7667                0.0592              1.1272

&#x20;CICIoT2023              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9172              0.9200            0.0000              1.0000                   NaN              1.7173

&#x20;CICIoT2023              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8822              0.8828            0.9667              0.0333                0.1193              0.5743

&#x20;CICIoT2023              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.8477              0.8433            0.0167              0.9833                0.1562              1.4989

&#x20;CICIoT2023              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.8283              0.8196            0.0000              1.0000                   NaN              2.2676

&#x20;CICIoT2023              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 60                    1.0000            0.8138              0.8050            0.0000              1.0000                   NaN              2.8196

&#x20;CICIoT2023              GBDT         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 42                    0.5015            0.8839              0.8833            0.9524              0.0476                0.1174              0.6594

&#x20;CICIoT2023              GBDT         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 42                    0.5015            0.8839              0.8833            0.9286              0.0714                0.1156              0.6673

&#x20;CICIoT2023              GBDT         12  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                107                    0.4998            0.8234              0.8013            0.3551              0.6449                0.1608              1.1578

&#x20;CICIoT2023              GBDT         12  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                107                    0.4998            0.8234              0.8013            0.3364              0.6636                0.1606              1.1661

&#x20;CICIoT2023               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 60                    0.0000            0.9551              0.9600            0.9667              0.0333                0.0453              0.6647

&#x20;CICIoT2023               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9401              0.9392            0.5000              0.5000                0.0633              1.0224

&#x20;CICIoT2023               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9172              0.9084            0.0000              1.0000                   NaN              1.7581

&#x20;CICIoT2023               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8822              0.8607            1.0000              0.0000                0.1178              0.5637

&#x20;CICIoT2023               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.8477              0.8103            0.0000              1.0000                   NaN              1.4942

&#x20;CICIoT2023               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.8283              0.7821            0.0000              1.0000                   NaN              2.3237

&#x20;CICIoT2023               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 60                    1.0000            0.8138              0.7632            0.0000              1.0000                   NaN              2.9231

&#x20;CICIoT2023               MLP         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 42                    0.5015            0.8839              0.8616            0.9762              0.0238                0.1170              0.6378

&#x20;CICIoT2023               MLP         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 42                    0.5015            0.8839              0.8616            0.9286              0.0714                0.1168              0.6517

&#x20;CICIoT2023               MLP         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                107                    0.4998            0.8234              0.7843            0.2056              0.7944                0.1602              1.2827

&#x20;CICIoT2023               MLP         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                107                    0.4998            0.8234              0.7843            0.2150              0.7850                0.1539              1.2905

&#x20;CICIoT2023               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 60                    0.0000            0.9551              0.9596            0.9167              0.0833                0.0463              0.6861

&#x20;CICIoT2023               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9401              0.9383            0.4667              0.5333                0.0633              1.0343

&#x20;CICIoT2023               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9172              0.9076            0.0000              1.0000                   NaN              1.6700

&#x20;CICIoT2023               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8822              0.8588            1.0000              0.0000                0.1178              0.5450

&#x20;CICIoT2023               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.8477              0.8071            0.0167              0.9833                0.1562              1.4540

&#x20;CICIoT2023               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.8283              0.7772            0.0000              1.0000                   NaN              2.2273

&#x20;CICIoT2023               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 60                    1.0000            0.8138              0.7579            0.0000              1.0000                   NaN              2.8095

&#x20;CICIoT2023               MLP         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 42                    0.5015            0.8839              0.8588            0.9762              0.0238                0.1170              0.6161

&#x20;CICIoT2023               MLP         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 42                    0.5015            0.8839              0.8588            0.9524              0.0476                0.1166              0.6192

&#x20;CICIoT2023               MLP         11  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                107                    0.4998            0.8234              0.7746            0.1682              0.8318                0.1558              1.2779

&#x20;CICIoT2023               MLP         11  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                107                    0.4998            0.8234              0.7746            0.2336              0.7664                0.1575              1.2827

&#x20;CICIoT2023               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 60                    0.0000            0.9551              0.9559            0.9833              0.0167                0.0452              0.6559

&#x20;CICIoT2023               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9401              0.9357            0.4333              0.5667                0.0610              1.0365

&#x20;CICIoT2023               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9172              0.9063            0.0000              1.0000                   NaN              1.7259

&#x20;CICIoT2023               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8822              0.8630            1.0000              0.0000                0.1178              0.5381

&#x20;CICIoT2023               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.8477              0.8177            0.0000              1.0000                   NaN              1.5088

&#x20;CICIoT2023               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.8283              0.7902            0.0000              1.0000                   NaN              2.3530

&#x20;CICIoT2023               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 60                    1.0000            0.8138              0.7730            0.0000              1.0000                   NaN              2.9635

&#x20;CICIoT2023               MLP         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 42                    0.5015            0.8839              0.8643            0.9524              0.0476                0.1182              0.6155

&#x20;CICIoT2023               MLP         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 42                    0.5015            0.8839              0.8643            0.9762              0.0238                0.1157              0.6245

&#x20;CICIoT2023               MLP         12  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                107                    0.4998            0.8234              0.7753            0.0935              0.9065                0.1508              1.4303

&#x20;CICIoT2023               MLP         12  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                107                    0.4998            0.8234              0.7753            0.0935              0.9065                0.1578              1.4378

&#x20;CICIoT2023 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 60                    0.0000            0.9551              0.9657            0.9500              0.0500                0.0461              0.6520

&#x20;CICIoT2023 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 60                    0.1016            0.9401              0.9138            0.3333              0.6667                0.0586              1.0867

&#x20;CICIoT2023 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 60                    0.2500            0.9172              0.8382            0.0000              1.0000                   NaN              1.8569

&#x20;CICIoT2023 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8822              0.7123            0.9833              0.0167                0.1165              0.5319

&#x20;CICIoT2023 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 60                    0.7500            0.8477              0.5865            0.0000              1.0000                   NaN              1.5780

&#x20;CICIoT2023 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 60                    0.8984            0.8283              0.5100            0.0000              1.0000                   NaN              2.4924

&#x20;CICIoT2023 logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 60                    1.0000            0.8138              0.4599            0.0000              1.0000                   NaN              3.1753

&#x20;CICIoT2023 logistic\_existing         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 42                    0.5015            0.8839              0.7125            0.9524              0.0476                0.1166              0.6371

&#x20;CICIoT2023 logistic\_existing         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 42                    0.5015            0.8839              0.7125            0.9762              0.0238                0.1157              0.6173

&#x20;CICIoT2023 logistic\_existing         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                107                    0.4998            0.8234              0.6751            0.0280              0.9720                0.1745              1.4580

&#x20;CICIoT2023 logistic\_existing         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                107                    0.4998            0.8234              0.6751            0.0374              0.9626                0.1816              1.4699

&#x20;       CSE              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9620              0.9776            0.9333              0.0667                0.0402              0.5805

&#x20;       CSE              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9644              0.9277            0.0000              1.0000                   NaN              2.2845

&#x20;       CSE              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9706              0.8581            0.0000              1.0000                   NaN              2.4684

&#x20;       CSE              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9806              0.7416            1.0000              0.0000                0.0194              0.3626

&#x20;       CSE              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9881              0.6261            0.0000              1.0000                   NaN              2.4463

&#x20;       CSE              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9939              0.5554            0.0000              1.0000                   NaN              3.8725

&#x20;       CSE              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            1.0000              0.5069            0.0000              1.0000                   NaN              4.8512

&#x20;       CSE              GBDT         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            1.0000              0.0000                0.0192              0.4892

&#x20;       CSE              GBDT         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            0.4545              0.5455                0.0391              3.0822

&#x20;       CSE              GBDT         10  real\_record\_order\_stress      natural\_day\_Botnet             random\_record\_order                     NaN                 46                    0.5008            0.4720              0.4798            0.6522              0.3478                0.5216              0.9218

&#x20;       CSE              GBDT         10  real\_record\_order\_stress      natural\_day\_Botnet           raw\_file\_record\_order                     NaN                 46                    0.5008            0.4720              0.4798            0.2174              0.7826                0.1148              1.5701

&#x20;       CSE              GBDT         10  real\_record\_order\_stress  natural\_day\_Bruteforce             random\_record\_order                     NaN                 47                    0.5002            0.4782              0.5964            0.0000              1.0000                   NaN              3.5931

&#x20;       CSE              GBDT         10  real\_record\_order\_stress  natural\_day\_Bruteforce           raw\_file\_record\_order                     NaN                 47                    0.5002            0.4782              0.5964            0.4894              0.5106                0.0421              3.3903

&#x20;       CSE              GBDT         10  real\_record\_order\_stress       natural\_day\_DDoS2             random\_record\_order                     NaN                 73                    0.5000            0.6823              0.5776            0.0000              1.0000                   NaN              3.1937

&#x20;       CSE              GBDT         10  real\_record\_order\_stress       natural\_day\_DDoS2           raw\_file\_record\_order                     NaN                 73                    0.5000            0.6823              0.5776            0.0000              1.0000                   NaN              3.3704

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_DoS1             random\_record\_order                     NaN                 93                    0.4998            0.6085              0.5642            0.0000              1.0000                   NaN              2.9595

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_DoS1           raw\_file\_record\_order                     NaN                 93                    0.4998            0.6085              0.5642            0.4194              0.5806                0.0517              2.0805

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_DoS2             random\_record\_order                     NaN                 47                    0.5003            0.8921              0.6316            0.0000              1.0000                   NaN              2.9114

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_DoS2           raw\_file\_record\_order                     NaN                 47                    0.5003            0.8921              0.6316            0.0000              1.0000                   NaN              3.1247

&#x20;       CSE              GBDT         10  real\_record\_order\_stress      natural\_day\_Infil1             random\_record\_order                     NaN                 46                    0.5008            0.5114              0.4978            0.0000              1.0000                   NaN              2.1502

&#x20;       CSE              GBDT         10  real\_record\_order\_stress      natural\_day\_Infil1           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5114              0.4978            0.3043              0.6957                0.5195              2.0601

&#x20;       CSE              GBDT         10  real\_record\_order\_stress      natural\_day\_Infil2             random\_record\_order                     NaN                 46                    0.5008            0.5078              0.5012            0.1087              0.8913                0.5141              1.9427

&#x20;       CSE              GBDT         10  real\_record\_order\_stress      natural\_day\_Infil2           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5078              0.5012            0.2174              0.7826                0.4727              1.9418

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_Web1             random\_record\_order                     NaN                  5                    0.4953            0.5797              0.4792            0.0000              1.0000                   NaN              3.3052

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_Web1           raw\_file\_record\_order                     NaN                  5                    0.4953            0.5797              0.4792            0.0000              1.0000                   NaN              3.6778

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_Web2             random\_record\_order                     NaN                  8                    0.4971            0.5576              0.4847            0.0000              1.0000                   NaN              2.7117

&#x20;       CSE              GBDT         10  real\_record\_order\_stress        natural\_day\_Web2           raw\_file\_record\_order                     NaN                  8                    0.4971            0.5576              0.4847            0.0000              1.0000                   NaN              2.7692

&#x20;       CSE              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9620              0.9776            0.9333              0.0667                0.0402              0.5805

&#x20;       CSE              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9644              0.9277            0.0000              1.0000                   NaN              2.2845

&#x20;       CSE              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9706              0.8581            0.0000              1.0000                   NaN              2.4684

&#x20;       CSE              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9806              0.7416            1.0000              0.0000                0.0194              0.3626

&#x20;       CSE              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9881              0.6261            0.0000              1.0000                   NaN              2.4463

&#x20;       CSE              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9939              0.5554            0.0000              1.0000                   NaN              3.8725

&#x20;       CSE              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            1.0000              0.5069            0.0000              1.0000                   NaN              4.8512

&#x20;       CSE              GBDT         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            1.0000              0.0000                0.0192              0.4892

&#x20;       CSE              GBDT         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            0.4545              0.5455                0.0391              3.0822

&#x20;       CSE              GBDT         11  real\_record\_order\_stress      natural\_day\_Botnet             random\_record\_order                     NaN                 46                    0.5008            0.4720              0.4798            0.6522              0.3478                0.5216              0.9218

&#x20;       CSE              GBDT         11  real\_record\_order\_stress      natural\_day\_Botnet           raw\_file\_record\_order                     NaN                 46                    0.5008            0.4720              0.4798            0.2174              0.7826                0.1148              1.5701

&#x20;       CSE              GBDT         11  real\_record\_order\_stress  natural\_day\_Bruteforce             random\_record\_order                     NaN                 47                    0.5002            0.4782              0.5964            0.0000              1.0000                   NaN              3.5931

&#x20;       CSE              GBDT         11  real\_record\_order\_stress  natural\_day\_Bruteforce           raw\_file\_record\_order                     NaN                 47                    0.5002            0.4782              0.5964            0.4894              0.5106                0.0421              3.3903

&#x20;       CSE              GBDT         11  real\_record\_order\_stress       natural\_day\_DDoS2             random\_record\_order                     NaN                 73                    0.5000            0.6823              0.5776            0.0000              1.0000                   NaN              3.1937

&#x20;       CSE              GBDT         11  real\_record\_order\_stress       natural\_day\_DDoS2           raw\_file\_record\_order                     NaN                 73                    0.5000            0.6823              0.5776            0.0000              1.0000                   NaN              3.3704

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_DoS1             random\_record\_order                     NaN                 93                    0.4998            0.6085              0.5642            0.0000              1.0000                   NaN              2.9595

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_DoS1           raw\_file\_record\_order                     NaN                 93                    0.4998            0.6085              0.5642            0.4194              0.5806                0.0517              2.0805

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_DoS2             random\_record\_order                     NaN                 47                    0.5003            0.8921              0.6316            0.0000              1.0000                   NaN              2.9114

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_DoS2           raw\_file\_record\_order                     NaN                 47                    0.5003            0.8921              0.6316            0.0000              1.0000                   NaN              3.1247

&#x20;       CSE              GBDT         11  real\_record\_order\_stress      natural\_day\_Infil1             random\_record\_order                     NaN                 46                    0.5008            0.5114              0.4978            0.0000              1.0000                   NaN              2.1502

&#x20;       CSE              GBDT         11  real\_record\_order\_stress      natural\_day\_Infil1           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5114              0.4978            0.3043              0.6957                0.5195              2.0601

&#x20;       CSE              GBDT         11  real\_record\_order\_stress      natural\_day\_Infil2             random\_record\_order                     NaN                 46                    0.5008            0.5078              0.5012            0.1087              0.8913                0.5141              1.9427

&#x20;       CSE              GBDT         11  real\_record\_order\_stress      natural\_day\_Infil2           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5078              0.5012            0.2174              0.7826                0.4727              1.9418

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_Web1             random\_record\_order                     NaN                  5                    0.4953            0.5797              0.4792            0.0000              1.0000                   NaN              3.3052

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_Web1           raw\_file\_record\_order                     NaN                  5                    0.4953            0.5797              0.4792            0.0000              1.0000                   NaN              3.6778

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_Web2             random\_record\_order                     NaN                  8                    0.4971            0.5576              0.4847            0.0000              1.0000                   NaN              2.7117

&#x20;       CSE              GBDT         11  real\_record\_order\_stress        natural\_day\_Web2           raw\_file\_record\_order                     NaN                  8                    0.4971            0.5576              0.4847            0.0000              1.0000                   NaN              2.7692

&#x20;       CSE              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9620              0.9776            0.9333              0.0667                0.0402              0.5805

&#x20;       CSE              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9644              0.9277            0.0000              1.0000                   NaN              2.2845

&#x20;       CSE              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9706              0.8581            0.0000              1.0000                   NaN              2.4684

&#x20;       CSE              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9806              0.7416            1.0000              0.0000                0.0194              0.3626

&#x20;       CSE              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9881              0.6261            0.0000              1.0000                   NaN              2.4463

&#x20;       CSE              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9939              0.5554            0.0000              1.0000                   NaN              3.8725

&#x20;       CSE              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            1.0000              0.5069            0.0000              1.0000                   NaN              4.8512

&#x20;       CSE              GBDT         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            1.0000              0.0000                0.0192              0.4892

&#x20;       CSE              GBDT         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            0.4545              0.5455                0.0391              3.0822

&#x20;       CSE              GBDT         12  real\_record\_order\_stress      natural\_day\_Botnet             random\_record\_order                     NaN                 46                    0.5008            0.4720              0.4798            0.6522              0.3478                0.5216              0.9218

&#x20;       CSE              GBDT         12  real\_record\_order\_stress      natural\_day\_Botnet           raw\_file\_record\_order                     NaN                 46                    0.5008            0.4720              0.4798            0.2174              0.7826                0.1148              1.5701

&#x20;       CSE              GBDT         12  real\_record\_order\_stress  natural\_day\_Bruteforce             random\_record\_order                     NaN                 47                    0.5002            0.4782              0.5964            0.0000              1.0000                   NaN              3.5931

&#x20;       CSE              GBDT         12  real\_record\_order\_stress  natural\_day\_Bruteforce           raw\_file\_record\_order                     NaN                 47                    0.5002            0.4782              0.5964            0.4894              0.5106                0.0421              3.3903

&#x20;       CSE              GBDT         12  real\_record\_order\_stress       natural\_day\_DDoS2             random\_record\_order                     NaN                 73                    0.5000            0.6823              0.5776            0.0000              1.0000                   NaN              3.1937

&#x20;       CSE              GBDT         12  real\_record\_order\_stress       natural\_day\_DDoS2           raw\_file\_record\_order                     NaN                 73                    0.5000            0.6823              0.5776            0.0000              1.0000                   NaN              3.3704

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_DoS1             random\_record\_order                     NaN                 93                    0.4998            0.6085              0.5642            0.0000              1.0000                   NaN              2.9595

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_DoS1           raw\_file\_record\_order                     NaN                 93                    0.4998            0.6085              0.5642            0.4194              0.5806                0.0517              2.0805

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_DoS2             random\_record\_order                     NaN                 47                    0.5003            0.8921              0.6316            0.0000              1.0000                   NaN              2.9114

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_DoS2           raw\_file\_record\_order                     NaN                 47                    0.5003            0.8921              0.6316            0.0000              1.0000                   NaN              3.1247

&#x20;       CSE              GBDT         12  real\_record\_order\_stress      natural\_day\_Infil1             random\_record\_order                     NaN                 46                    0.5008            0.5114              0.4978            0.0000              1.0000                   NaN              2.1502

&#x20;       CSE              GBDT         12  real\_record\_order\_stress      natural\_day\_Infil1           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5114              0.4978            0.3043              0.6957                0.5195              2.0601

&#x20;       CSE              GBDT         12  real\_record\_order\_stress      natural\_day\_Infil2             random\_record\_order                     NaN                 46                    0.5008            0.5078              0.5012            0.1087              0.8913                0.5141              1.9427

&#x20;       CSE              GBDT         12  real\_record\_order\_stress      natural\_day\_Infil2           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5078              0.5012            0.2174              0.7826                0.4727              1.9418

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_Web1             random\_record\_order                     NaN                  5                    0.4953            0.5797              0.4792            0.0000              1.0000                   NaN              3.3052

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_Web1           raw\_file\_record\_order                     NaN                  5                    0.4953            0.5797              0.4792            0.0000              1.0000                   NaN              3.6778

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_Web2             random\_record\_order                     NaN                  8                    0.4971            0.5576              0.4847            0.0000              1.0000                   NaN              2.7117

&#x20;       CSE              GBDT         12  real\_record\_order\_stress        natural\_day\_Web2           raw\_file\_record\_order                     NaN                  8                    0.4971            0.5576              0.4847            0.0000              1.0000                   NaN              2.7692

&#x20;       CSE               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9620              0.9793            0.9333              0.0667                0.0396              0.6872

&#x20;       CSE               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9644              0.9293            0.0000              1.0000                   NaN              2.2017

&#x20;       CSE               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9706              0.8573            0.0000              1.0000                   NaN              2.3927

&#x20;       CSE               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9806              0.7367            1.0000              0.0000                0.0194              0.4422

&#x20;       CSE               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9881              0.6176            0.0000              1.0000                   NaN              2.1656

&#x20;       CSE               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9939              0.5435            0.0000              1.0000                   NaN              3.4453

&#x20;       CSE               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            1.0000              0.4953            0.0000              1.0000                   NaN              4.3291

&#x20;       CSE               MLP         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9808              0.7370            0.9091              0.0909                0.0203              0.5390

&#x20;       CSE               MLP         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9808              0.7370            0.4545              0.5455                0.0391              3.0755

&#x20;       CSE               MLP         10  real\_record\_order\_stress      natural\_day\_Botnet             random\_record\_order                     NaN                 46                    0.5008            0.4720              0.4811            0.6087              0.3913                0.5307              0.9983

&#x20;       CSE               MLP         10  real\_record\_order\_stress      natural\_day\_Botnet           raw\_file\_record\_order                     NaN                 46                    0.5008            0.4720              0.4811            0.2391              0.7609                0.0540              1.7968

&#x20;       CSE               MLP         10  real\_record\_order\_stress  natural\_day\_Bruteforce             random\_record\_order                     NaN                 47                    0.5002            0.4782              0.4929            0.0000              1.0000                   NaN              1.4183

&#x20;       CSE               MLP         10  real\_record\_order\_stress  natural\_day\_Bruteforce           raw\_file\_record\_order                     NaN                 47                    0.5002            0.4782              0.4929            0.3617              0.6383                0.0772              1.5917

&#x20;       CSE               MLP         10  real\_record\_order\_stress       natural\_day\_DDoS2             random\_record\_order                     NaN                 73                    0.5000            0.6823              0.5607            0.0000              1.0000                   NaN              4.7453

&#x20;       CSE               MLP         10  real\_record\_order\_stress       natural\_day\_DDoS2           raw\_file\_record\_order                     NaN                 73                    0.5000            0.6823              0.5607            0.0000              1.0000                   NaN              4.1389

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_DoS1             random\_record\_order                     NaN                 93                    0.4998            0.6085              0.5139            0.0323              0.9677                0.4453              1.6128

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_DoS1           raw\_file\_record\_order                     NaN                 93                    0.4998            0.6085              0.5139            0.3548              0.6452                0.0549              2.2233

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_DoS2             random\_record\_order                     NaN                 47                    0.5003            0.8921              0.4997            0.0000              1.0000                   NaN              4.6802

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_DoS2           raw\_file\_record\_order                     NaN                 47                    0.5003            0.8921              0.4997            0.0000              1.0000                   NaN              4.5299

&#x20;       CSE               MLP         10  real\_record\_order\_stress      natural\_day\_Infil1             random\_record\_order                     NaN                 46                    0.5008            0.5114              0.4976            0.0217              0.9783                0.5156              1.9370

&#x20;       CSE               MLP         10  real\_record\_order\_stress      natural\_day\_Infil1           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5114              0.4976            0.2609              0.7391                0.6048              2.0732

&#x20;       CSE               MLP         10  real\_record\_order\_stress      natural\_day\_Infil2             random\_record\_order                     NaN                 46                    0.5008            0.5078              0.4947            0.0435              0.9565                0.5117              1.6158

&#x20;       CSE               MLP         10  real\_record\_order\_stress      natural\_day\_Infil2           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5078              0.4947            0.1087              0.8913                0.2594              1.8620

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_Web1             random\_record\_order                     NaN                  5                    0.4953            0.5797              0.4760            0.0000              1.0000                   NaN              2.9030

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_Web1           raw\_file\_record\_order                     NaN                  5                    0.4953            0.5797              0.4760            0.0000              1.0000                   NaN              3.2553

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_Web2             random\_record\_order                     NaN                  8                    0.4971            0.5576              0.4772            0.0000              1.0000                   NaN              2.1366

&#x20;       CSE               MLP         10  real\_record\_order\_stress        natural\_day\_Web2           raw\_file\_record\_order                     NaN                  8                    0.4971            0.5576              0.4772            0.0000              1.0000                   NaN              2.5817

&#x20;       CSE               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9620              0.9738            1.0000              0.0000                0.0380              0.5753

&#x20;       CSE               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9644              0.9252            0.0000              1.0000                   NaN              1.3991

&#x20;       CSE               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9706              0.8557            0.0000              1.0000                   NaN              2.1879

&#x20;       CSE               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9806              0.7396            1.0000              0.0000                0.0194              0.4130

&#x20;       CSE               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9881              0.6246            0.0000              1.0000                   NaN              2.0754

&#x20;       CSE               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9939              0.5528            0.0000              1.0000                   NaN              3.2693

&#x20;       CSE               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            1.0000              0.5061            0.0000              1.0000                   NaN              4.0907

&#x20;       CSE               MLP         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9808              0.7391            1.0000              0.0000                0.0192              0.5506

&#x20;       CSE               MLP         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9808              0.7391            0.4545              0.5455                0.0391              2.8530

&#x20;       CSE               MLP         11  real\_record\_order\_stress      natural\_day\_Botnet             random\_record\_order                     NaN                 46                    0.5008            0.4720              0.4754            0.9130              0.0870                0.5296              0.8534

&#x20;       CSE               MLP         11  real\_record\_order\_stress      natural\_day\_Botnet           raw\_file\_record\_order                     NaN                 46                    0.5008            0.4720              0.4754            0.2391              0.7609                0.0540              1.5345

&#x20;       CSE               MLP         11  real\_record\_order\_stress  natural\_day\_Bruteforce             random\_record\_order                     NaN                 47                    0.5002            0.4782              0.4863            0.5532              0.4468                0.5039              1.0034

&#x20;       CSE               MLP         11  real\_record\_order\_stress  natural\_day\_Bruteforce           raw\_file\_record\_order                     NaN                 47                    0.5002            0.4782              0.4863            0.4681              0.5319                0.0657              1.2878

&#x20;       CSE               MLP         11  real\_record\_order\_stress       natural\_day\_DDoS2             random\_record\_order                     NaN                 73                    0.5000            0.6823              0.5606            0.0000              1.0000                   NaN              3.5265

&#x20;       CSE               MLP         11  real\_record\_order\_stress       natural\_day\_DDoS2           raw\_file\_record\_order                     NaN                 73                    0.5000            0.6823              0.5606            0.0000              1.0000                   NaN              3.4645

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_DoS1             random\_record\_order                     NaN                 93                    0.4998            0.6085              0.5188            0.1935              0.8065                0.4162              1.3154

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_DoS1           raw\_file\_record\_order                     NaN                 93                    0.4998            0.6085              0.5188            0.4086              0.5914                0.0516              1.8488

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_DoS2             random\_record\_order                     NaN                 47                    0.5003            0.8921              0.4998            0.0000              1.0000                   NaN              3.9976

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_DoS2           raw\_file\_record\_order                     NaN                 47                    0.5003            0.8921              0.4998            0.0000              1.0000                   NaN              3.9773

&#x20;       CSE               MLP         11  real\_record\_order\_stress      natural\_day\_Infil1             random\_record\_order                     NaN                 46                    0.5008            0.5114              0.4968            0.0435              0.9565                0.5117              1.6470

&#x20;       CSE               MLP         11  real\_record\_order\_stress      natural\_day\_Infil1           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5114              0.4968            0.2391              0.7609                0.5945              1.7696

&#x20;       CSE               MLP         11  real\_record\_order\_stress      natural\_day\_Infil2             random\_record\_order                     NaN                 46                    0.5008            0.5078              0.4935            0.0652              0.9348                0.5052              1.4154

&#x20;       CSE               MLP         11  real\_record\_order\_stress      natural\_day\_Infil2           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5078              0.4935            0.1304              0.8696                0.3503              1.5900

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_Web1             random\_record\_order                     NaN                  5                    0.4953            0.5797              0.4771            0.0000              1.0000                   NaN              2.1424

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_Web1           raw\_file\_record\_order                     NaN                  5                    0.4953            0.5797              0.4771            0.0000              1.0000                   NaN              2.3471

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_Web2             random\_record\_order                     NaN                  8                    0.4971            0.5576              0.4749            0.1250              0.8750                0.3906              1.5071

&#x20;       CSE               MLP         11  real\_record\_order\_stress        natural\_day\_Web2           raw\_file\_record\_order                     NaN                  8                    0.4971            0.5576              0.4749            0.0000              1.0000                   NaN              1.9308

&#x20;       CSE               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9620              0.9741            1.0000              0.0000                0.0380              0.6226

&#x20;       CSE               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9644              0.9256            0.0000              1.0000                   NaN              1.9963

&#x20;       CSE               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9706              0.8563            0.0000              1.0000                   NaN              2.1116

&#x20;       CSE               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9806              0.7408            1.0000              0.0000                0.0194              0.3798

&#x20;       CSE               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9881              0.6262            0.0000              1.0000                   NaN              2.1640

&#x20;       CSE               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9939              0.5548            0.0000              1.0000                   NaN              3.3919

&#x20;       CSE               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            1.0000              0.5073            0.0000              1.0000                   NaN              4.2328

&#x20;       CSE               MLP         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            1.0000              0.0000                0.0192              0.5150

&#x20;       CSE               MLP         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9808              0.7401            0.4545              0.5455                0.0391              2.8121

&#x20;       CSE               MLP         12  real\_record\_order\_stress      natural\_day\_Botnet             random\_record\_order                     NaN                 46                    0.5008            0.4720              0.4785            0.7391              0.2609                0.5260              0.9471

&#x20;       CSE               MLP         12  real\_record\_order\_stress      natural\_day\_Botnet           raw\_file\_record\_order                     NaN                 46                    0.5008            0.4720              0.4785            0.2174              0.7826                0.0508              1.5760

&#x20;       CSE               MLP         12  real\_record\_order\_stress  natural\_day\_Bruteforce             random\_record\_order                     NaN                 47                    0.5002            0.4782              0.4863            0.0851              0.9149                0.4980              1.2484

&#x20;       CSE               MLP         12  real\_record\_order\_stress  natural\_day\_Bruteforce           raw\_file\_record\_order                     NaN                 47                    0.5002            0.4782              0.4863            0.4468              0.5532                0.0681              1.5017

&#x20;       CSE               MLP         12  real\_record\_order\_stress       natural\_day\_DDoS2             random\_record\_order                     NaN                 73                    0.5000            0.6823              0.6212            0.0000              1.0000                   NaN              3.7385

&#x20;       CSE               MLP         12  real\_record\_order\_stress       natural\_day\_DDoS2           raw\_file\_record\_order                     NaN                 73                    0.5000            0.6823              0.6212            0.0000              1.0000                   NaN              3.2576

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_DoS1             random\_record\_order                     NaN                 93                    0.4998            0.6085              0.5179            0.0430              0.9570                0.4375              1.7302

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_DoS1           raw\_file\_record\_order                     NaN                 93                    0.4998            0.6085              0.5179            0.4301              0.5699                0.0547              2.0392

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_DoS2             random\_record\_order                     NaN                 47                    0.5003            0.8921              0.5145            0.0000              1.0000                   NaN              3.8561

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_DoS2           raw\_file\_record\_order                     NaN                 47                    0.5003            0.8921              0.5145            0.0000              1.0000                   NaN              3.8108

&#x20;       CSE               MLP         12  real\_record\_order\_stress      natural\_day\_Infil1             random\_record\_order                     NaN                 46                    0.5008            0.5114              0.4965            0.0000              1.0000                   NaN              1.9279

&#x20;       CSE               MLP         12  real\_record\_order\_stress      natural\_day\_Infil1           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5114              0.4965            0.2391              0.7609                0.6349              1.9661

&#x20;       CSE               MLP         12  real\_record\_order\_stress      natural\_day\_Infil2             random\_record\_order                     NaN                 46                    0.5008            0.5078              0.4952            0.1087              0.8913                0.5047              1.6996

&#x20;       CSE               MLP         12  real\_record\_order\_stress      natural\_day\_Infil2           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5078              0.4952            0.1304              0.8696                0.3516              1.7920

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_Web1             random\_record\_order                     NaN                  5                    0.4953            0.5797              0.4760            0.0000              1.0000                   NaN              2.8391

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_Web1           raw\_file\_record\_order                     NaN                  5                    0.4953            0.5797              0.4760            0.0000              1.0000                   NaN              3.0685

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_Web2             random\_record\_order                     NaN                  8                    0.4971            0.5576              0.4766            0.1250              0.8750                0.3906              2.0427

&#x20;       CSE               MLP         12  real\_record\_order\_stress        natural\_day\_Web2           raw\_file\_record\_order                     NaN                  8                    0.4971            0.5576              0.4766            0.0000              1.0000                   NaN              2.3797

&#x20;       CSE logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9620              0.9786            1.0000              0.0000                0.0380              0.6522

&#x20;       CSE logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9644              0.9269            0.0000              1.0000                   NaN              1.5061

&#x20;       CSE logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9706              0.8557            0.0000              1.0000                   NaN              2.4241

&#x20;       CSE logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9806              0.7338            1.0000              0.0000                0.0194              0.4118

&#x20;       CSE logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9881              0.6142            0.0000              1.0000                   NaN              2.0806

&#x20;       CSE logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9939              0.5405            0.0000              1.0000                   NaN              3.3998

&#x20;       CSE logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            1.0000              0.4903            0.0000              1.0000                   NaN              4.2916

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9808              0.7330            1.0000              0.0000                0.0192              0.5039

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9808              0.7330            0.4545              0.5455                0.0391              3.0204

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress      natural\_day\_Botnet             random\_record\_order                     NaN                 46                    0.5008            0.4720              0.4789            0.4565              0.5435                0.5283              1.0159

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress      natural\_day\_Botnet           raw\_file\_record\_order                     NaN                 46                    0.5008            0.4720              0.4789            0.1957              0.8043                0.0469              1.5572

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress  natural\_day\_Bruteforce             random\_record\_order                     NaN                 47                    0.5002            0.4782              0.4890            0.0000              1.0000                   NaN              1.4191

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress  natural\_day\_Bruteforce           raw\_file\_record\_order                     NaN                 47                    0.5002            0.4782              0.4890            0.4255              0.5745                0.0445              1.5768

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress       natural\_day\_DDoS2             random\_record\_order                     NaN                 73                    0.5000            0.6823              0.5789            0.0000              1.0000                   NaN              3.2280

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress       natural\_day\_DDoS2           raw\_file\_record\_order                     NaN                 73                    0.5000            0.6823              0.5789            0.0000              1.0000                   NaN              3.7677

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_DoS1             random\_record\_order                     NaN                 93                    0.4998            0.6085              0.5215            0.0753              0.9247                0.3929              1.5948

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_DoS1           raw\_file\_record\_order                     NaN                 93                    0.4998            0.6085              0.5215            0.4194              0.5806                0.0569              1.7796

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_DoS2             random\_record\_order                     NaN                 47                    0.5003            0.8921              0.6950            0.0000              1.0000                   NaN              2.0275

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_DoS2           raw\_file\_record\_order                     NaN                 47                    0.5003            0.8921              0.6950            0.0000              1.0000                   NaN              2.3315

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress      natural\_day\_Infil1             random\_record\_order                     NaN                 46                    0.5008            0.5114              0.4996            0.0435              0.9565                0.4844              1.4961

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress      natural\_day\_Infil1           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5114              0.4996            0.3913              0.6087                0.4991              1.5675

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress      natural\_day\_Infil2             random\_record\_order                     NaN                 46                    0.5008            0.5078              0.4969            0.1957              0.8043                0.5061              1.3425

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress      natural\_day\_Infil2           raw\_file\_record\_order                     NaN                 46                    0.5008            0.5078              0.4969            0.3913              0.6087                0.4449              1.3990

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_Web1             random\_record\_order                     NaN                  5                    0.4953            0.5797              0.4896            0.0000              1.0000                   NaN              2.4450

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_Web1           raw\_file\_record\_order                     NaN                  5                    0.4953            0.5797              0.4896            0.0000              1.0000                   NaN              2.7316

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_Web2             random\_record\_order                     NaN                  8                    0.4971            0.5576              0.4941            0.1250              0.8750                0.3906              1.9050

&#x20;       CSE logistic\_existing         10  real\_record\_order\_stress        natural\_day\_Web2           raw\_file\_record\_order                     NaN                  8                    0.4971            0.5576              0.4941            0.0000              1.0000                   NaN              2.2469

&#x20;       NSL              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9182              0.9547            0.8000              0.2000                0.0788              0.7590

&#x20;       NSL              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9240              0.9275            0.0556              0.9444                0.0312              1.2821

&#x20;       NSL              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9286              0.8896            0.0000              1.0000                   NaN              2.0433

&#x20;       NSL              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9401              0.8264            1.0000              0.0000                0.0599              0.6320

&#x20;       NSL              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9483              0.7629            0.0000              1.0000                   NaN              1.8033

&#x20;       NSL              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9562              0.7251            0.0000              1.0000                   NaN              2.7117

&#x20;       NSL              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            0.9583              0.6979            0.0000              1.0000                   NaN              3.3939

&#x20;       NSL              GBDT         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9403              0.8257            1.0000              0.0000                0.0597              0.5969

&#x20;       NSL              GBDT         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9403              0.8257            0.9091              0.0909                0.0578              0.7588

&#x20;       NSL              GBDT         10  real\_record\_order\_stress   natural\_official\_test             random\_record\_order                     NaN                 93                    0.4999            0.7644              0.7059            0.0000              1.0000                   NaN              1.8889

&#x20;       NSL              GBDT         10  real\_record\_order\_stress   natural\_official\_test           raw\_file\_record\_order                     NaN                 93                    0.4999            0.7644              0.7059            0.0000              1.0000                   NaN              1.8819

&#x20;       NSL              GBDT         10  real\_record\_order\_stress natural\_official\_test21             random\_record\_order                     NaN                 33                    0.4995            0.6023              0.6154            0.0000              1.0000                   NaN              3.0964

&#x20;       NSL              GBDT         10  real\_record\_order\_stress natural\_official\_test21           raw\_file\_record\_order                     NaN                 33                    0.4995            0.6023              0.6154            0.0000              1.0000                   NaN              3.1015

&#x20;       NSL              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9182              0.9547            0.8000              0.2000                0.0788              0.7590

&#x20;       NSL              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9240              0.9275            0.0556              0.9444                0.0312              1.2821

&#x20;       NSL              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9286              0.8896            0.0000              1.0000                   NaN              2.0433

&#x20;       NSL              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9401              0.8264            1.0000              0.0000                0.0599              0.6320

&#x20;       NSL              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9483              0.7629            0.0000              1.0000                   NaN              1.8033

&#x20;       NSL              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9562              0.7251            0.0000              1.0000                   NaN              2.7117

&#x20;       NSL              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            0.9583              0.6979            0.0000              1.0000                   NaN              3.3939

&#x20;       NSL              GBDT         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9403              0.8257            1.0000              0.0000                0.0597              0.5969

&#x20;       NSL              GBDT         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9403              0.8257            0.9091              0.0909                0.0578              0.7588

&#x20;       NSL              GBDT         11  real\_record\_order\_stress   natural\_official\_test             random\_record\_order                     NaN                 93                    0.4999            0.7644              0.7059            0.0000              1.0000                   NaN              1.8889

&#x20;       NSL              GBDT         11  real\_record\_order\_stress   natural\_official\_test           raw\_file\_record\_order                     NaN                 93                    0.4999            0.7644              0.7059            0.0000              1.0000                   NaN              1.8819

&#x20;       NSL              GBDT         11  real\_record\_order\_stress natural\_official\_test21             random\_record\_order                     NaN                 33                    0.4995            0.6023              0.6154            0.0000              1.0000                   NaN              3.0964

&#x20;       NSL              GBDT         11  real\_record\_order\_stress natural\_official\_test21           raw\_file\_record\_order                     NaN                 33                    0.4995            0.6023              0.6154            0.0000              1.0000                   NaN              3.1015

&#x20;       NSL              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9182              0.9547            0.8000              0.2000                0.0788              0.7590

&#x20;       NSL              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9240              0.9275            0.0556              0.9444                0.0312              1.2821

&#x20;       NSL              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9286              0.8896            0.0000              1.0000                   NaN              2.0433

&#x20;       NSL              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9401              0.8264            1.0000              0.0000                0.0599              0.6320

&#x20;       NSL              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9483              0.7629            0.0000              1.0000                   NaN              1.8033

&#x20;       NSL              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9562              0.7251            0.0000              1.0000                   NaN              2.7117

&#x20;       NSL              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            0.9583              0.6979            0.0000              1.0000                   NaN              3.3939

&#x20;       NSL              GBDT         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9403              0.8257            1.0000              0.0000                0.0597              0.5969

&#x20;       NSL              GBDT         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9403              0.8257            0.9091              0.0909                0.0578              0.7588

&#x20;       NSL              GBDT         12  real\_record\_order\_stress   natural\_official\_test             random\_record\_order                     NaN                 93                    0.4999            0.7644              0.7059            0.0000              1.0000                   NaN              1.8889

&#x20;       NSL              GBDT         12  real\_record\_order\_stress   natural\_official\_test           raw\_file\_record\_order                     NaN                 93                    0.4999            0.7644              0.7059            0.0000              1.0000                   NaN              1.8819

&#x20;       NSL              GBDT         12  real\_record\_order\_stress natural\_official\_test21             random\_record\_order                     NaN                 33                    0.4995            0.6023              0.6154            0.0000              1.0000                   NaN              3.0964

&#x20;       NSL              GBDT         12  real\_record\_order\_stress natural\_official\_test21           raw\_file\_record\_order                     NaN                 33                    0.4995            0.6023              0.6154            0.0000              1.0000                   NaN              3.1015

&#x20;       NSL               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9182              0.9464            1.0000              0.0000                0.0818              0.6679

&#x20;       NSL               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9240              0.8989            0.0000              1.0000                   NaN              1.5242

&#x20;       NSL               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9286              0.8306            0.0000              1.0000                   NaN              1.9558

&#x20;       NSL               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9401              0.7165            1.0000              0.0000                0.0599              0.6113

&#x20;       NSL               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9483              0.6022            0.0000              1.0000                   NaN              1.8551

&#x20;       NSL               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9562              0.5344            0.0000              1.0000                   NaN              2.7977

&#x20;       NSL               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            0.9583              0.4867            0.0000              1.0000                   NaN              3.4935

&#x20;       NSL               MLP         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9403              0.7149            0.9091              0.0909                0.0609              0.5786

&#x20;       NSL               MLP         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9403              0.7149            0.9091              0.0909                0.0578              0.7109

&#x20;       NSL               MLP         10  real\_record\_order\_stress   natural\_official\_test             random\_record\_order                     NaN                 93                    0.4999            0.7644              0.6659            0.0108              0.9892                0.2578              1.7112

&#x20;       NSL               MLP         10  real\_record\_order\_stress   natural\_official\_test           raw\_file\_record\_order                     NaN                 93                    0.4999            0.7644              0.6659            0.0000              1.0000                   NaN              1.7192

&#x20;       NSL               MLP         10  real\_record\_order\_stress natural\_official\_test21             random\_record\_order                     NaN                 33                    0.4995            0.6023              0.6290            0.0000              1.0000                   NaN              2.3384

&#x20;       NSL               MLP         10  real\_record\_order\_stress natural\_official\_test21           raw\_file\_record\_order                     NaN                 33                    0.4995            0.6023              0.6290            0.0000              1.0000                   NaN              2.3249

&#x20;       NSL               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9182              0.9533            1.0000              0.0000                0.0818              0.7089

&#x20;       NSL               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9240              0.9043            0.0000              1.0000                   NaN              1.4505

&#x20;       NSL               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9286              0.8343            0.0000              1.0000                   NaN              1.8150

&#x20;       NSL               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9401              0.7158            1.0000              0.0000                0.0599              0.5579

&#x20;       NSL               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9483              0.5970            0.0000              1.0000                   NaN              1.7938

&#x20;       NSL               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9562              0.5273            0.0000              1.0000                   NaN              2.6725

&#x20;       NSL               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            0.9583              0.4780            0.0000              1.0000                   NaN              3.3279

&#x20;       NSL               MLP         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9403              0.7151            1.0000              0.0000                0.0597              0.5216

&#x20;       NSL               MLP         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9403              0.7151            0.9091              0.0909                0.0578              0.6540

&#x20;       NSL               MLP         11  real\_record\_order\_stress   natural\_official\_test             random\_record\_order                     NaN                 93                    0.4999            0.7644              0.6496            0.1290              0.8710                0.2109              1.4110

&#x20;       NSL               MLP         11  real\_record\_order\_stress   natural\_official\_test           raw\_file\_record\_order                     NaN                 93                    0.4999            0.7644              0.6496            0.0430              0.9570                0.2344              1.4079

&#x20;       NSL               MLP         11  real\_record\_order\_stress natural\_official\_test21             random\_record\_order                     NaN                 33                    0.4995            0.6023              0.5928            0.0000              1.0000                   NaN              1.7468

&#x20;       NSL               MLP         11  real\_record\_order\_stress natural\_official\_test21           raw\_file\_record\_order                     NaN                 33                    0.4995            0.6023              0.5928            0.0000              1.0000                   NaN              1.7397

&#x20;       NSL               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9182              0.9477            0.9333              0.0667                0.0787              0.7207

&#x20;       NSL               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9240              0.8990            0.0000              1.0000                   NaN              1.5780

&#x20;       NSL               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9286              0.8292            0.0000              1.0000                   NaN              1.8540

&#x20;       NSL               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9401              0.7133            1.0000              0.0000                0.0599              0.5845

&#x20;       NSL               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9483              0.5959            0.0000              1.0000                   NaN              1.8994

&#x20;       NSL               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9562              0.5270            0.0000              1.0000                   NaN              2.8409

&#x20;       NSL               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            0.9583              0.4782            0.0000              1.0000                   NaN              3.5327

&#x20;       NSL               MLP         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9403              0.7122            1.0000              0.0000                0.0597              0.5497

&#x20;       NSL               MLP         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9403              0.7122            0.9091              0.0909                0.0578              0.7015

&#x20;       NSL               MLP         12  real\_record\_order\_stress   natural\_official\_test             random\_record\_order                     NaN                 93                    0.4999            0.7644              0.6655            0.0538              0.9462                0.2141              1.5523

&#x20;       NSL               MLP         12  real\_record\_order\_stress   natural\_official\_test           raw\_file\_record\_order                     NaN                 93                    0.4999            0.7644              0.6655            0.0000              1.0000                   NaN              1.5570

&#x20;       NSL               MLP         12  real\_record\_order\_stress natural\_official\_test21             random\_record\_order                     NaN                 33                    0.4995            0.6023              0.6291            0.0000              1.0000                   NaN              2.1495

&#x20;       NSL               MLP         12  real\_record\_order\_stress natural\_official\_test21           raw\_file\_record\_order                     NaN                 33                    0.4995            0.6023              0.6291            0.0000              1.0000                   NaN              2.1472

&#x20;       NSL logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 15                    0.0000            0.9182              0.9568            1.0000              0.0000                0.0818              0.7535

&#x20;       NSL logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 18                    0.1016            0.9240              0.8949            0.1111              0.8889                0.0430              1.2565

&#x20;       NSL logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 21                    0.2500            0.9286              0.8057            0.0000              1.0000                   NaN              1.9412

&#x20;       NSL logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 33                    0.5000            0.9401              0.6572            1.0000              0.0000                0.0599              0.6126

&#x20;       NSL logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 21                    0.7500            0.9483              0.5099            0.0000              1.0000                   NaN              1.8271

&#x20;       NSL logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 18                    0.8984            0.9562              0.4199            0.0000              1.0000                   NaN              2.7887

&#x20;       NSL logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 15                    1.0000            0.9583              0.3608            0.0000              1.0000                   NaN              3.5035

&#x20;       NSL logistic\_existing         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 11                    0.5007            0.9403              0.6561            1.0000              0.0000                0.0597              0.6141

&#x20;       NSL logistic\_existing         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 11                    0.5007            0.9403              0.6561            0.9091              0.0909                0.0578              0.6776

&#x20;       NSL logistic\_existing         10  real\_record\_order\_stress   natural\_official\_test             random\_record\_order                     NaN                 93                    0.4999            0.7644              0.6398            0.0538              0.9462                0.2234              1.5028

&#x20;       NSL logistic\_existing         10  real\_record\_order\_stress   natural\_official\_test           raw\_file\_record\_order                     NaN                 93                    0.4999            0.7644              0.6398            0.0108              0.9892                0.2188              1.4927

&#x20;       NSL logistic\_existing         10  real\_record\_order\_stress natural\_official\_test21             random\_record\_order                     NaN                 33                    0.4995            0.6023              0.6027            0.0000              1.0000                   NaN              1.7166

&#x20;       NSL logistic\_existing         10  real\_record\_order\_stress natural\_official\_test21           raw\_file\_record\_order                     NaN                 33                    0.4995            0.6023              0.6027            0.0000              1.0000                   NaN              1.7155

&#x20;    TONIoT              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 36                    0.0000            0.9586              0.9831            0.8333              0.1667                0.0445              0.7700

&#x20;    TONIoT              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 39                    0.1016            0.9321              0.9156            0.0000              1.0000                   NaN              1.6948

&#x20;    TONIoT              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 48                    0.2500            0.8866              0.8161            0.0000              1.0000                   NaN              2.2226

&#x20;    TONIoT              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8217              0.6501            0.9833              0.0167                0.1789              0.5430

&#x20;    TONIoT              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 48                    0.7500            0.7552              0.4838            0.0000              1.0000                   NaN              2.0857

&#x20;    TONIoT              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 39                    0.8984            0.7143              0.3850            0.0000              1.0000                   NaN              3.2756

&#x20;    TONIoT              GBDT         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 36                    1.0000            0.6877              0.3170            0.0000              1.0000                   NaN              4.1159

&#x20;    TONIoT              GBDT         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 24                    0.4997            0.8249              0.6508            0.9167              0.0833                0.1768              0.6618

&#x20;    TONIoT              GBDT         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 24                    0.4997            0.8249              0.6508            0.0417              0.9583                0.0859              3.6163

&#x20;    TONIoT              GBDT         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 48                    0.5007            0.5532              0.5244            0.0000              1.0000                   NaN              1.8014

&#x20;    TONIoT              GBDT         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 48                    0.5007            0.5532              0.5244            0.0208              0.9792                0.0703              2.0969

&#x20;    TONIoT              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 36                    0.0000            0.9586              0.9831            0.8333              0.1667                0.0445              0.7700

&#x20;    TONIoT              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 39                    0.1016            0.9321              0.9156            0.0000              1.0000                   NaN              1.6948

&#x20;    TONIoT              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 48                    0.2500            0.8866              0.8161            0.0000              1.0000                   NaN              2.2226

&#x20;    TONIoT              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8217              0.6501            0.9833              0.0167                0.1789              0.5430

&#x20;    TONIoT              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 48                    0.7500            0.7552              0.4838            0.0000              1.0000                   NaN              2.0857

&#x20;    TONIoT              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 39                    0.8984            0.7143              0.3850            0.0000              1.0000                   NaN              3.2756

&#x20;    TONIoT              GBDT         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 36                    1.0000            0.6877              0.3170            0.0000              1.0000                   NaN              4.1159

&#x20;    TONIoT              GBDT         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 24                    0.4997            0.8249              0.6508            0.9167              0.0833                0.1768              0.6618

&#x20;    TONIoT              GBDT         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 24                    0.4997            0.8249              0.6508            0.0417              0.9583                0.0859              3.6163

&#x20;    TONIoT              GBDT         11  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 48                    0.5007            0.5532              0.5244            0.0000              1.0000                   NaN              1.8014

&#x20;    TONIoT              GBDT         11  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 48                    0.5007            0.5532              0.5244            0.0208              0.9792                0.0703              2.0969

&#x20;    TONIoT              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 36                    0.0000            0.9586              0.9831            0.8333              0.1667                0.0445              0.7700

&#x20;    TONIoT              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 39                    0.1016            0.9321              0.9156            0.0000              1.0000                   NaN              1.6948

&#x20;    TONIoT              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 48                    0.2500            0.8866              0.8161            0.0000              1.0000                   NaN              2.2226

&#x20;    TONIoT              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8217              0.6501            0.9833              0.0167                0.1789              0.5430

&#x20;    TONIoT              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 48                    0.7500            0.7552              0.4838            0.0000              1.0000                   NaN              2.0857

&#x20;    TONIoT              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 39                    0.8984            0.7143              0.3850            0.0000              1.0000                   NaN              3.2756

&#x20;    TONIoT              GBDT         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 36                    1.0000            0.6877              0.3170            0.0000              1.0000                   NaN              4.1159

&#x20;    TONIoT              GBDT         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 24                    0.4997            0.8249              0.6508            0.9167              0.0833                0.1768              0.6618

&#x20;    TONIoT              GBDT         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 24                    0.4997            0.8249              0.6508            0.0417              0.9583                0.0859              3.6163

&#x20;    TONIoT              GBDT         12  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 48                    0.5007            0.5532              0.5244            0.0000              1.0000                   NaN              1.8014

&#x20;    TONIoT              GBDT         12  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 48                    0.5007            0.5532              0.5244            0.0208              0.9792                0.0703              2.0969

&#x20;    TONIoT               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 36                    0.0000            0.9586              0.9840            0.9722              0.0278                0.0424              0.6454

&#x20;    TONIoT               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 39                    0.1016            0.9321              0.8984            0.1282              0.8718                0.0688              1.2835

&#x20;    TONIoT               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 48                    0.2500            0.8866              0.7713            0.0417              0.9583                0.0898              1.4364

&#x20;    TONIoT               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8217              0.5584            0.9833              0.0167                0.1789              0.5928

&#x20;    TONIoT               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 48                    0.7500            0.7552              0.3457            0.0000              1.0000                   NaN              1.6199

&#x20;    TONIoT               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 39                    0.8984            0.7143              0.2195            0.0000              1.0000                   NaN              2.4259

&#x20;    TONIoT               MLP         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 36                    1.0000            0.6877              0.1330            0.0000              1.0000                   NaN              2.9843

&#x20;    TONIoT               MLP         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 24                    0.4997            0.8249              0.5591            0.8750              0.1250                0.1749              0.6887

&#x20;    TONIoT               MLP         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 24                    0.4997            0.8249              0.5591            0.0000              1.0000                   NaN              2.9583

&#x20;    TONIoT               MLP         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 48                    0.5007            0.5532              0.5098            0.0625              0.9375                0.4167              1.4918

&#x20;    TONIoT               MLP         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 48                    0.5007            0.5532              0.5098            0.0208              0.9792                0.0078              1.8983

&#x20;    TONIoT               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 36                    0.0000            0.9586              0.9837            1.0000              0.0000                0.0414              0.6046

&#x20;    TONIoT               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 39                    0.1016            0.9321              0.8989            0.1795              0.8205                0.0681              1.2220

&#x20;    TONIoT               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 48                    0.2500            0.8866              0.7727            0.0000              1.0000                   NaN              1.4962

&#x20;    TONIoT               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8217              0.5614            0.9833              0.0167                0.1789              0.5778

&#x20;    TONIoT               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 48                    0.7500            0.7552              0.3504            0.0000              1.0000                   NaN              1.5875

&#x20;    TONIoT               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 39                    0.8984            0.7143              0.2252            0.0000              1.0000                   NaN              2.3939

&#x20;    TONIoT               MLP         11 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 36                    1.0000            0.6877              0.1393            0.0000              1.0000                   NaN              2.9608

&#x20;    TONIoT               MLP         11  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 24                    0.4997            0.8249              0.5620            0.9167              0.0833                0.1747              0.6605

&#x20;    TONIoT               MLP         11  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 24                    0.4997            0.8249              0.5620            0.0417              0.9583                0.0859              3.0032

&#x20;    TONIoT               MLP         11  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 48                    0.5007            0.5532              0.5066            0.2708              0.7292                0.4579              1.3028

&#x20;    TONIoT               MLP         11  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 48                    0.5007            0.5532              0.5066            0.0208              0.9792                0.0078              1.9230

&#x20;    TONIoT               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 36                    0.0000            0.9586              0.9832            1.0000              0.0000                0.0414              0.6393

&#x20;    TONIoT               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 39                    0.1016            0.9321              0.8937            0.4872              0.5128                0.0617              1.0708

&#x20;    TONIoT               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 48                    0.2500            0.8866              0.7610            0.0833              0.9167                0.1035              1.3547

&#x20;    TONIoT               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8217              0.5370            0.9667              0.0333                0.1781              0.6216

&#x20;    TONIoT               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 48                    0.7500            0.7552              0.3138            0.0625              0.9375                0.2734              1.4379

&#x20;    TONIoT               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 39                    0.8984            0.7143              0.1813            0.0000              1.0000                   NaN              2.1565

&#x20;    TONIoT               MLP         12 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 36                    1.0000            0.6877              0.0906            0.0000              1.0000                   NaN              2.6693

&#x20;    TONIoT               MLP         12  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 24                    0.4997            0.8249              0.5374            0.8750              0.1250                0.1715              0.6948

&#x20;    TONIoT               MLP         12  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 24                    0.4997            0.8249              0.5374            0.0000              1.0000                   NaN              2.9626

&#x20;    TONIoT               MLP         12  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 48                    0.5007            0.5532              0.5072            0.1458              0.8542                0.4386              1.3560

&#x20;    TONIoT               MLP         12  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 48                    0.5007            0.5532              0.5072            0.0000              1.0000                   NaN              2.0018

&#x20;    TONIoT logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.00                 36                    0.0000            0.9586              0.9869            0.9444              0.0556                0.0430              0.7104

&#x20;    TONIoT logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.10                 39                    0.1016            0.9321              0.9001            0.1795              0.8205                0.0647              1.2368

&#x20;    TONIoT logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.25                 48                    0.2500            0.8866              0.7715            0.0000              1.0000                   NaN              1.6484

&#x20;    TONIoT logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.50                 60                    0.5000            0.8217              0.5560            0.9500              0.0500                0.1806              0.6019

&#x20;    TONIoT logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.75                 48                    0.7500            0.7552              0.3403            0.0000              1.0000                   NaN              1.7712

&#x20;    TONIoT logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    0.90                 39                    0.8984            0.7143              0.2125            0.0000              1.0000                   NaN              2.6827

&#x20;    TONIoT logistic\_existing         10 real\_record\_class\_mixture            clean\_source controlled\_real\_record\_sampling                    1.00                 36                    1.0000            0.6877              0.1248            0.0000              1.0000                   NaN              3.3155

&#x20;    TONIoT logistic\_existing         10  real\_record\_order\_stress            clean\_source             random\_record\_order                     NaN                 24                    0.4997            0.8249              0.5565            0.8333              0.1667                0.1738              0.6976

&#x20;    TONIoT logistic\_existing         10  real\_record\_order\_stress            clean\_source           raw\_file\_record\_order                     NaN                 24                    0.4997            0.8249              0.5565            0.0000              1.0000                   NaN              3.4599

&#x20;    TONIoT logistic\_existing         10  real\_record\_order\_stress  natural\_heldout\_family             random\_record\_order                     NaN                 48                    0.5007            0.5532              0.5057            0.2917              0.7083                0.4565              1.2813

&#x20;    TONIoT logistic\_existing         10  real\_record\_order\_stress  natural\_heldout\_family           raw\_file\_record\_order                     NaN                 48                    0.5007            0.5532              0.5057            0.0417              0.9583                0.4531              1.9270



PREVIOUS VERIFIED ACCEPTED-COLLAPSE ESTIMATOR RESULTS

&#x20;  dataset            family  view\_seed  epsilon     candidate\_kind              panel                    estimator  candidate\_windows  mean\_true\_damage  mean\_estimated\_damage  mean\_damage\_underestimation  mean\_differential\_absolute\_error

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses                           AC                150            0.0784                 0.0167                       0.0617                            0.0617

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                150            0.0784                 0.0181                       0.0603                            0.0603

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses                          ATC                150            0.0784                 0.0325                       0.0459                            0.0459

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                150            0.0784                -0.0206                       0.0991                            0.0991

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses                          DoC                150            0.0784                 0.0167                       0.0617                            0.0617

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                150            0.0784                -0.0153                       0.0938                            0.0938

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses       WACC\_primary\_agreement                150            0.0784                 0.0259                       0.0525                            0.0525

CICIoT2023 logistic\_existing         10     0.25 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                150            0.0784                -0.0084                       0.0869                            0.0869

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses                           AC                116            0.0847                 0.0169                       0.0679                            0.0679

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                116            0.0847                 0.0152                       0.0695                            0.0695

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses                          ATC                116            0.0847                 0.0357                       0.0490                            0.0496

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                116            0.0847                -0.0240                       0.1087                            0.1087

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses                          DoC                116            0.0847                 0.0169                       0.0679                            0.0679

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                116            0.0847                -0.0245                       0.1092                            0.1092

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses       WACC\_primary\_agreement                116            0.0847                 0.0209                       0.0638                            0.0638

CICIoT2023 logistic\_existing         10     0.50 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                116            0.0847                -0.0143                       0.0990                            0.0990

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses                           AC                194            0.0813                 0.0174                       0.0638                            0.0638

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                194            0.0813                 0.0420                       0.0393                            0.0408

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses                          ATC                194            0.0813                 0.0341                       0.0472                            0.0472

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                194            0.0813                 0.0404                       0.0408                            0.0408

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses                          DoC                194            0.0813                 0.0174                       0.0638                            0.0638

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                194            0.0813                 0.0419                       0.0394                            0.0399

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses       WACC\_primary\_agreement                194            0.0813                 0.0419                       0.0394                            0.0399

CICIoT2023               MLP         10     0.25 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                194            0.0813                 0.0382                       0.0431                            0.0431

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses                           AC                212            0.1050                 0.0161                       0.0889                            0.0889

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                212            0.1050                 0.0617                       0.0433                            0.0448

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses                          ATC                212            0.1050                 0.0290                       0.0760                            0.0760

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                212            0.1050                 0.0598                       0.0453                            0.0467

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses                          DoC                212            0.1050                 0.0161                       0.0889                            0.0889

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                212            0.1050                 0.0586                       0.0464                            0.0464

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses       WACC\_primary\_agreement                212            0.1050                 0.0586                       0.0464                            0.0464

CICIoT2023               MLP         10     0.50 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                212            0.1050                 0.0494                       0.0556                            0.0556

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses                           AC                196            0.0800                 0.0171                       0.0628                            0.0628

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                196            0.0800                 0.0420                       0.0379                            0.0423

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses                          ATC                196            0.0800                 0.0332                       0.0467                            0.0467

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                196            0.0800                 0.0358                       0.0442                            0.0446

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses                          DoC                196            0.0800                 0.0171                       0.0628                            0.0628

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                196            0.0800                 0.0364                       0.0435                            0.0438

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses       WACC\_primary\_agreement                196            0.0800                 0.0364                       0.0435                            0.0438

CICIoT2023               MLP         11     0.25 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                196            0.0800                 0.0333                       0.0466                            0.0466

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses                           AC                196            0.0923                 0.0161                       0.0762                            0.0762

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                196            0.0923                 0.0468                       0.0455                            0.0493

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses                          ATC                196            0.0923                 0.0289                       0.0635                            0.0635

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                196            0.0923                 0.0404                       0.0519                            0.0522

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses                          DoC                196            0.0923                 0.0161                       0.0762                            0.0762

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                196            0.0923                 0.0409                       0.0514                            0.0514

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses       WACC\_primary\_agreement                196            0.0923                 0.0409                       0.0514                            0.0514

CICIoT2023               MLP         11     0.50 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                196            0.0923                 0.0368                       0.0555                            0.0555

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses                           AC                198            0.0806                 0.0168                       0.0638                            0.0638

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                198            0.0806                 0.0385                       0.0421                            0.0435

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses                          ATC                198            0.0806                 0.0338                       0.0468                            0.0468

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                198            0.0806                 0.0356                       0.0450                            0.0464

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses                          DoC                198            0.0806                 0.0168                       0.0638                            0.0638

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                198            0.0806                 0.0344                       0.0462                            0.0462

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses       WACC\_primary\_agreement                198            0.0806                 0.0344                       0.0462                            0.0462

CICIoT2023               MLP         12     0.25 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                198            0.0806                 0.0346                       0.0459                            0.0459

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses                           AC                214            0.1207                 0.0147                       0.1060                            0.1060

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                214            0.1207                 0.0691                       0.0516                            0.0518

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses                          ATC                214            0.1207                 0.0234                       0.0973                            0.0973

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                214            0.1207                 0.0641                       0.0566                            0.0576

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses                          DoC                214            0.1207                 0.0147                       0.1060                            0.1060

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                214            0.1207                 0.0640                       0.0567                            0.0572

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses       WACC\_primary\_agreement                214            0.1207                 0.0640                       0.0567                            0.0572

CICIoT2023               MLP         12     0.50 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                214            0.1207                 0.0548                       0.0659                            0.0659

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses                           AC                134            0.0737                 0.0161                       0.0575                            0.0575

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                134            0.0737                 0.0546                       0.0191                            0.0261

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses                          ATC                134            0.0737                 0.0343                       0.0394                            0.0401

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                134            0.0737                 0.0536                       0.0201                            0.0271

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses                          DoC                134            0.0737                 0.0161                       0.0575                            0.0575

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                134            0.0737                 0.0554                       0.0183                            0.0246

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses       WACC\_primary\_agreement                134            0.0737                 0.0554                       0.0183                            0.0246

CICIoT2023              GBDT         10     0.25 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                134            0.0737                 0.0453                       0.0284                            0.0284

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses                           AC                156            0.0853                 0.0169                       0.0684                            0.0684

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                156            0.0853                 0.0618                       0.0235                            0.0291

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses                          ATC                156            0.0853                 0.0360                       0.0494                            0.0502

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                156            0.0853                 0.0615                       0.0238                            0.0294

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses                          DoC                156            0.0853                 0.0169                       0.0684                            0.0684

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                156            0.0853                 0.0616                       0.0237                            0.0281

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses       WACC\_primary\_agreement                156            0.0853                 0.0616                       0.0237                            0.0281

CICIoT2023              GBDT         10     0.50 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                156            0.0853                 0.0511                       0.0342                            0.0348

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses                           AC                134            0.0737                 0.0161                       0.0575                            0.0575

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                134            0.0737                 0.0546                       0.0191                            0.0261

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses                          ATC                134            0.0737                 0.0343                       0.0394                            0.0401

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                134            0.0737                 0.0536                       0.0201                            0.0271

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses                          DoC                134            0.0737                 0.0161                       0.0575                            0.0575

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                134            0.0737                 0.0554                       0.0183                            0.0246

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses       WACC\_primary\_agreement                134            0.0737                 0.0554                       0.0183                            0.0246

CICIoT2023              GBDT         11     0.25 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                134            0.0737                 0.0453                       0.0284                            0.0284

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses                           AC                156            0.0853                 0.0169                       0.0684                            0.0684

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                156            0.0853                 0.0618                       0.0235                            0.0291

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses                          ATC                156            0.0853                 0.0360                       0.0494                            0.0502

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                156            0.0853                 0.0615                       0.0238                            0.0294

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses                          DoC                156            0.0853                 0.0169                       0.0684                            0.0684

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                156            0.0853                 0.0616                       0.0237                            0.0281

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses       WACC\_primary\_agreement                156            0.0853                 0.0616                       0.0237                            0.0281

CICIoT2023              GBDT         11     0.50 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                156            0.0853                 0.0511                       0.0342                            0.0348

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses                           AC                134            0.0737                 0.0161                       0.0575                            0.0575

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                134            0.0737                 0.0546                       0.0191                            0.0261

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses                          ATC                134            0.0737                 0.0343                       0.0394                            0.0401

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                134            0.0737                 0.0536                       0.0201                            0.0271

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses                          DoC                134            0.0737                 0.0161                       0.0575                            0.0575

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                134            0.0737                 0.0554                       0.0183                            0.0246

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses       WACC\_primary\_agreement                134            0.0737                 0.0554                       0.0183                            0.0246

CICIoT2023              GBDT         12     0.25 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                134            0.0737                 0.0453                       0.0284                            0.0284

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses                           AC                156            0.0853                 0.0169                       0.0684                            0.0684

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses       ANCH\_primary\_agreement                156            0.0853                 0.0618                       0.0235                            0.0291

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses                          ATC                156            0.0853                 0.0360                       0.0494                            0.0502

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses  DRIFTONLY\_primary\_agreement                156            0.0853                 0.0615                       0.0238                            0.0294

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses                          DoC                156            0.0853                 0.0169                       0.0684                            0.0684

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses        MAJ\_primary\_agreement                156            0.0853                 0.0616                       0.0237                            0.0281

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses       WACC\_primary\_agreement                156            0.0853                 0.0616                       0.0237                            0.0281

CICIoT2023              GBDT         12     0.50 objective\_selected accepted\_collapses primary\_view\_agreement\_proxy                156            0.0853                 0.0511                       0.0342                            0.0348


7. CICIoT2023 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoT2023 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CICIoMT2024 single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

CSE single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

NSL single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 REPLAY + POST-PROCESSING REPAIRED

TONIoT single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 REPLAY + POST-PROCESSING REPAIRED



CORRECTED DIRECT-TARGET SUMMARY

&#x20;   dataset  case\_kind\_corrected        domain\_corrected              attack\_family  epsilon      scope estimator  reported\_rows  distinct\_trained\_targets  valid\_estimates  actual\_accuracy  estimated\_accuracy  absolute\_accuracy\_error  true\_damage  estimated\_damage  differential\_absolute\_error

CICIoMT2024         clean\_source            clean\_source                       none      NaN whole\_case        AC              3                         3                3           0.9655              0.9637                   0.0017          NaN               NaN                          NaN

CICIoMT2024         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_D              3                         3                3           0.9655              0.9649                   0.0030          NaN               NaN                          NaN

CICIoMT2024         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_S              3                         3                3           0.9655              0.9691                   0.0036          NaN               NaN                          NaN

CICIoMT2024         clean\_source            clean\_source                       none      NaN whole\_case       DoC              3                         3                3           0.9655              0.9717                   0.0062          NaN               NaN                          NaN

CICIoMT2024         clean\_source            clean\_source                       none      NaN window\_128        AC            117                         3              117           0.9655              0.9637                   0.0094          NaN               NaN                          NaN

CICIoMT2024         clean\_source            clean\_source                       none      NaN window\_128   ALine\_D            117                         3              117           0.9655              0.9675                   0.0189          NaN               NaN                          NaN

CICIoMT2024         clean\_source            clean\_source                       none      NaN window\_128   ALine\_S            117                         3              117           0.9655              0.9750                   0.0134          NaN               NaN                          NaN

CICIoMT2024         clean\_source            clean\_source                       none      NaN window\_128       DoC            117                         3              117           0.9655              0.9717                   0.0101          NaN               NaN                          NaN

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case        AC              9                         3                9           0.9649              0.9633                   0.0019       0.0006            0.0004                       0.0004

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9649              0.9649                   0.0029       0.0006            0.0001                       0.0007

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9649              0.9686                   0.0037       0.0006            0.0005                       0.0002

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9649              0.9713                   0.0064       0.0006            0.0004                       0.0004

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128        AC            351                         3              351           0.9649              0.9633                   0.0096       0.0006            0.0004                       0.0015

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_D            351                         3              351           0.9649              0.9677                   0.0188       0.0006           -0.0003                       0.0053

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_S            351                         3              351           0.9649              0.9749                   0.0139       0.0006            0.0001                       0.0027

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128       DoC            351                         3              351           0.9649              0.9713                   0.0107       0.0006            0.0004                       0.0015

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case        AC              9                         3                9           0.9641              0.9625                   0.0018       0.0014            0.0012                       0.0005

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9641              0.9652                   0.0030       0.0014           -0.0002                       0.0016

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9641              0.9679                   0.0037       0.0014            0.0012                       0.0001

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9641              0.9705                   0.0063       0.0014            0.0012                       0.0005

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128        AC            351                         3              351           0.9641              0.9625                   0.0096       0.0014            0.0012                       0.0026

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_D            351                         3              351           0.9641              0.9677                   0.0188       0.0014           -0.0002                       0.0080

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_S            351                         3              351           0.9641              0.9741                   0.0144       0.0014            0.0009                       0.0037

CICIoMT2024 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128       DoC            351                         3              351           0.9641              0.9705                   0.0108       0.0014            0.0012                       0.0026

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case        AC              9                         3                9           0.9654              0.9635                   0.0020       0.0001            0.0003                       0.0004

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_D              9                         3                9           0.9654              0.9647                   0.0028       0.0001            0.0003                       0.0009

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_S              9                         3                9           0.9654              0.9692                   0.0038       0.0001           -0.0001                       0.0004

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case       DoC              9                         3                9           0.9654              0.9714                   0.0060       0.0001            0.0003                       0.0004

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128        AC            351                         3              351           0.9654              0.9635                   0.0094       0.0001            0.0003                       0.0012

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_D            351                         3              351           0.9654              0.9670                   0.0199       0.0001            0.0005                       0.0050

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_S            351                         3              351           0.9654              0.9753                   0.0140       0.0001           -0.0003                       0.0023

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128       DoC            351                         3              351           0.9654              0.9714                   0.0101       0.0001            0.0003                       0.0012

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case        AC              9                         3                9           0.9658              0.9629                   0.0029      -0.0003            0.0008                       0.0011

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_D              9                         3                9           0.9658              0.9642                   0.0031      -0.0003            0.0007                       0.0013

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_S              9                         3                9           0.9658              0.9686                   0.0028      -0.0003            0.0005                       0.0009

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case       DoC              9                         3                9           0.9658              0.9709                   0.0051      -0.0003            0.0008                       0.0011

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128        AC            351                         3              351           0.9658              0.9629                   0.0095      -0.0003            0.0008                       0.0024

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_D            351                         3              351           0.9658              0.9671                   0.0198      -0.0003            0.0004                       0.0077

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_S            351                         3              351           0.9658              0.9749                   0.0139      -0.0003            0.0002                       0.0036

CICIoMT2024 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128       DoC            351                         3              351           0.9658              0.9709                   0.0097      -0.0003            0.0008                       0.0024

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case        AC              9                         3                9           0.9639              0.9631                   0.0016       0.0015            0.0006                       0.0009

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9639              0.9658                   0.0035       0.0015           -0.0009                       0.0024

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9639              0.9691                   0.0051       0.0015            0.0000                       0.0015

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9639              0.9711                   0.0072       0.0015            0.0006                       0.0009

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128        AC            351                         3              351           0.9639              0.9631                   0.0098       0.0015            0.0006                       0.0020

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_D            351                         3              351           0.9639              0.9680                   0.0197       0.0015           -0.0006                       0.0058

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_S            351                         3              351           0.9639              0.9750                   0.0148       0.0015            0.0000                       0.0028

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128       DoC            351                         3              351           0.9639              0.9711                   0.0110       0.0015            0.0006                       0.0020

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case        AC              9                         3                9           0.9628              0.9619                   0.0014       0.0026            0.0018                       0.0008

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9628              0.9660                   0.0035       0.0026           -0.0010                       0.0037

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9628              0.9684                   0.0055       0.0026            0.0007                       0.0019

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9628              0.9699                   0.0070       0.0026            0.0018                       0.0008

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128        AC            351                         3              351           0.9628              0.9619                   0.0098       0.0026            0.0018                       0.0032

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_D            351                         3              351           0.9628              0.9691                   0.0200       0.0026           -0.0016                       0.0087

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_S            351                         3              351           0.9628              0.9742                   0.0149       0.0026            0.0009                       0.0043

CICIoMT2024 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128       DoC            351                         3              351           0.9628              0.9699                   0.0110       0.0026            0.0018                       0.0032

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case        AC              3                         3                3           0.8064              0.9239                   0.1175          NaN               NaN                          NaN

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case   ALine\_D              3                         3                3           0.8064              0.9453                   0.1389          NaN               NaN                          NaN

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case   ALine\_S              3                         3                3           0.8064              0.9538                   0.1474          NaN               NaN                          NaN

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case       DoC              3                         3                3           0.8064              0.9319                   0.1254          NaN               NaN                          NaN

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN window\_128        AC            258                         3              258           0.8064              0.9238                   0.1174          NaN               NaN                          NaN

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN window\_128   ALine\_D            258                         3              258           0.8064              0.9439                   0.1376          NaN               NaN                          NaN

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN window\_128   ALine\_S            258                         3              258           0.8064              0.9561                   0.1498          NaN               NaN                          NaN

CICIoMT2024        natural\_shift  natural\_heldout\_family                       none      NaN window\_128       DoC            258                         3              258           0.8064              0.9318                   0.1254          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN whole\_case        AC              3                         3                3           0.9104              0.9119                   0.0030          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_D              3                         3                3           0.9104              0.9234                   0.0130          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_S              3                         3                3           0.9104              0.9212                   0.0108          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN whole\_case       DoC              3                         3                3           0.9104              0.9197                   0.0093          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN window\_128        AC            126                         3              126           0.9104              0.9119                   0.0171          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN window\_128   ALine\_D            126                         3              126           0.9104              0.9233                   0.0297          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN window\_128   ALine\_S            126                         3              126           0.9104              0.9229                   0.0215          NaN               NaN                          NaN

&#x20;CICIoT2023         clean\_source            clean\_source                       none      NaN window\_128       DoC            126                         3              126           0.9104              0.9197                   0.0189          NaN               NaN                          NaN

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case        AC              9                         3                9           0.8923              0.9128                   0.0204       0.0181           -0.0009                       0.0190

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.8923              0.9298                   0.0375       0.0181           -0.0064                       0.0245

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.8923              0.9232                   0.0308       0.0181           -0.0020                       0.0201

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case       DoC              9                         3                9           0.8923              0.9206                   0.0282       0.0181           -0.0009                       0.0190

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128        AC            378                         3              378           0.8923              0.9128                   0.0248       0.0181           -0.0009                       0.0191

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_D            378                         3              378           0.8923              0.9311                   0.0420       0.0181           -0.0078                       0.0277

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_S            378                         3              378           0.8923              0.9251                   0.0344       0.0181           -0.0022                       0.0206

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128       DoC            378                         3              378           0.8923              0.9206                   0.0306       0.0181           -0.0009                       0.0191

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case        AC              9                         3                9           0.8833              0.9128                   0.0295       0.0271           -0.0009                       0.0280

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.8833              0.9328                   0.0495       0.0271           -0.0095                       0.0366

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.8833              0.9240                   0.0407       0.0271           -0.0028                       0.0299

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case       DoC              9                         3                9           0.8833              0.9206                   0.0373       0.0271           -0.0009                       0.0280

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128        AC            378                         3              378           0.8833              0.9128                   0.0321       0.0271           -0.0009                       0.0281

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_D            378                         3              378           0.8833              0.9331                   0.0510       0.0271           -0.0098                       0.0390

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_S            378                         3              378           0.8833              0.9257                   0.0436       0.0271           -0.0028                       0.0302

&#x20;CICIoT2023 feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128       DoC            378                         3              378           0.8833              0.9206                   0.0388       0.0271           -0.0009                       0.0281

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case        AC              9                         3                9           0.8989              0.9127                   0.0138       0.0115           -0.0008                       0.0123

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_D              9                         3                9           0.8989              0.9269                   0.0280       0.0115           -0.0036                       0.0151

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_S              9                         3                9           0.8989              0.9225                   0.0236       0.0115           -0.0013                       0.0128

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case       DoC              9                         3                9           0.8989              0.9205                   0.0215       0.0115           -0.0008                       0.0123

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128        AC            378                         3              378           0.8989              0.9127                   0.0216       0.0115           -0.0008                       0.0129

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_D            378                         3              378           0.8989              0.9273                   0.0363       0.0115           -0.0040                       0.0198

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_S            378                         3              378           0.8989              0.9243                   0.0295       0.0115           -0.0014                       0.0137

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128       DoC            378                         3              378           0.8989              0.9205                   0.0261       0.0115           -0.0008                       0.0129

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case        AC              9                         3                9           0.8929              0.9130                   0.0201       0.0175           -0.0011                       0.0186

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_D              9                         3                9           0.8929              0.9286                   0.0357       0.0175           -0.0052                       0.0228

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_S              9                         3                9           0.8929              0.9233                   0.0304       0.0175           -0.0021                       0.0196

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case       DoC              9                         3                9           0.8929              0.9208                   0.0279       0.0175           -0.0011                       0.0186

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128        AC            378                         3              378           0.8929              0.9130                   0.0257       0.0175           -0.0011                       0.0195

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_D            378                         3              378           0.8929              0.9285                   0.0412       0.0175           -0.0053                       0.0290

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_S            378                         3              378           0.8929              0.9251                   0.0354       0.0175           -0.0022                       0.0210

&#x20;CICIoT2023 feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128       DoC            378                         3              378           0.8929              0.9208                   0.0314       0.0175           -0.0011                       0.0195

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case        AC              9                         3                9           0.8882              0.9133                   0.0250       0.0222           -0.0014                       0.0236

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.8882              0.9308                   0.0426       0.0222           -0.0075                       0.0297

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.8882              0.9223                   0.0341       0.0222           -0.0011                       0.0233

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case       DoC              9                         3                9           0.8882              0.9210                   0.0328       0.0222           -0.0014                       0.0236

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128        AC            378                         3              378           0.8882              0.9133                   0.0280       0.0222           -0.0014                       0.0237

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_D            378                         3              378           0.8882              0.9317                   0.0457       0.0222           -0.0084                       0.0319

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_S            378                         3              378           0.8882              0.9241                   0.0373       0.0222           -0.0012                       0.0235

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128       DoC            378                         3              378           0.8882              0.9210                   0.0346       0.0222           -0.0014                       0.0237

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case        AC              9                         3                9           0.8769              0.9124                   0.0355       0.0335           -0.0005                       0.0340

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.8769              0.9337                   0.0568       0.0335           -0.0103                       0.0438

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.8769              0.9225                   0.0456       0.0335           -0.0013                       0.0348

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case       DoC              9                         3                9           0.8769              0.9202                   0.0433       0.0335           -0.0005                       0.0340

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128        AC            378                         3              378           0.8769              0.9124                   0.0376       0.0335           -0.0005                       0.0342

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_D            378                         3              378           0.8769              0.9342                   0.0582       0.0335           -0.0109                       0.0459

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_S            378                         3              378           0.8769              0.9242                   0.0486       0.0335           -0.0014                       0.0349

&#x20;CICIoT2023 feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128       DoC            378                         3              378           0.8769              0.9202                   0.0444       0.0335           -0.0005                       0.0342

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case        AC              3                         3                3           0.8519              0.8901                   0.0382          NaN               NaN                          NaN

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case   ALine\_D              3                         3                3           0.8519              0.8951                   0.0432          NaN               NaN                          NaN

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case   ALine\_S              3                         3                3           0.8519              0.8794                   0.0275          NaN               NaN                          NaN

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case       DoC              3                         3                3           0.8519              0.8979                   0.0460          NaN               NaN                          NaN

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN window\_128        AC            321                         3              321           0.8519              0.8900                   0.0412          NaN               NaN                          NaN

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN window\_128   ALine\_D            321                         3              321           0.8519              0.8941                   0.0506          NaN               NaN                          NaN

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN window\_128   ALine\_S            321                         3              321           0.8519              0.8812                   0.0373          NaN               NaN                          NaN

&#x20;CICIoT2023        natural\_shift  natural\_heldout\_family                       none      NaN window\_128       DoC            321                         3              321           0.8519              0.8978                   0.0479          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN whole\_case        AC              3                         3                3           0.9898              0.9747                   0.0151          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_D              3                         3                3           0.9898              0.9933                   0.0035          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_S              3                         3                3           0.9898              0.9933                   0.0035          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN whole\_case       DoC              3                         3                3           0.9898              0.9906                   0.0008          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN window\_128        AC             33                         3               33           0.9898              0.9747                   0.0152          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN window\_128   ALine\_D             33                         3               33           0.9898              0.9944                   0.0116          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN window\_128   ALine\_S             33                         3               33           0.9898              0.9981                   0.0094          NaN               NaN                          NaN

&#x20;       CSE         clean\_source            clean\_source                       none      NaN window\_128       DoC             33                         3               33           0.9898              0.9903                   0.0058          NaN               NaN                          NaN

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case        AC              9                         3                9           0.9781              0.9686                   0.0094       0.0118            0.0061                       0.0075

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9781              0.9783                   0.0025       0.0118            0.0150                       0.0038

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9781              0.9851                   0.0102       0.0118            0.0082                       0.0092

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9781              0.9846                   0.0074       0.0118            0.0061                       0.0075

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128        AC             99                         3               99           0.9781              0.9686                   0.0130       0.0118            0.0061                       0.0095

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_D             99                         3               99           0.9781              0.9793                   0.0162       0.0118            0.0151                       0.0110

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_S             99                         3               99           0.9781              0.9919                   0.0158       0.0118            0.0061                       0.0103

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128       DoC             99                         3               99           0.9781              0.9845                   0.0108       0.0118            0.0057                       0.0094

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case        AC              9                         3                9           0.9621              0.9629                   0.0111       0.0277            0.0118                       0.0160

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9621              0.9775                   0.0268       0.0277            0.0158                       0.0263

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9621              0.9823                   0.0201       0.0277            0.0110                       0.0179

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9621              0.9788                   0.0167       0.0277            0.0118                       0.0160

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128        AC             99                         3               99           0.9621              0.9629                   0.0145       0.0277            0.0118                       0.0202

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_D             99                         3               99           0.9621              0.9773                   0.0389       0.0277            0.0171                       0.0371

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_S             99                         3               99           0.9621              0.9905                   0.0289       0.0277            0.0075                       0.0225

&#x20;       CSE feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128       DoC             99                         3               99           0.9621              0.9788                   0.0196       0.0277            0.0114                       0.0200

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case        AC              9                         3                9           0.9799              0.9694                   0.0105       0.0099            0.0053                       0.0062

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_D              9                         3                9           0.9799              0.9789                   0.0011       0.0099            0.0144                       0.0045

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_S              9                         3                9           0.9799              0.9862                   0.0090       0.0099            0.0071                       0.0079

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case       DoC              9                         3                9           0.9799              0.9853                   0.0061       0.0099            0.0053                       0.0062

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128        AC             99                         3               99           0.9799              0.9694                   0.0134       0.0099            0.0053                       0.0085

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_D             99                         3               99           0.9799              0.9768                   0.0176       0.0099            0.0176                       0.0121

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_S             99                         3               99           0.9799              0.9926                   0.0150       0.0099            0.0054                       0.0088

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128       DoC             99                         3               99           0.9799              0.9852                   0.0100       0.0099            0.0051                       0.0082

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case        AC              9                         3                9           0.9646              0.9641                   0.0116       0.0252            0.0106                       0.0161

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_D              9                         3                9           0.9646              0.9740                   0.0160       0.0252            0.0193                       0.0155

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_S              9                         3                9           0.9646              0.9788                   0.0179       0.0252            0.0145                       0.0169

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case       DoC              9                         3                9           0.9646              0.9800                   0.0162       0.0252            0.0106                       0.0161

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128        AC             99                         3               99           0.9646              0.9641                   0.0145       0.0252            0.0106                       0.0181

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_D             99                         3               99           0.9646              0.9779                   0.0255       0.0252            0.0165                       0.0223

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_S             99                         3               99           0.9646              0.9864                   0.0243       0.0252            0.0117                       0.0188

&#x20;       CSE feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128       DoC             99                         3               99           0.9646              0.9800                   0.0181       0.0252            0.0103                       0.0180

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case        AC              9                         3                9           0.9744              0.9674                   0.0069       0.0155            0.0073                       0.0082

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9744              0.9706                   0.0066       0.0155            0.0227                       0.0074

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9744              0.9861                   0.0118       0.0155            0.0072                       0.0083

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9744              0.9833                   0.0090       0.0155            0.0073                       0.0082

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128        AC             99                         3               99           0.9744              0.9674                   0.0110       0.0155            0.0073                       0.0110

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_D             99                         3               99           0.9744              0.9656                   0.0204       0.0155            0.0287                       0.0168

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_S             99                         3               99           0.9744              0.9924                   0.0185       0.0155            0.0056                       0.0103

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128       DoC             99                         3               99           0.9744              0.9833                   0.0109       0.0155            0.0069                       0.0108

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case        AC              9                         3                9           0.9555              0.9615                   0.0060       0.0343            0.0132                       0.0211

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9555              0.9833                   0.0278       0.0343            0.0100                       0.0243

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9555              0.9816                   0.0261       0.0343            0.0117                       0.0226

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9555              0.9774                   0.0219       0.0343            0.0132                       0.0211

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128        AC             99                         3               99           0.9555              0.9615                   0.0123       0.0343            0.0132                       0.0226

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_D             99                         3               99           0.9555              0.9908                   0.0360       0.0343            0.0036                       0.0307

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_S             99                         3               99           0.9555              0.9901                   0.0346       0.0343            0.0080                       0.0263

&#x20;       CSE feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128       DoC             99                         3               99           0.9555              0.9774                   0.0223       0.0343            0.0129                       0.0224

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN whole\_case        AC              3                         3                3           0.5079              0.9545                   0.4466          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN whole\_case   ALine\_D              3                         3                3           0.5079              0.9829                   0.4750          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN whole\_case   ALine\_S              3                         3                3           0.5079              0.9788                   0.4709          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN whole\_case       DoC              3                         3                3           0.5079              0.9705                   0.4626          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN window\_128        AC            138                         3              138           0.5076              0.9545                   0.4469          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN window\_128   ALine\_D            138                         3              138           0.5076              0.9866                   0.4790          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN window\_128   ALine\_S            138                         3              138           0.5076              0.9867                   0.4790          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Botnet                       none      NaN window\_128       DoC            138                         3              138           0.5076              0.9704                   0.4628          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN whole\_case        AC              3                         3                3           0.4886              0.9877                   0.4991          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN whole\_case   ALine\_D              3                         3                3           0.4886              0.9909                   0.5023          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN whole\_case   ALine\_S              3                         3                3           0.4886              0.9890                   0.5004          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN whole\_case       DoC              3                         3                3           0.4886              1.0000                   0.5114          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN window\_128        AC            141                         3              141           0.4886              0.9877                   0.4991          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN window\_128   ALine\_D            141                         3              141           0.4886              0.9916                   0.5030          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN window\_128   ALine\_S            141                         3              141           0.4886              0.9961                   0.5075          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift  natural\_day\_Bruteforce                       none      NaN window\_128       DoC            141                         3              141           0.4886              0.9995                   0.5109          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN whole\_case        AC              3                         3                3           0.6825              0.9846                   0.3021          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN whole\_case   ALine\_D              3                         3                3           0.6825              0.9928                   0.3103          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN whole\_case   ALine\_S              3                         3                3           0.6825              0.9793                   0.2968          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN whole\_case       DoC              3                         3                3           0.6825              0.9961                   0.3136          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN window\_128        AC            219                         3              219           0.6816              0.9845                   0.3029          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN window\_128   ALine\_D            219                         3              219           0.6816              0.9974                   0.3157          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN window\_128   ALine\_S            219                         3              219           0.6816              0.9922                   0.3105          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift       natural\_day\_DDoS2                       none      NaN window\_128       DoC            219                         3              219           0.6816              0.9959                   0.3142          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN whole\_case        AC              3                         3                3           0.5689              0.9736                   0.4047          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN whole\_case   ALine\_D              3                         3                3           0.5689              0.9851                   0.4162          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN whole\_case   ALine\_S              3                         3                3           0.5689              0.9782                   0.4093          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN whole\_case       DoC              3                         3                3           0.5689              0.9895                   0.4206          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN window\_128        AC            279                         3              279           0.5688              0.9736                   0.4048          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN window\_128   ALine\_D            279                         3              279           0.5688              0.9898                   0.4210          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN window\_128   ALine\_S            279                         3              279           0.5688              0.9884                   0.4196          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS1                       none      NaN window\_128       DoC            279                         3              279           0.5688              0.9892                   0.4205          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN whole\_case        AC              3                         3                3           0.8936              0.8611                   0.0347          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN whole\_case   ALine\_D              3                         3                3           0.8936              0.9989                   0.1053          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN whole\_case   ALine\_S              3                         3                3           0.8936              0.9983                   0.1047          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN whole\_case       DoC              3                         3                3           0.8936              0.8770                   0.0300          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN window\_128        AC            141                         3              141           0.8931              0.8614                   0.0427          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN window\_128   ALine\_D            141                         3              141           0.8931              0.9978                   0.1047          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN window\_128   ALine\_S            141                         3              141           0.8931              0.9996                   0.1066          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_DoS2                       none      NaN window\_128       DoC            141                         3              141           0.8931              0.8773                   0.0380          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN whole\_case        AC              3                         3                3           0.5028              0.9567                   0.4539          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN whole\_case   ALine\_D              3                         3                3           0.5028              0.9491                   0.4462          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN whole\_case   ALine\_S              3                         3                3           0.5028              0.9515                   0.4487          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN whole\_case       DoC              3                         3                3           0.5028              0.9727                   0.4698          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN window\_128        AC            138                         3              138           0.5028              0.9563                   0.4535          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN window\_128   ALine\_D            138                         3              138           0.5028              0.9493                   0.4465          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN window\_128   ALine\_S            138                         3              138           0.5028              0.9548                   0.4520          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil1                       none      NaN window\_128       DoC            138                         3              138           0.5028              0.9721                   0.4693          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN whole\_case        AC              3                         3                3           0.5076              0.9628                   0.4552          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN whole\_case   ALine\_D              3                         3                3           0.5076              0.9489                   0.4413          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN whole\_case   ALine\_S              3                         3                3           0.5076              0.9489                   0.4413          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN whole\_case       DoC              3                         3                3           0.5076              0.9787                   0.4711          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN window\_128        AC            138                         3              138           0.5075              0.9629                   0.4554          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN window\_128   ALine\_D            138                         3              138           0.5075              0.9498                   0.4423          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN window\_128   ALine\_S            138                         3              138           0.5075              0.9522                   0.4447          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift      natural\_day\_Infil2                       none      NaN window\_128       DoC            138                         3              138           0.5075              0.9788                   0.4713          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN whole\_case        AC              3                         3                3           0.5352              0.9026                   0.3674          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN whole\_case   ALine\_D              3                         3                3           0.5352              0.8533                   0.3181          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN whole\_case   ALine\_S              3                         3                3           0.5352              0.9066                   0.3714          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN whole\_case       DoC              3                         3                3           0.5352              0.9185                   0.3833          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN window\_128        AC             15                         3               15           0.5260              0.9028                   0.3768          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN window\_128   ALine\_D             15                         3               15           0.5260              0.8533                   0.3273          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN window\_128   ALine\_S             15                         3               15           0.5260              0.9110                   0.3849          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web1                       none      NaN window\_128       DoC             15                         3               15           0.5260              0.9187                   0.3927          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN whole\_case        AC              3                         3                3           0.5302              0.9218                   0.3916          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN whole\_case   ALine\_D              3                         3                3           0.5302              0.8815                   0.3513          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN whole\_case   ALine\_S              3                         3                3           0.5302              0.9229                   0.3927          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN whole\_case       DoC              3                         3                3           0.5302              0.9377                   0.4075          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN window\_128        AC             24                         3               24           0.5273              0.9236                   0.3963          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN window\_128   ALine\_D             24                         3               24           0.5273              0.8865                   0.3592          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN window\_128   ALine\_S             24                         3               24           0.5273              0.9303                   0.4030          NaN               NaN                          NaN

&#x20;       CSE        natural\_shift        natural\_day\_Web2                       none      NaN window\_128       DoC             24                         3               24           0.5273              0.9396                   0.4122          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN whole\_case        AC              3                         3                3           0.9517              0.9516                   0.0010          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_D              3                         3                3           0.9517              0.9494                   0.0027          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_S              3                         3                3           0.9517              0.9526                   0.0029          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN whole\_case       DoC              3                         3                3           0.9517              0.9555                   0.0043          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN window\_128        AC             33                         3               33           0.9517              0.9516                   0.0106          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN window\_128   ALine\_D             33                         3               33           0.9517              0.9537                   0.0263          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN window\_128   ALine\_S             33                         3               33           0.9517              0.9569                   0.0216          NaN               NaN                          NaN

&#x20;       NSL         clean\_source            clean\_source                       none      NaN window\_128       DoC             33                         3               33           0.9517              0.9555                   0.0122          NaN               NaN                          NaN

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case        AC              9                         3                9           0.9515              0.9510                   0.0008       0.0002            0.0005                       0.0006

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9515              0.9476                   0.0039       0.0002            0.0018                       0.0016

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9515              0.9520                   0.0029       0.0002            0.0006                       0.0004

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9515              0.9550                   0.0045       0.0002            0.0005                       0.0006

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128        AC             99                         3               99           0.9515              0.9510                   0.0105       0.0002            0.0005                       0.0013

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_D             99                         3               99           0.9515              0.9496                   0.0240       0.0002            0.0041                       0.0040

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_S             99                         3               99           0.9515              0.9562                   0.0211       0.0002            0.0007                       0.0019

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128       DoC             99                         3               99           0.9515              0.9550                   0.0119       0.0002            0.0005                       0.0013

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case        AC              9                         3                9           0.9512              0.9502                   0.0010       0.0005            0.0014                       0.0010

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9512              0.9460                   0.0053       0.0005            0.0034                       0.0029

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9512              0.9514                   0.0020       0.0005            0.0012                       0.0009

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9512              0.9542                   0.0037       0.0005            0.0014                       0.0010

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128        AC             99                         3               99           0.9512              0.9502                   0.0105       0.0005            0.0014                       0.0025

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_D             99                         3               99           0.9512              0.9470                   0.0237       0.0005            0.0067                       0.0065

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_S             99                         3               99           0.9512              0.9549                   0.0207       0.0005            0.0020                       0.0032

&#x20;       NSL feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128       DoC             99                         3               99           0.9512              0.9542                   0.0117       0.0005            0.0014                       0.0025

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case        AC              9                         3                9           0.9515              0.9516                   0.0008       0.0002            0.0000                       0.0003

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_D              9                         3                9           0.9515              0.9485                   0.0030       0.0002            0.0009                       0.0007

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_S              9                         3                9           0.9515              0.9525                   0.0029       0.0002            0.0001                       0.0003

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case       DoC              9                         3                9           0.9515              0.9555                   0.0044       0.0002            0.0000                       0.0003

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128        AC             99                         3               99           0.9515              0.9516                   0.0105       0.0002            0.0000                       0.0006

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_D             99                         3               99           0.9515              0.9513                   0.0249       0.0002            0.0024                       0.0023

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_S             99                         3               99           0.9515              0.9567                   0.0215       0.0002            0.0002                       0.0010

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128       DoC             99                         3               99           0.9515              0.9555                   0.0121       0.0002            0.0000                       0.0006

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case        AC              9                         3                9           0.9514              0.9514                   0.0011       0.0003            0.0001                       0.0008

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_D              9                         3                9           0.9514              0.9476                   0.0039       0.0003            0.0018                       0.0016

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_S              9                         3                9           0.9514              0.9520                   0.0022       0.0003            0.0006                       0.0007

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case       DoC              9                         3                9           0.9514              0.9554                   0.0042       0.0003            0.0001                       0.0008

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128        AC             99                         3               99           0.9514              0.9514                   0.0106       0.0003            0.0001                       0.0013

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_D             99                         3               99           0.9514              0.9495                   0.0237       0.0003            0.0042                       0.0044

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_S             99                         3               99           0.9514              0.9556                   0.0207       0.0003            0.0013                       0.0024

&#x20;       NSL feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128       DoC             99                         3               99           0.9514              0.9554                   0.0121       0.0003            0.0001                       0.0013

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case        AC              9                         3                9           0.9512              0.9509                   0.0006       0.0005            0.0007                       0.0004

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9512              0.9479                   0.0033       0.0005            0.0014                       0.0010

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9512              0.9520                   0.0026       0.0005            0.0006                       0.0003

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9512              0.9548                   0.0041       0.0005            0.0007                       0.0004

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128        AC             99                         3               99           0.9512              0.9509                   0.0107       0.0005            0.0007                       0.0011

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_D             99                         3               99           0.9512              0.9500                   0.0241       0.0005            0.0037                       0.0032

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_S             99                         3               99           0.9512              0.9564                   0.0216       0.0005            0.0006                       0.0012

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128       DoC             99                         3               99           0.9512              0.9548                   0.0121       0.0005            0.0007                       0.0011

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case        AC              9                         3                9           0.9505              0.9499                   0.0006       0.0012            0.0017                       0.0010

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9505              0.9468                   0.0037       0.0012            0.0026                       0.0014

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9505              0.9514                   0.0021       0.0012            0.0012                       0.0008

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9505              0.9539                   0.0036       0.0012            0.0017                       0.0010

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128        AC             99                         3               99           0.9505              0.9499                   0.0108       0.0012            0.0017                       0.0024

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_D             99                         3               99           0.9505              0.9480                   0.0227       0.0012            0.0057                       0.0049

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_S             99                         3               99           0.9505              0.9550                   0.0211       0.0012            0.0020                       0.0026

&#x20;       NSL feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128       DoC             99                         3               99           0.9505              0.9539                   0.0118       0.0012            0.0017                       0.0024

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN whole\_case        AC              3                         3                3           0.7828              0.9345                   0.1517          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN whole\_case   ALine\_D              3                         3                3           0.7828              0.8960                   0.1132          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN whole\_case   ALine\_S              3                         3                3           0.7828              0.9122                   0.1293          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN whole\_case       DoC              3                         3                3           0.7828              0.9385                   0.1557          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN window\_128        AC            279                         3              279           0.7827              0.9345                   0.1518          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN window\_128   ALine\_D            279                         3              279           0.7827              0.8962                   0.1143          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN window\_128   ALine\_S            279                         3              279           0.7827              0.9144                   0.1317          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift   natural\_official\_test                       none      NaN window\_128       DoC            279                         3              279           0.7827              0.9384                   0.1557          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN whole\_case        AC              3                         3                3           0.6379              0.8942                   0.2563          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN whole\_case   ALine\_D              3                         3                3           0.6379              0.8242                   0.1863          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN whole\_case   ALine\_S              3                         3                3           0.6379              0.8463                   0.2085          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN whole\_case       DoC              3                         3                3           0.6379              0.8981                   0.2603          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN window\_128        AC             99                         3               99           0.6392              0.8942                   0.2549          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN window\_128   ALine\_D             99                         3               99           0.6392              0.8246                   0.1863          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN window\_128   ALine\_S             99                         3               99           0.6392              0.8479                   0.2087          NaN               NaN                          NaN

&#x20;       NSL        natural\_shift natural\_official\_test21                       none      NaN window\_128       DoC             99                         3               99           0.6392              0.8981                   0.2589          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN whole\_case        AC              3                         3                3           0.9234              0.9241                   0.0008          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_D              3                         3                3           0.9234              0.9768                   0.0534          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN whole\_case   ALine\_S              3                         3                3           0.9234              0.9795                   0.0561          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN whole\_case       DoC              3                         3                3           0.9234              0.9233                   0.0014          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN window\_128        AC             72                         3               72           0.9234              0.9241                   0.0175          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN window\_128   ALine\_D             72                         3               72           0.9234              0.8571                   0.1558          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN window\_128   ALine\_S             72                         3               72           0.9234              0.8831                   0.1370          NaN               NaN                          NaN

&#x20;    TONIoT         clean\_source            clean\_source                       none      NaN window\_128       DoC             72                         3               72           0.9234              0.9233                   0.0175          NaN               NaN                          NaN

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case        AC              9                         3                9           0.9227              0.9240                   0.0012       0.0007            0.0001                       0.0006

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9227              0.9812                   0.0584       0.0007           -0.0044                       0.0050

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9227              0.9806                   0.0579       0.0007           -0.0011                       0.0017

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9227              0.9232                   0.0011       0.0007            0.0001                       0.0006

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128        AC            216                         3              216           0.9227              0.9240                   0.0182       0.0007            0.0001                       0.0012

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_D            216                         3              216           0.9227              0.8752                   0.1513       0.0007           -0.0181                       0.0187

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128   ALine\_S            216                         3              216           0.9227              0.8851                   0.1397       0.0007           -0.0020                       0.0026

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.25 window\_128       DoC            216                         3              216           0.9227              0.9232                   0.0181       0.0007            0.0001                       0.0012

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case        AC              9                         3                9           0.9227              0.9240                   0.0013       0.0007            0.0000                       0.0006

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9227              0.9812                   0.0584       0.0007           -0.0044                       0.0050

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9227              0.9806                   0.0579       0.0007           -0.0011                       0.0017

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9227              0.9232                   0.0011       0.0007            0.0000                       0.0006

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128        AC            216                         3              216           0.9227              0.9240                   0.0182       0.0007            0.0000                       0.0012

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_D            216                         3              216           0.9227              0.8752                   0.1513       0.0007           -0.0181                       0.0187

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128   ALine\_S            216                         3              216           0.9227              0.8851                   0.1397       0.0007           -0.0020                       0.0026

&#x20;    TONIoT feature\_space\_attack             source\_test   coordinated\_ensemble\_pgd     0.50 window\_128       DoC            216                         3              216           0.9227              0.9232                   0.0182       0.0007            0.0000                       0.0012

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case        AC              9                         3                9           0.9229              0.9245                   0.0016       0.0005           -0.0004                       0.0009

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_D              9                         3                9           0.9229              0.9818                   0.0589       0.0005           -0.0050                       0.0055

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case   ALine\_S              9                         3                9           0.9229              0.9820                   0.0590       0.0005           -0.0024                       0.0029

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 whole\_case       DoC              9                         3                9           0.9229              0.9237                   0.0016       0.0005           -0.0004                       0.0009

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128        AC            216                         3              216           0.9229              0.9245                   0.0180       0.0005           -0.0004                       0.0013

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_D            216                         3              216           0.9229              0.8739                   0.1514       0.0005           -0.0168                       0.0175

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128   ALine\_S            216                         3              216           0.9229              0.8857                   0.1398       0.0005           -0.0026                       0.0032

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.25 window\_128       DoC            216                         3              216           0.9229              0.9237                   0.0179       0.0005           -0.0004                       0.0013

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case        AC              9                         3                9           0.9234              0.9251                   0.0018       0.0000           -0.0011                       0.0011

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_D              9                         3                9           0.9234              0.9820                   0.0586       0.0000           -0.0052                       0.0086

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case   ALine\_S              9                         3                9           0.9234              0.9840                   0.0607       0.0000           -0.0045                       0.0045

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 whole\_case       DoC              9                         3                9           0.9234              0.9244                   0.0016       0.0000           -0.0011                       0.0011

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128        AC            216                         3              216           0.9234              0.9251                   0.0180       0.0000           -0.0011                       0.0020

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_D            216                         3              216           0.9234              0.8852                   0.1413       0.0000           -0.0281                       0.0363

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128   ALine\_S            216                         3              216           0.9234              0.9070                   0.1201       0.0000           -0.0239                       0.0245

&#x20;    TONIoT feature\_space\_attack             source\_test genuine\_surrogate\_transfer     0.50 window\_128       DoC            216                         3              216           0.9234              0.9244                   0.0179       0.0000           -0.0011                       0.0020

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case        AC              9                         3                9           0.9227              0.9233                   0.0006       0.0007            0.0008                       0.0002

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_D              9                         3                9           0.9227              0.9810                   0.0583       0.0007           -0.0042                       0.0049

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case   ALine\_S              9                         3                9           0.9227              0.9807                   0.0580       0.0007           -0.0012                       0.0018

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 whole\_case       DoC              9                         3                9           0.9227              0.9225                   0.0015       0.0007            0.0008                       0.0002

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128        AC            216                         3              216           0.9227              0.9233                   0.0181       0.0007            0.0008                       0.0013

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_D            216                         3              216           0.9227              0.8750                   0.1511       0.0007           -0.0179                       0.0189

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128   ALine\_S            216                         3              216           0.9227              0.8851                   0.1396       0.0007           -0.0020                       0.0027

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.25 window\_128       DoC            216                         3              216           0.9227              0.9225                   0.0181       0.0007            0.0008                       0.0013

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case        AC              9                         3                9           0.9227              0.9230                   0.0005       0.0007            0.0011                       0.0004

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_D              9                         3                9           0.9227              0.9813                   0.0586       0.0007           -0.0045                       0.0052

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case   ALine\_S              9                         3                9           0.9227              0.9809                   0.0582       0.0007           -0.0014                       0.0021

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 whole\_case       DoC              9                         3                9           0.9227              0.9222                   0.0016       0.0007            0.0011                       0.0004

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128        AC            216                         3              216           0.9227              0.9230                   0.0182       0.0007            0.0011                       0.0017

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_D            216                         3              216           0.9227              0.8793                   0.1454       0.0007           -0.0222                       0.0232

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128   ALine\_S            216                         3              216           0.9227              0.8916                   0.1319       0.0007           -0.0084                       0.0092

&#x20;    TONIoT feature\_space\_attack             source\_test          single\_target\_pgd     0.50 window\_128       DoC            216                         3              216           0.9227              0.9222                   0.0182       0.0007            0.0011                       0.0017

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case        AC              3                         3                3           0.5235              0.8894                   0.3659          NaN               NaN                          NaN

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case   ALine\_D              3                         3                3           0.5235              0.9442                   0.4207          NaN               NaN                          NaN

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case   ALine\_S              3                         3                3           0.5235              0.9478                   0.4243          NaN               NaN                          NaN

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN whole\_case       DoC              3                         3                3           0.5235              0.8887                   0.3651          NaN               NaN                          NaN

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN window\_128        AC            144                         3              144           0.5243              0.8892                   0.3650          NaN               NaN                          NaN

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN window\_128   ALine\_D            144                         3              144           0.5243              0.8061                   0.3644          NaN               NaN                          NaN

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN window\_128   ALine\_S            144                         3              144           0.5243              0.8358                   0.3691          NaN               NaN                          NaN

&#x20;    TONIoT        natural\_shift  natural\_heldout\_family                       none      NaN window\_128       DoC            144                         3              144           0.5243              0.8885                   0.3642          NaN               NaN                          NaN



REPAIR STATUS

&#x20;   dataset                       status  verified\_saved\_attacks  undefined\_estimates detail

&#x20;CICIoT2023 REPAIRED\_AND\_REPLAY\_VERIFIED                      30                    0       

CICIoMT2024 REPAIRED\_AND\_REPLAY\_VERIFIED                      30                    0       

&#x20;       CSE REPAIRED\_AND\_REPLAY\_VERIFIED                      30                    0       

&#x20;       NSL REPAIRED\_AND\_REPLAY\_VERIFIED                      30                    0       

&#x20;    TONIoT REPAIRED\_AND\_REPLAY\_VERIFIED                      30                    0   

8. CICIoT2023 bank=2201 MLP16 member\_seed=2201 trained/loaded

CICIoT2023 bank=2201 MLP16 member\_seed=2202 trained/loaded

CICIoT2023 bank=2201 MLP16 member\_seed=2203 trained/loaded

CICIoT2023 bank=2201 MLP32 member\_seed=2204 trained/loaded

CICIoT2023 bank=2201 MLP32 member\_seed=2205 trained/loaded

CICIoT2023 bank=2201 MLP32 member\_seed=2206 trained/loaded

CICIoT2023 bank=2201 MLP32\_16 member\_seed=2207 trained/loaded

CICIoT2023 bank=2201 MLP32\_16 member\_seed=2208 trained/loaded

CICIoT2023 bank=2201 MLP32\_16 member\_seed=2209 trained/loaded

CICIoT2023 bank=2201 clean\_source estimated

CICIoT2023 bank=2201 natural\_heldout\_family estimated

CICIoT2023 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2201 WHOLE-BANK REPETITION COMPLETE

CICIoT2023 bank=2301 MLP16 member\_seed=2301 trained/loaded

CICIoT2023 bank=2301 MLP16 member\_seed=2302 trained/loaded

CICIoT2023 bank=2301 MLP16 member\_seed=2303 trained/loaded

CICIoT2023 bank=2301 MLP32 member\_seed=2304 trained/loaded

CICIoT2023 bank=2301 MLP32 member\_seed=2305 trained/loaded

CICIoT2023 bank=2301 MLP32 member\_seed=2306 trained/loaded

CICIoT2023 bank=2301 MLP32\_16 member\_seed=2307 trained/loaded

CICIoT2023 bank=2301 MLP32\_16 member\_seed=2308 trained/loaded

CICIoT2023 bank=2301 MLP32\_16 member\_seed=2309 trained/loaded

CICIoT2023 bank=2301 clean\_source estimated

CICIoT2023 bank=2301 natural\_heldout\_family estimated

CICIoT2023 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2301 WHOLE-BANK REPETITION COMPLETE

CICIoT2023 bank=2401 MLP16 member\_seed=2401 trained/loaded

CICIoT2023 bank=2401 MLP16 member\_seed=2402 trained/loaded

CICIoT2023 bank=2401 MLP16 member\_seed=2403 trained/loaded

CICIoT2023 bank=2401 MLP32 member\_seed=2404 trained/loaded

CICIoT2023 bank=2401 MLP32 member\_seed=2405 trained/loaded

CICIoT2023 bank=2401 MLP32 member\_seed=2406 trained/loaded

CICIoT2023 bank=2401 MLP32\_16 member\_seed=2407 trained/loaded

CICIoT2023 bank=2401 MLP32\_16 member\_seed=2408 trained/loaded

CICIoT2023 bank=2401 MLP32\_16 member\_seed=2409 trained/loaded

CICIoT2023 bank=2401 clean\_source estimated

CICIoT2023 bank=2401 natural\_heldout\_family estimated

CICIoT2023 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2401 WHOLE-BANK REPETITION COMPLETE

CICIoT2023 bank=2501 MLP16 member\_seed=2501 trained/loaded

CICIoT2023 bank=2501 MLP16 member\_seed=2502 trained/loaded

CICIoT2023 bank=2501 MLP16 member\_seed=2503 trained/loaded

CICIoT2023 bank=2501 MLP32 member\_seed=2504 trained/loaded

CICIoT2023 bank=2501 MLP32 member\_seed=2505 trained/loaded

CICIoT2023 bank=2501 MLP32 member\_seed=2506 trained/loaded

CICIoT2023 bank=2501 MLP32\_16 member\_seed=2507 trained/loaded

CICIoT2023 bank=2501 MLP32\_16 member\_seed=2508 trained/loaded

CICIoT2023 bank=2501 MLP32\_16 member\_seed=2509 trained/loaded

CICIoT2023 bank=2501 clean\_source estimated

CICIoT2023 bank=2501 natural\_heldout\_family estimated

CICIoT2023 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2501 WHOLE-BANK REPETITION COMPLETE

CICIoT2023 bank=2601 MLP16 member\_seed=2601 trained/loaded

CICIoT2023 bank=2601 MLP16 member\_seed=2602 trained/loaded

CICIoT2023 bank=2601 MLP16 member\_seed=2603 trained/loaded

CICIoT2023 bank=2601 MLP32 member\_seed=2604 trained/loaded

CICIoT2023 bank=2601 MLP32 member\_seed=2605 trained/loaded

CICIoT2023 bank=2601 MLP32 member\_seed=2606 trained/loaded

CICIoT2023 bank=2601 MLP32\_16 member\_seed=2607 trained/loaded

CICIoT2023 bank=2601 MLP32\_16 member\_seed=2608 trained/loaded

CICIoT2023 bank=2601 MLP32\_16 member\_seed=2609 trained/loaded

CICIoT2023 bank=2601 clean\_source estimated

CICIoT2023 bank=2601 natural\_heldout\_family estimated

CICIoT2023 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoT2023 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoT2023 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoT2023 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoT2023 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoT2023 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoT2023 bank=2601 WHOLE-BANK REPETITION COMPLETE

CICIoMT2024 bank=2201 MLP16 member\_seed=2201 trained/loaded

CICIoMT2024 bank=2201 MLP16 member\_seed=2202 trained/loaded

CICIoMT2024 bank=2201 MLP16 member\_seed=2203 trained/loaded

CICIoMT2024 bank=2201 MLP32 member\_seed=2204 trained/loaded

CICIoMT2024 bank=2201 MLP32 member\_seed=2205 trained/loaded

CICIoMT2024 bank=2201 MLP32 member\_seed=2206 trained/loaded

CICIoMT2024 bank=2201 MLP32\_16 member\_seed=2207 trained/loaded

CICIoMT2024 bank=2201 MLP32\_16 member\_seed=2208 trained/loaded

CICIoMT2024 bank=2201 MLP32\_16 member\_seed=2209 trained/loaded

CICIoMT2024 bank=2201 clean\_source estimated

CICIoMT2024 bank=2201 natural\_heldout\_family estimated

CICIoMT2024 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2201 WHOLE-BANK REPETITION COMPLETE

CICIoMT2024 bank=2301 MLP16 member\_seed=2301 trained/loaded

CICIoMT2024 bank=2301 MLP16 member\_seed=2302 trained/loaded

CICIoMT2024 bank=2301 MLP16 member\_seed=2303 trained/loaded

CICIoMT2024 bank=2301 MLP32 member\_seed=2304 trained/loaded

CICIoMT2024 bank=2301 MLP32 member\_seed=2305 trained/loaded

CICIoMT2024 bank=2301 MLP32 member\_seed=2306 trained/loaded

CICIoMT2024 bank=2301 MLP32\_16 member\_seed=2307 trained/loaded

CICIoMT2024 bank=2301 MLP32\_16 member\_seed=2308 trained/loaded

CICIoMT2024 bank=2301 MLP32\_16 member\_seed=2309 trained/loaded

CICIoMT2024 bank=2301 clean\_source estimated

CICIoMT2024 bank=2301 natural\_heldout\_family estimated

CICIoMT2024 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2301 WHOLE-BANK REPETITION COMPLETE

CICIoMT2024 bank=2401 MLP16 member\_seed=2401 trained/loaded

CICIoMT2024 bank=2401 MLP16 member\_seed=2402 trained/loaded

CICIoMT2024 bank=2401 MLP16 member\_seed=2403 trained/loaded

CICIoMT2024 bank=2401 MLP32 member\_seed=2404 trained/loaded

CICIoMT2024 bank=2401 MLP32 member\_seed=2405 trained/loaded

CICIoMT2024 bank=2401 MLP32 member\_seed=2406 trained/loaded

CICIoMT2024 bank=2401 MLP32\_16 member\_seed=2407 trained/loaded

CICIoMT2024 bank=2401 MLP32\_16 member\_seed=2408 trained/loaded

CICIoMT2024 bank=2401 MLP32\_16 member\_seed=2409 trained/loaded

CICIoMT2024 bank=2401 clean\_source estimated

CICIoMT2024 bank=2401 natural\_heldout\_family estimated

CICIoMT2024 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2401 WHOLE-BANK REPETITION COMPLETE

CICIoMT2024 bank=2501 MLP16 member\_seed=2501 trained/loaded

CICIoMT2024 bank=2501 MLP16 member\_seed=2502 trained/loaded

CICIoMT2024 bank=2501 MLP16 member\_seed=2503 trained/loaded

CICIoMT2024 bank=2501 MLP32 member\_seed=2504 trained/loaded

CICIoMT2024 bank=2501 MLP32 member\_seed=2505 trained/loaded

CICIoMT2024 bank=2501 MLP32 member\_seed=2506 trained/loaded

CICIoMT2024 bank=2501 MLP32\_16 member\_seed=2507 trained/loaded

CICIoMT2024 bank=2501 MLP32\_16 member\_seed=2508 trained/loaded

CICIoMT2024 bank=2501 MLP32\_16 member\_seed=2509 trained/loaded

CICIoMT2024 bank=2501 clean\_source estimated

CICIoMT2024 bank=2501 natural\_heldout\_family estimated

CICIoMT2024 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2501 WHOLE-BANK REPETITION COMPLETE

CICIoMT2024 bank=2601 MLP16 member\_seed=2601 trained/loaded

CICIoMT2024 bank=2601 MLP16 member\_seed=2602 trained/loaded

CICIoMT2024 bank=2601 MLP16 member\_seed=2603 trained/loaded

CICIoMT2024 bank=2601 MLP32 member\_seed=2604 trained/loaded

CICIoMT2024 bank=2601 MLP32 member\_seed=2605 trained/loaded

CICIoMT2024 bank=2601 MLP32 member\_seed=2606 trained/loaded

CICIoMT2024 bank=2601 MLP32\_16 member\_seed=2607 trained/loaded

CICIoMT2024 bank=2601 MLP32\_16 member\_seed=2608 trained/loaded

CICIoMT2024 bank=2601 MLP32\_16 member\_seed=2609 trained/loaded

CICIoMT2024 bank=2601 clean\_source estimated

CICIoMT2024 bank=2601 natural\_heldout\_family estimated

CICIoMT2024 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CICIoMT2024 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CICIoMT2024 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CICIoMT2024 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CICIoMT2024 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CICIoMT2024 bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CICIoMT2024 bank=2601 WHOLE-BANK REPETITION COMPLETE

CSE bank=2201 MLP16 member\_seed=2201 trained/loaded

CSE bank=2201 MLP16 member\_seed=2202 trained/loaded

CSE bank=2201 MLP16 member\_seed=2203 trained/loaded

CSE bank=2201 MLP32 member\_seed=2204 trained/loaded

CSE bank=2201 MLP32 member\_seed=2205 trained/loaded

CSE bank=2201 MLP32 member\_seed=2206 trained/loaded

CSE bank=2201 MLP32\_16 member\_seed=2207 trained/loaded

CSE bank=2201 MLP32\_16 member\_seed=2208 trained/loaded

CSE bank=2201 MLP32\_16 member\_seed=2209 trained/loaded

CSE bank=2201 clean\_source estimated

CSE bank=2201 natural\_day\_Botnet estimated

CSE bank=2201 natural\_day\_Bruteforce estimated

CSE bank=2201 natural\_day\_DDoS2 estimated

CSE bank=2201 natural\_day\_DoS1 estimated

CSE bank=2201 natural\_day\_DoS2 estimated

CSE bank=2201 natural\_day\_Infil1 estimated

CSE bank=2201 natural\_day\_Infil2 estimated

CSE bank=2201 natural\_day\_Web1 estimated

CSE bank=2201 natural\_day\_Web2 estimated

CSE bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CSE bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CSE bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CSE bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CSE bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CSE bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CSE bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CSE bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CSE bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CSE bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CSE bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CSE bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CSE bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CSE bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CSE bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CSE bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CSE bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CSE bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CSE bank=2201 WHOLE-BANK REPETITION COMPLETE

CSE bank=2301 MLP16 member\_seed=2301 trained/loaded

CSE bank=2301 MLP16 member\_seed=2302 trained/loaded

CSE bank=2301 MLP16 member\_seed=2303 trained/loaded

CSE bank=2301 MLP32 member\_seed=2304 trained/loaded

CSE bank=2301 MLP32 member\_seed=2305 trained/loaded

CSE bank=2301 MLP32 member\_seed=2306 trained/loaded

CSE bank=2301 MLP32\_16 member\_seed=2307 trained/loaded

CSE bank=2301 MLP32\_16 member\_seed=2308 trained/loaded

CSE bank=2301 MLP32\_16 member\_seed=2309 trained/loaded

CSE bank=2301 clean\_source estimated

CSE bank=2301 natural\_day\_Botnet estimated

CSE bank=2301 natural\_day\_Bruteforce estimated

CSE bank=2301 natural\_day\_DDoS2 estimated

CSE bank=2301 natural\_day\_DoS1 estimated

CSE bank=2301 natural\_day\_DoS2 estimated

CSE bank=2301 natural\_day\_Infil1 estimated

CSE bank=2301 natural\_day\_Infil2 estimated

CSE bank=2301 natural\_day\_Web1 estimated

CSE bank=2301 natural\_day\_Web2 estimated

CSE bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CSE bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CSE bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CSE bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CSE bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CSE bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CSE bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CSE bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CSE bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CSE bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CSE bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CSE bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CSE bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CSE bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CSE bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CSE bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CSE bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CSE bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CSE bank=2301 WHOLE-BANK REPETITION COMPLETE

CSE bank=2401 MLP16 member\_seed=2401 trained/loaded

CSE bank=2401 MLP16 member\_seed=2402 trained/loaded

CSE bank=2401 MLP16 member\_seed=2403 trained/loaded

CSE bank=2401 MLP32 member\_seed=2404 trained/loaded

CSE bank=2401 MLP32 member\_seed=2405 trained/loaded

CSE bank=2401 MLP32 member\_seed=2406 trained/loaded

CSE bank=2401 MLP32\_16 member\_seed=2407 trained/loaded

CSE bank=2401 MLP32\_16 member\_seed=2408 trained/loaded

CSE bank=2401 MLP32\_16 member\_seed=2409 trained/loaded

CSE bank=2401 clean\_source estimated

CSE bank=2401 natural\_day\_Botnet estimated

CSE bank=2401 natural\_day\_Bruteforce estimated

CSE bank=2401 natural\_day\_DDoS2 estimated

CSE bank=2401 natural\_day\_DoS1 estimated

CSE bank=2401 natural\_day\_DoS2 estimated

CSE bank=2401 natural\_day\_Infil1 estimated

CSE bank=2401 natural\_day\_Infil2 estimated

CSE bank=2401 natural\_day\_Web1 estimated

CSE bank=2401 natural\_day\_Web2 estimated

CSE bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CSE bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CSE bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CSE bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CSE bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CSE bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CSE bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CSE bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CSE bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CSE bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CSE bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CSE bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CSE bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CSE bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CSE bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CSE bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CSE bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CSE bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CSE bank=2401 WHOLE-BANK REPETITION COMPLETE

CSE bank=2501 MLP16 member\_seed=2501 trained/loaded

CSE bank=2501 MLP16 member\_seed=2502 trained/loaded

CSE bank=2501 MLP16 member\_seed=2503 trained/loaded

CSE bank=2501 MLP32 member\_seed=2504 trained/loaded

CSE bank=2501 MLP32 member\_seed=2505 trained/loaded

CSE bank=2501 MLP32 member\_seed=2506 trained/loaded

CSE bank=2501 MLP32\_16 member\_seed=2507 trained/loaded

CSE bank=2501 MLP32\_16 member\_seed=2508 trained/loaded

CSE bank=2501 MLP32\_16 member\_seed=2509 trained/loaded

CSE bank=2501 clean\_source estimated

CSE bank=2501 natural\_day\_Botnet estimated

CSE bank=2501 natural\_day\_Bruteforce estimated

CSE bank=2501 natural\_day\_DDoS2 estimated

CSE bank=2501 natural\_day\_DoS1 estimated

CSE bank=2501 natural\_day\_DoS2 estimated

CSE bank=2501 natural\_day\_Infil1 estimated

CSE bank=2501 natural\_day\_Infil2 estimated

CSE bank=2501 natural\_day\_Web1 estimated

CSE bank=2501 natural\_day\_Web2 estimated

CSE bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CSE bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CSE bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CSE bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CSE bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CSE bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CSE bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CSE bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CSE bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CSE bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CSE bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CSE bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CSE bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CSE bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CSE bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CSE bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CSE bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CSE bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CSE bank=2501 WHOLE-BANK REPETITION COMPLETE

CSE bank=2601 MLP16 member\_seed=2601 trained/loaded

CSE bank=2601 MLP16 member\_seed=2602 trained/loaded

CSE bank=2601 MLP16 member\_seed=2603 trained/loaded

CSE bank=2601 MLP32 member\_seed=2604 trained/loaded

CSE bank=2601 MLP32 member\_seed=2605 trained/loaded

CSE bank=2601 MLP32 member\_seed=2606 trained/loaded

CSE bank=2601 MLP32\_16 member\_seed=2607 trained/loaded

CSE bank=2601 MLP32\_16 member\_seed=2608 trained/loaded

CSE bank=2601 MLP32\_16 member\_seed=2609 trained/loaded

CSE bank=2601 clean\_source estimated

CSE bank=2601 natural\_day\_Botnet estimated

CSE bank=2601 natural\_day\_Bruteforce estimated

CSE bank=2601 natural\_day\_DDoS2 estimated

CSE bank=2601 natural\_day\_DoS1 estimated

CSE bank=2601 natural\_day\_DoS2 estimated

CSE bank=2601 natural\_day\_Infil1 estimated

CSE bank=2601 natural\_day\_Infil2 estimated

CSE bank=2601 natural\_day\_Web1 estimated

CSE bank=2601 natural\_day\_Web2 estimated

CSE bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

CSE bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

CSE bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

CSE bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

CSE bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

CSE bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

CSE bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

CSE bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

CSE bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

CSE bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

CSE bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

CSE bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

CSE bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

CSE bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

CSE bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

CSE bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

CSE bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

CSE bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

CSE bank=2601 WHOLE-BANK REPETITION COMPLETE

NSL bank=2201 MLP16 member\_seed=2201 trained/loaded

NSL bank=2201 MLP16 member\_seed=2202 trained/loaded

NSL bank=2201 MLP16 member\_seed=2203 trained/loaded

NSL bank=2201 MLP32 member\_seed=2204 trained/loaded

NSL bank=2201 MLP32 member\_seed=2205 trained/loaded

NSL bank=2201 MLP32 member\_seed=2206 trained/loaded

NSL bank=2201 MLP32\_16 member\_seed=2207 trained/loaded

NSL bank=2201 MLP32\_16 member\_seed=2208 trained/loaded

NSL bank=2201 MLP32\_16 member\_seed=2209 trained/loaded

NSL bank=2201 clean\_source estimated

NSL bank=2201 natural\_official\_test estimated

NSL bank=2201 natural\_official\_test21 estimated

NSL bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

NSL bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

NSL bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

NSL bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

NSL bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

NSL bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

NSL bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

NSL bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

NSL bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

NSL bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

NSL bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

NSL bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

NSL bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

NSL bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

NSL bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

NSL bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

NSL bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

NSL bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

NSL bank=2201 WHOLE-BANK REPETITION COMPLETE

NSL bank=2301 MLP16 member\_seed=2301 trained/loaded

NSL bank=2301 MLP16 member\_seed=2302 trained/loaded

NSL bank=2301 MLP16 member\_seed=2303 trained/loaded

NSL bank=2301 MLP32 member\_seed=2304 trained/loaded

NSL bank=2301 MLP32 member\_seed=2305 trained/loaded

NSL bank=2301 MLP32 member\_seed=2306 trained/loaded

NSL bank=2301 MLP32\_16 member\_seed=2307 trained/loaded

NSL bank=2301 MLP32\_16 member\_seed=2308 trained/loaded

NSL bank=2301 MLP32\_16 member\_seed=2309 trained/loaded

NSL bank=2301 clean\_source estimated

NSL bank=2301 natural\_official\_test estimated

NSL bank=2301 natural\_official\_test21 estimated

NSL bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

NSL bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

NSL bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

NSL bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

NSL bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

NSL bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

NSL bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

NSL bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

NSL bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

NSL bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

NSL bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

NSL bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

NSL bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

NSL bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

NSL bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

NSL bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

NSL bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

NSL bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

NSL bank=2301 WHOLE-BANK REPETITION COMPLETE

NSL bank=2401 MLP16 member\_seed=2401 trained/loaded

NSL bank=2401 MLP16 member\_seed=2402 trained/loaded

NSL bank=2401 MLP16 member\_seed=2403 trained/loaded

NSL bank=2401 MLP32 member\_seed=2404 trained/loaded

NSL bank=2401 MLP32 member\_seed=2405 trained/loaded

NSL bank=2401 MLP32 member\_seed=2406 trained/loaded

NSL bank=2401 MLP32\_16 member\_seed=2407 trained/loaded

NSL bank=2401 MLP32\_16 member\_seed=2408 trained/loaded

NSL bank=2401 MLP32\_16 member\_seed=2409 trained/loaded

NSL bank=2401 clean\_source estimated

NSL bank=2401 natural\_official\_test estimated

NSL bank=2401 natural\_official\_test21 estimated

NSL bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

NSL bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

NSL bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

NSL bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

NSL bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

NSL bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

NSL bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

NSL bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

NSL bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

NSL bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

NSL bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

NSL bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

NSL bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

NSL bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

NSL bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

NSL bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

NSL bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

NSL bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

NSL bank=2401 WHOLE-BANK REPETITION COMPLETE

NSL bank=2501 MLP16 member\_seed=2501 trained/loaded

NSL bank=2501 MLP16 member\_seed=2502 trained/loaded

NSL bank=2501 MLP16 member\_seed=2503 trained/loaded

NSL bank=2501 MLP32 member\_seed=2504 trained/loaded

NSL bank=2501 MLP32 member\_seed=2505 trained/loaded

NSL bank=2501 MLP32 member\_seed=2506 trained/loaded

NSL bank=2501 MLP32\_16 member\_seed=2507 trained/loaded

NSL bank=2501 MLP32\_16 member\_seed=2508 trained/loaded

NSL bank=2501 MLP32\_16 member\_seed=2509 trained/loaded

NSL bank=2501 clean\_source estimated

NSL bank=2501 natural\_official\_test estimated

NSL bank=2501 natural\_official\_test21 estimated

NSL bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

NSL bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

NSL bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

NSL bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

NSL bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

NSL bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

NSL bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

NSL bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

NSL bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

NSL bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

NSL bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

NSL bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

NSL bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

NSL bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

NSL bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

NSL bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

NSL bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

NSL bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

NSL bank=2501 WHOLE-BANK REPETITION COMPLETE

NSL bank=2601 MLP16 member\_seed=2601 trained/loaded

NSL bank=2601 MLP16 member\_seed=2602 trained/loaded

NSL bank=2601 MLP16 member\_seed=2603 trained/loaded

NSL bank=2601 MLP32 member\_seed=2604 trained/loaded

NSL bank=2601 MLP32 member\_seed=2605 trained/loaded

NSL bank=2601 MLP32 member\_seed=2606 trained/loaded

NSL bank=2601 MLP32\_16 member\_seed=2607 trained/loaded

NSL bank=2601 MLP32\_16 member\_seed=2608 trained/loaded

NSL bank=2601 MLP32\_16 member\_seed=2609 trained/loaded

NSL bank=2601 clean\_source estimated

NSL bank=2601 natural\_official\_test estimated

NSL bank=2601 natural\_official\_test21 estimated

NSL bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

NSL bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

NSL bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

NSL bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

NSL bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

NSL bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

NSL bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

NSL bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

NSL bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

NSL bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

NSL bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

NSL bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

NSL bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

NSL bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

NSL bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

NSL bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

NSL bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

NSL bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

NSL bank=2601 WHOLE-BANK REPETITION COMPLETE

TONIoT bank=2201 MLP16 member\_seed=2201 trained/loaded

TONIoT bank=2201 MLP16 member\_seed=2202 trained/loaded

TONIoT bank=2201 MLP16 member\_seed=2203 trained/loaded

TONIoT bank=2201 MLP32 member\_seed=2204 trained/loaded

TONIoT bank=2201 MLP32 member\_seed=2205 trained/loaded

TONIoT bank=2201 MLP32 member\_seed=2206 trained/loaded

TONIoT bank=2201 MLP32\_16 member\_seed=2207 trained/loaded

TONIoT bank=2201 MLP32\_16 member\_seed=2208 trained/loaded

TONIoT bank=2201 MLP32\_16 member\_seed=2209 trained/loaded

TONIoT bank=2201 clean\_source estimated

TONIoT bank=2201 natural\_heldout\_family estimated

TONIoT bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2201 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2201 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2201 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2201 WHOLE-BANK REPETITION COMPLETE

TONIoT bank=2301 MLP16 member\_seed=2301 trained/loaded

TONIoT bank=2301 MLP16 member\_seed=2302 trained/loaded

TONIoT bank=2301 MLP16 member\_seed=2303 trained/loaded

TONIoT bank=2301 MLP32 member\_seed=2304 trained/loaded

TONIoT bank=2301 MLP32 member\_seed=2305 trained/loaded

TONIoT bank=2301 MLP32 member\_seed=2306 trained/loaded

TONIoT bank=2301 MLP32\_16 member\_seed=2307 trained/loaded

TONIoT bank=2301 MLP32\_16 member\_seed=2308 trained/loaded

TONIoT bank=2301 MLP32\_16 member\_seed=2309 trained/loaded

TONIoT bank=2301 clean\_source estimated

TONIoT bank=2301 natural\_heldout\_family estimated

TONIoT bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2301 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2301 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2301 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2301 WHOLE-BANK REPETITION COMPLETE

TONIoT bank=2401 MLP16 member\_seed=2401 trained/loaded

TONIoT bank=2401 MLP16 member\_seed=2402 trained/loaded

TONIoT bank=2401 MLP16 member\_seed=2403 trained/loaded

TONIoT bank=2401 MLP32 member\_seed=2404 trained/loaded

TONIoT bank=2401 MLP32 member\_seed=2405 trained/loaded

TONIoT bank=2401 MLP32 member\_seed=2406 trained/loaded

TONIoT bank=2401 MLP32\_16 member\_seed=2407 trained/loaded

TONIoT bank=2401 MLP32\_16 member\_seed=2408 trained/loaded

TONIoT bank=2401 MLP32\_16 member\_seed=2409 trained/loaded

TONIoT bank=2401 clean\_source estimated

TONIoT bank=2401 natural\_heldout\_family estimated

TONIoT bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2401 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2401 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2401 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2401 WHOLE-BANK REPETITION COMPLETE

TONIoT bank=2501 MLP16 member\_seed=2501 trained/loaded

TONIoT bank=2501 MLP16 member\_seed=2502 trained/loaded

TONIoT bank=2501 MLP16 member\_seed=2503 trained/loaded

TONIoT bank=2501 MLP32 member\_seed=2504 trained/loaded

TONIoT bank=2501 MLP32 member\_seed=2505 trained/loaded

TONIoT bank=2501 MLP32 member\_seed=2506 trained/loaded

TONIoT bank=2501 MLP32\_16 member\_seed=2507 trained/loaded

TONIoT bank=2501 MLP32\_16 member\_seed=2508 trained/loaded

TONIoT bank=2501 MLP32\_16 member\_seed=2509 trained/loaded

TONIoT bank=2501 clean\_source estimated

TONIoT bank=2501 natural\_heldout\_family estimated

TONIoT bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2501 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2501 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2501 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2501 WHOLE-BANK REPETITION COMPLETE

TONIoT bank=2601 MLP16 member\_seed=2601 trained/loaded

TONIoT bank=2601 MLP16 member\_seed=2602 trained/loaded

TONIoT bank=2601 MLP16 member\_seed=2603 trained/loaded

TONIoT bank=2601 MLP32 member\_seed=2604 trained/loaded

TONIoT bank=2601 MLP32 member\_seed=2605 trained/loaded

TONIoT bank=2601 MLP32 member\_seed=2606 trained/loaded

TONIoT bank=2601 MLP32\_16 member\_seed=2607 trained/loaded

TONIoT bank=2601 MLP32\_16 member\_seed=2608 trained/loaded

TONIoT bank=2601 MLP32\_16 member\_seed=2609 trained/loaded

TONIoT bank=2601 clean\_source estimated

TONIoT bank=2601 natural\_heldout\_family estimated

TONIoT bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2601 coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2601 genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 estimated

TONIoT bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 estimated

TONIoT bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 estimated

TONIoT bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 estimated

TONIoT bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 estimated

TONIoT bank=2601 single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 estimated

TONIoT bank=2601 WHOLE-BANK REPETITION COMPLETE



PAIRED CONDITIONAL-BANK INTERVALS

&#x20;   dataset              attack\_family  epsilon                                              comparison  independent\_whole\_bank\_runs  mean\_error\_difference  conditional\_bank\_bootstrap\_p025  conditional\_bank\_bootstrap\_p975                             interpretation                                                   interval\_scope  few\_bank\_units\_warning  confirmatory\_test

CICIoMT2024   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0007                          -0.0009                          -0.0006 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0019                          -0.0023                          -0.0015 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0013                          -0.0018                          -0.0008 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0048                          -0.0065                          -0.0036 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024 genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0010                          -0.0011                          -0.0008 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024 genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0034                          -0.0038                          -0.0030 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024 genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0013                          -0.0016                          -0.0010 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024 genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0051                          -0.0054                          -0.0047 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024          single\_target\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0007                          -0.0010                          -0.0004 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024          single\_target\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0025                          -0.0032                          -0.0020 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024          single\_target\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0007                          -0.0010                          -0.0003 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

CICIoMT2024          single\_target\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0040                          -0.0048                          -0.0028 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0010                          -0.0016                          -0.0003 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0116                          -0.0132                          -0.0100 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0011                          -0.0020                          -0.0000 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0123                          -0.0132                          -0.0112 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023 genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0013                          -0.0017                          -0.0006 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023 genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0098                          -0.0103                          -0.0094 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023 genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0013                          -0.0021                          -0.0003 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023 genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0108                          -0.0118                          -0.0100 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023          single\_target\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                 0.0005                          -0.0001                           0.0011 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023          single\_target\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0078                          -0.0096                          -0.0052 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023          single\_target\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                 0.0006                          -0.0000                           0.0012 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;CICIoT2023          single\_target\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0089                          -0.0108                          -0.0070 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0016                          -0.0041                           0.0005 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0004                          -0.0027                           0.0012 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0021                          -0.0040                          -0.0003 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0115                          -0.0228                          -0.0002 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0026                          -0.0050                          -0.0003 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0006                          -0.0033                           0.0011 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0071                          -0.0103                          -0.0042 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0206                          -0.0363                          -0.0066 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE          single\_target\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                 0.0013                           0.0004                           0.0023 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE          single\_target\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0150                          -0.0286                          -0.0016 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE          single\_target\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                 0.0037                           0.0011                           0.0065 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       CSE          single\_target\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0012                          -0.0054                           0.0031 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0000                          -0.0004                           0.0003 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0004                          -0.0009                           0.0001 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                 0.0007                           0.0004                           0.0011 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                 0.0001                          -0.0006                           0.0008 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0002                          -0.0003                           0.0000 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0004                          -0.0007                          -0.0001 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0002                          -0.0003                           0.0000 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0008                          -0.0011                          -0.0004 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL          single\_target\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                 0.0003                          -0.0001                           0.0006 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL          single\_target\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                 0.0000                          -0.0003                           0.0004 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL          single\_target\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                 0.0007                           0.0005                           0.0010 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;       NSL          single\_target\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0001                          -0.0009                           0.0007 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0067                          -0.0117                          -0.0019 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT   coordinated\_ensemble\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0221                          -0.0310                          -0.0144 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0070                          -0.0123                          -0.0018 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT   coordinated\_ensemble\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0224                          -0.0309                          -0.0147 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0072                          -0.0126                          -0.0023 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT genuine\_surrogate\_transfer     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0226                          -0.0318                          -0.0149 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0124                          -0.0234                          -0.0037 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT genuine\_surrogate\_transfer     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0276                          -0.0390                          -0.0162 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT          single\_target\_pgd     0.25 DoC differential error minus ALine\_S differential error                            5                -0.0066                          -0.0115                          -0.0016 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT          single\_target\_pgd     0.25 DoC differential error minus ALine\_D differential error                            5                -0.0222                          -0.0322                          -0.0140 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT          single\_target\_pgd     0.50 DoC differential error minus ALine\_S differential error                            5                -0.0070                          -0.0120                          -0.0021 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False

&#x20;    TONIoT          single\_target\_pgd     0.50 DoC differential error minus ALine\_D differential error                            5                -0.0239                          -0.0334                          -0.0152 Positive favors ALine; negative favors DoC Conditional on fixed corpus, fixed target and fixed attack cases                       1              False



DATASET STATUS

&#x20;   dataset                              status detail

&#x20;CICIoT2023 FIVE\_FRESH\_ESTIMATOR\_BANKS\_COMPUTED       

CICIoMT2024 FIVE\_FRESH\_ESTIMATOR\_BANKS\_COMPUTED       

&#x20;       CSE FIVE\_FRESH\_ESTIMATOR\_BANKS\_COMPUTED       

&#x20;       NSL FIVE\_FRESH\_ESTIMATOR\_BANKS\_COMPUTED       

&#x20;    TONIoT FIVE\_FRESH\_ESTIMATOR\_BANKS\_COMPUTED

9. 

CICIoT2023 CICIoT2023/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 CICIoT2023/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoT2023 GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 CICIoMT2024/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CICIoMT2024 GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE CSE/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

CSE GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL NSL/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

NSL GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/coordinated\_ensemble\_pgd\_all\_nine\_neural\_models\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/genuine\_surrogate\_transfer\_independent\_half\_train\_surrogate\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_901\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_902\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.25\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1101 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1102 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT TONIoT/single\_target\_pgd\_MLP32\_16\_seed\_903\_eps\_0.50\_seed\_1103 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT logistic\_existing\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT MLP\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_10/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_11/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.25\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.25\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.25\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.50\_search\_10\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.50\_search\_11\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_0.25 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED

TONIoT GBDT\_seed\_12/eps\_0.50\_search\_12\_lambda\_1.00 ALGEBRAIC SCREEN + RESTORATION EFFECT COMPUTED



DAMAGE RETENTION AFTER OFFLINE RESTORATION

&#x20;   dataset              attack\_kind            target\_model  epsilon  recorded\_cases  new\_violation\_fraction\_of\_modified  clean\_accuracy  damage\_before  damage\_after  retention\_ratio

CICIoMT2024 per\_record\_neural\_target       MLP32\_16\_seed\_901     0.25               9                              0.0000          0.9643         0.0004        0.0004           1.0000

CICIoMT2024 per\_record\_neural\_target       MLP32\_16\_seed\_901     0.50               9                              0.0000          0.9643         0.0010        0.0010           1.0000

CICIoMT2024 per\_record\_neural\_target       MLP32\_16\_seed\_902     0.25               9                              0.0000          0.9657         0.0011        0.0011           1.0000

CICIoMT2024 per\_record\_neural\_target       MLP32\_16\_seed\_902     0.50               9                              0.0000          0.9657         0.0012        0.0012           1.0000

CICIoMT2024 per\_record\_neural\_target       MLP32\_16\_seed\_903     0.25               9                              0.0000          0.9663         0.0007        0.0007           1.0000

CICIoMT2024 per\_record\_neural\_target       MLP32\_16\_seed\_903     0.50               9                              0.0000          0.9663         0.0014        0.0014           1.0000

CICIoMT2024   shared\_logistic\_target frozen\_logistic\_primary     0.25              42                              0.0000          0.9553         0.0011        0.0011           1.0000

CICIoMT2024   shared\_logistic\_target frozen\_logistic\_primary     0.50              42                              0.0000          0.9553         0.0053        0.0053           1.0000

&#x20;CICIoT2023 per\_record\_neural\_target       MLP32\_16\_seed\_901     0.25               9                              0.0924          0.9131         0.0155        0.0144           0.9174

&#x20;CICIoT2023 per\_record\_neural\_target       MLP32\_16\_seed\_901     0.50               9                              0.1215          0.9131         0.0228        0.0213           0.9723

&#x20;CICIoT2023 per\_record\_neural\_target       MLP32\_16\_seed\_902     0.25               9                              0.2230          0.9068         0.0184        0.0140           0.7737

&#x20;CICIoT2023 per\_record\_neural\_target       MLP32\_16\_seed\_902     0.50               9                              0.2754          0.9068         0.0290        0.0206           0.7209

&#x20;CICIoT2023 per\_record\_neural\_target       MLP32\_16\_seed\_903     0.25               9                              0.2643          0.9113         0.0179        0.0124           0.7209

&#x20;CICIoT2023 per\_record\_neural\_target       MLP32\_16\_seed\_903     0.50               9                              0.3156          0.9113         0.0263        0.0178           0.7074

&#x20;CICIoT2023   shared\_logistic\_target frozen\_logistic\_primary     0.25              42                              0.0115          0.8839         0.0619        0.0619           1.0000

&#x20;CICIoT2023   shared\_logistic\_target frozen\_logistic\_primary     0.50              42                              0.0559          0.8839         0.0794        0.0789           0.9941

&#x20;       CSE per\_record\_neural\_target       MLP32\_16\_seed\_901     0.25               9                              0.2035          0.9879         0.0026        0.0002           0.4000

&#x20;       CSE per\_record\_neural\_target       MLP32\_16\_seed\_901     0.50               9                              0.2102          0.9879         0.0159        0.0036           0.3333

&#x20;       CSE per\_record\_neural\_target       MLP32\_16\_seed\_902     0.25               9                              0.1560          0.9901         0.0157        0.0115           0.6667

&#x20;       CSE per\_record\_neural\_target       MLP32\_16\_seed\_902     0.50               9                              0.1578          0.9901         0.0357        0.0241           0.6667

&#x20;       CSE per\_record\_neural\_target       MLP32\_16\_seed\_903     0.25               9                              0.2917          0.9915         0.0189        0.0072           0.3723

&#x20;       CSE per\_record\_neural\_target       MLP32\_16\_seed\_903     0.50               9                              0.2648          0.9915         0.0357        0.0241           0.6667

&#x20;       CSE   shared\_logistic\_target frozen\_logistic\_primary     0.25              42                              1.0000          0.9808         0.0000        0.0000              NaN

&#x20;       CSE   shared\_logistic\_target frozen\_logistic\_primary     0.50              42                              0.6500          0.9808         0.0000        0.0000              NaN

&#x20;       NSL per\_record\_neural\_target       MLP32\_16\_seed\_901     0.25               9                              0.0000          0.9503         0.0000        0.0000              NaN

&#x20;       NSL per\_record\_neural\_target       MLP32\_16\_seed\_901     0.50               9                              0.0000          0.9503        -0.0003       -0.0003              NaN

&#x20;       NSL per\_record\_neural\_target       MLP32\_16\_seed\_902     0.25               9                              0.0000          0.9538         0.0006        0.0006           1.0000

&#x20;       NSL per\_record\_neural\_target       MLP32\_16\_seed\_902     0.50               9                              0.0000          0.9538         0.0007        0.0007           1.0000

&#x20;       NSL per\_record\_neural\_target       MLP32\_16\_seed\_903     0.25               9                              0.0000          0.9510         0.0003        0.0003           1.0000

&#x20;       NSL per\_record\_neural\_target       MLP32\_16\_seed\_903     0.50               9                              0.0000          0.9510         0.0016        0.0016           1.0000

&#x20;       NSL   shared\_logistic\_target frozen\_logistic\_primary     0.25              42                              0.0000          0.9403         0.0000        0.0000              NaN

&#x20;       NSL   shared\_logistic\_target frozen\_logistic\_primary     0.50              42                              0.0000          0.9403         0.0000        0.0000              NaN

&#x20;    TONIoT per\_record\_neural\_target       MLP32\_16\_seed\_901     0.25               9                              0.0000          0.9229         0.0010        0.0010           1.0000

&#x20;    TONIoT per\_record\_neural\_target       MLP32\_16\_seed\_901     0.50               9                              0.0000          0.9229         0.0010        0.0010           1.0000

&#x20;    TONIoT per\_record\_neural\_target       MLP32\_16\_seed\_902     0.25               9                              0.0000          0.9238         0.0009        0.0009           1.0000

&#x20;    TONIoT per\_record\_neural\_target       MLP32\_16\_seed\_902     0.50               9                              0.0000          0.9238         0.0009        0.0009           1.0000

&#x20;    TONIoT per\_record\_neural\_target       MLP32\_16\_seed\_903     0.25               9                              0.0000          0.9235        -0.0001       -0.0001              NaN

&#x20;    TONIoT per\_record\_neural\_target       MLP32\_16\_seed\_903     0.50               9                              0.0000          0.9235        -0.0005       -0.0005              NaN

&#x20;    TONIoT   shared\_logistic\_target frozen\_logistic\_primary     0.25              42                              0.0000          0.8249         0.0011        0.0011           1.0000

&#x20;    TONIoT   shared\_logistic\_target frozen\_logistic\_primary     0.50              42                              0.0000          0.8249         0.0011        0.0011           1.0000



DATASET STATUS

&#x20;   dataset                                    status  saved\_cases packet\_validity\_status detail

&#x20;CICIoT2023 CANDIDATE\_SCREEN\_AND\_RESTORATION\_COMPUTED          114        NOT\_ESTABLISHED       

CICIoMT2024 CANDIDATE\_SCREEN\_AND\_RESTORATION\_COMPUTED          114        NOT\_ESTABLISHED       

&#x20;       CSE CANDIDATE\_SCREEN\_AND\_RESTORATION\_COMPUTED          114        NOT\_ESTABLISHED       

&#x20;       NSL CANDIDATE\_SCREEN\_AND\_RESTORATION\_COMPUTED          114        NOT\_ESTABLISHED       

&#x20;    TONIoT CANDIDATE\_SCREEN\_AND\_RESTORATION\_COMPUTED          114        NOT\_ESTABLISHED

10. CICIoT2023 frozen\_logistic\_primary RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 logistic\_existing\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 logistic\_existing\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 logistic\_existing\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_11\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_11\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_12\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP\_12\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_11\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_11\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_12\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 GBDT\_12\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP32\_16\_seed\_901 RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP32\_16\_seed\_902 RESOURCE / PRECISION AUDIT COMPUTED

CICIoT2023 MLP32\_16\_seed\_903 RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 frozen\_logistic\_primary RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 logistic\_existing\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 logistic\_existing\_10\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 logistic\_existing\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_10\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_11\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_11\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_12\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP\_12\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_10\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_11\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_11\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_12\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 GBDT\_12\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP32\_16\_seed\_901 RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP32\_16\_seed\_902 RESOURCE / PRECISION AUDIT COMPUTED

CICIoMT2024 MLP32\_16\_seed\_903 RESOURCE / PRECISION AUDIT COMPUTED

CSE frozen\_logistic\_primary RESOURCE / PRECISION AUDIT COMPUTED

CSE logistic\_existing\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CSE logistic\_existing\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CSE logistic\_existing\_10\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_10\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_11\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_11\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_12\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP\_12\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_10\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_11\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_11\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_12\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

CSE GBDT\_12\_timing\_rate RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP32\_16\_seed\_901 RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP32\_16\_seed\_902 RESOURCE / PRECISION AUDIT COMPUTED

CSE MLP32\_16\_seed\_903 RESOURCE / PRECISION AUDIT COMPUTED

NSL frozen\_logistic\_primary RESOURCE / PRECISION AUDIT COMPUTED

NSL logistic\_existing\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

NSL logistic\_existing\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

NSL logistic\_existing\_10\_timing RESOURCE / PRECISION AUDIT COMPUTED

NSL logistic\_existing\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

NSL logistic\_existing\_10\_error\_rates RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_10\_timing RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_10\_error\_rates RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_11\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_11\_timing RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_11\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_11\_error\_rates RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_12\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_12\_timing RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_12\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP\_12\_error\_rates RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_10\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_10\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_10\_timing RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_10\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_10\_error\_rates RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_11\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_11\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_11\_timing RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_11\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_11\_error\_rates RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_12\_protocol\_state RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_12\_volume\_size RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_12\_timing RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_12\_count\_burst RESOURCE / PRECISION AUDIT COMPUTED

NSL GBDT\_12\_error\_rates RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP32\_16\_seed\_901 RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP32\_16\_seed\_902 RESOURCE / PRECISION AUDIT COMPUTED

NSL MLP32\_16\_seed\_903 RESOURCE / PRECISION AUDIT COMPUTED

TONIoT frozen\_logistic\_primary RESOURCE / PRECISION AUDIT COMPUTED

TONIoT logistic\_existing\_10\_context\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT logistic\_existing\_10\_volume RESOURCE / PRECISION AUDIT COMPUTED

TONIoT logistic\_existing\_10\_timing RESOURCE / PRECISION AUDIT COMPUTED

TONIoT logistic\_existing\_10\_dns\_codes RESOURCE / PRECISION AUDIT COMPUTED

TONIoT logistic\_existing\_10\_tls\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT logistic\_existing\_10\_http\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT logistic\_existing\_10\_zeek\_anomaly\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_10\_context\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_10\_volume RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_10\_timing RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_10\_dns\_codes RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_10\_tls\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_10\_http\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_10\_zeek\_anomaly\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_11\_context\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_11\_volume RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_11\_timing RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_11\_dns\_codes RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_11\_tls\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_11\_http\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_11\_zeek\_anomaly\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_12\_context\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_12\_volume RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_12\_timing RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_12\_dns\_codes RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_12\_tls\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_12\_http\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP\_12\_zeek\_anomaly\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_10\_context\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_10\_volume RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_10\_timing RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_10\_dns\_codes RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_10\_tls\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_10\_http\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_10\_zeek\_anomaly\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_11\_context\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_11\_volume RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_11\_timing RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_11\_dns\_codes RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_11\_tls\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_11\_http\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_11\_zeek\_anomaly\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_12\_context\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_12\_volume RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_12\_timing RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_12\_dns\_codes RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_12\_tls\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_12\_http\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT GBDT\_12\_zeek\_anomaly\_state RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP32\_16\_seed\_901 RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP32\_16\_seed\_902 RESOURCE / PRECISION AUDIT COMPUTED

TONIoT MLP32\_16\_seed\_903 RESOURCE / PRECISION AUDIT COMPUTED



RESOURCE AUDIT STATUS

&#x20;   dataset                     status  INT8\_failed\_or\_unavailable\_rows                                                    detail

&#x20;CICIoT2023 RESOURCE\_FIDELITY\_COMPUTED                                0 See explicit tree exclusions and any conversion failures.

CICIoMT2024 RESOURCE\_FIDELITY\_COMPUTED                                0 See explicit tree exclusions and any conversion failures.

&#x20;       CSE RESOURCE\_FIDELITY\_COMPUTED                                0 See explicit tree exclusions and any conversion failures.

&#x20;       NSL RESOURCE\_FIDELITY\_COMPUTED                                0 See explicit tree exclusions and any conversion failures.

&#x20;    TONIoT RESOURCE\_FIDELITY\_COMPUTED                                0 See explicit tree exclusions and any conversion failures.



PRIVATE SNAPSHOT STATUS

{

&#x20; "status": "PRIVATE\_SNAPSHOT\_CREATED\_AND\_HASH\_VERIFIED",

&#x20; "archive": "/kaggle/working/fresh\_all\_datasets\_v1/resource\_quantization\_and\_private\_freeze\_v1/PRIVATE\_development\_snapshot\_20261007T194041650064Z.zip",

&#x20; "archive\_sha256": "f0bf9bae042ef5780b1d678ef5cd5e097556db8355258cbfcfb8c96a27737c17",

&#x20; "archived\_files": 3059,

&#x20; "private\_only": true,

&#x20; "public\_redistribution\_approved": false

11.====================================================================================================

GROUP B1 — SOURCE-BACKED PROVENANCE WORKBENCH

====================================================================================================



CANDIDATE MAPPING SUMMARY

&#x20;   dataset     candidate\_semantic\_view                                                                          candidate\_derived\_status   candidate\_mutability   candidate\_attack\_action          candidate\_confidence  features

CICIoMT2024            derived\_geometry                                                                          derived\_window\_statistic derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                          high         5

CICIoMT2024                      header                                                                                  window aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                        medium         1

CICIoMT2024      packet\_ttl\_or\_duration published CICIoT/CICIoMT documentation describes Duration as TTL-like; verify extractor semantics            constrained           REVIEW\_REQUIRED                        medium         1

CICIoMT2024     protocol\_or\_application                                                                           packet/window indicator              immutable                 IMMUTABLE                          high        16

CICIoMT2024                 size\_volume                                                                     fixed\_packet\_window\_aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                          high         7

CICIoMT2024                 timing\_rate                                                                      window timing/rate aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                        medium         4

CICIoMT2024             transport\_state                                                                     packet\_or\_window\_flag\_summary            constrained           REVIEW\_REQUIRED                          high        11

&#x20;CICIoT2023            derived\_geometry                                                                          derived\_window\_statistic derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                          high         5

&#x20;CICIoT2023                      header                                                                                  window aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                        medium         1

&#x20;CICIoT2023      packet\_ttl\_or\_duration published CICIoT/CICIoMT documentation describes Duration as TTL-like; verify extractor semantics            constrained           REVIEW\_REQUIRED                        medium         1

&#x20;CICIoT2023     protocol\_or\_application                                                                           packet/window indicator              immutable                 IMMUTABLE                          high        15

&#x20;CICIoT2023                 size\_volume                                                                     fixed\_packet\_window\_aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                          high         7

&#x20;CICIoT2023                 timing\_rate                                                                      window timing/rate aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                        medium         4

&#x20;CICIoT2023             transport\_state                                                                     packet\_or\_window\_flag\_summary            constrained           REVIEW\_REQUIRED                          high        12

&#x20;CICIoT2023                  unassigned                                                                                           unknown        review\_required           REVIEW\_REQUIRED requires\_manual\_source\_review         1

&#x20;       CSE            flow\_size\_volume                                                                      bidirectional\_flow\_aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                          high        15

&#x20;       CSE            flow\_timing\_rate                                                                      bidirectional\_flow\_aggregate derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                          high        25

&#x20;       CSE                    protocol                                                                    connection protocol identifier              immutable                 IMMUTABLE                          high         1

&#x20;       CSE             transport\_state                                                                                   flow flag count            constrained           REVIEW\_REQUIRED                          high        10

&#x20;       CSE                  unassigned                                                                                           unknown        review\_required           REVIEW\_REQUIRED requires\_manual\_source\_review        26

&#x20;       NSL connection\_or\_content\_state                                                                      connection/content indicator            constrained           REVIEW\_REQUIRED                          high         6

&#x20;       NSL    connection\_volume\_timing                                              connection-level field; raw packet mapping is absent        review\_required           REVIEW\_REQUIRED                        medium         3

&#x20;       NSL           protocol\_or\_state                                                                                  encoded\_category              immutable                 IMMUTABLE                          high        74

&#x20;       NSL      time\_or\_host\_statistic                                                                time\_based\_or\_host\_based\_statistic derived\_recompute\_only RECOMPUTE\_FROM\_PRIMITIVES                          high        19

&#x20;       NSL                  unassigned                                                                                           unknown        review\_required           REVIEW\_REQUIRED requires\_manual\_source\_review        10

&#x20;    TONIoT           protocol\_or\_state                                                                                  encoded\_category              immutable                 IMMUTABLE                          high        63

&#x20;    TONIoT      zeek\_connection\_timing                                               duration field; official extractor mapping required        review\_required           REVIEW\_REQUIRED                           low         1

&#x20;    TONIoT      zeek\_connection\_volume                                              official extractor and exact source mapping required        review\_required           REVIEW\_REQUIRED                           low         5

&#x20;    TONIoT   zeek\_or\_application\_state                                                     requires official TON-IoT source verification        review\_required           REVIEW\_REQUIRED                           low         6



GROUP B BLOCKERS

&#x20;   dataset  model\_features  currently\_mutable\_features  approved\_attack\_features  source\_verified\_features  primitive\_action\_candidates                 final\_group\_B\_status

&#x20;CICIoT2023              46                           8                         0                         0                            0 BLOCKED\_PENDING\_MANUAL\_SOURCE\_REVIEW

CICIoMT2024              45                           5                         0                         0                            0 BLOCKED\_PENDING\_MANUAL\_SOURCE\_REVIEW

&#x20;       CSE              77                           8                         0                         0                            0 BLOCKED\_PENDING\_MANUAL\_SOURCE\_REVIEW

&#x20;       NSL             112                           3                         0                         0                            0 BLOCKED\_PENDING\_MANUAL\_SOURCE\_REVIEW

&#x20;    TONIoT              75                           4                         0                         0                            0 BLOCKED\_PENDING\_MANUAL\_SOURCE\_REVIEW


12. ====================================================================================================

GROUP B2 — RAW TRACE / CSV MAPPING AUDIT

====================================================================================================



DATASET DECISIONS

&#x20;   dataset                                                    bundle\_sha256  frozen\_raw\_features  packet\_capture\_files\_found  tabular\_or\_log\_files\_found  readable\_tabular\_schemas\_found  raw\_features\_found\_in\_local\_schema  raw\_features\_not\_found\_in\_local\_schema                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              unmatched\_raw\_features  trace\_to\_csv\_mapping\_verified  extractor\_reproduction\_verified                        mapping\_status                       group\_B2\_status                           group\_C\_status                                            candidate\_extractor                                                                                 candidate\_extractor\_reason

&#x20;CICIoT2023 29953ea07802a058999db2e66a84ee11cafe00ca5498b8a2d27bb41f80ad6e88                   46                           0                          52                              52                                  46                                       0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              False                            False TABULAR\_PRESENT\_RAW\_CAPTURE\_NOT\_FOUND TRACE\_CSV\_AUDIT\_COMPUTED\_NOT\_APPROVED BLOCKED\_MISSING\_TRACE\_OR\_SCHEMA\_EVIDENCE Dataset-specific published fixed-size packet-window extraction     Requires original PCAPs and the exact CICIoT2023 windowing/extraction implementation plus row mapping.

CICIoMT2024 7fb9923184800d7cbbc8b5a90ac4a339344d5e2ca91ca378647d3c2466b38473                   45                           0                          42                              42                                  45                                       0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              False                            False TABULAR\_PRESENT\_RAW\_CAPTURE\_NOT\_FOUND TRACE\_CSV\_AUDIT\_COMPUTED\_NOT\_APPROVED BLOCKED\_MISSING\_TRACE\_OR\_SCHEMA\_EVIDENCE                   Dataset-specific IoMT PCAP-to-CSV extraction                       Requires original protocol traces, exact extractor version, and record/flow mapping.

&#x20;       CSE df7b8d69c59e75be107c3f524bed0c6cf0293b8c3a1cd7c8add65b5afcd4dae3                   77                           0                          13                              13                                  77                                       0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              False                            False TABULAR\_PRESENT\_RAW\_CAPTURE\_NOT\_FOUND TRACE\_CSV\_AUDIT\_COMPUTED\_NOT\_APPROVED BLOCKED\_MISSING\_TRACE\_OR\_SCHEMA\_EVIDENCE          CICFlowMeter-compatible bidirectional flow extraction                                        Requires original PCAPs and matching CICFlowMeter version/settings.

&#x20;       NSL cd29b0ac4a421aa7ba0d75c7da2e8238ca601c80e13ebfef8fb01691d03fda29                   41                           0                          22                               9                                   1                                      40 protocol\_type|service|flag|src\_bytes|dst\_bytes|land|wrong\_fragment|urgent|hot|num\_failed\_logins|logged\_in|num\_compromised|root\_shell|su\_attempted|num\_root|num\_file\_creations|num\_shells|num\_access\_files|num\_outbound\_cmds|is\_host\_login|is\_guest\_login|count|srv\_count|serror\_rate|srv\_serror\_rate|rerror\_rate|srv\_rerror\_rate|same\_srv\_rate|diff\_srv\_rate|srv\_diff\_host\_rate|dst\_host\_count|dst\_host\_srv\_count|dst\_host\_same\_srv\_rate|dst\_host\_diff\_srv\_rate|dst\_host\_same\_src\_port\_rate|dst\_host\_srv\_diff\_host\_rate|dst\_host\_serror\_rate|dst\_host\_srv\_serror\_rate|dst\_host\_rerror\_rate|dst\_host\_srv\_rerror\_rate                          False                            False TABULAR\_PRESENT\_RAW\_CAPTURE\_NOT\_FOUND TRACE\_CSV\_AUDIT\_COMPUTED\_NOT\_APPROVED BLOCKED\_MISSING\_TRACE\_OR\_SCHEMA\_EVIDENCE                           KDD connection-record representation Current NSL-KDD records are connection-feature tables; raw packet reconstruction is not assumed available.

&#x20;    TONIoT bb65ffc65efcd62a93c7f9b33aa4d000ecde3970370f2fa05f5786753d53b1bf                   30                           0                           1                               1                                  30                                       0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              False                            False TABULAR\_PRESENT\_RAW\_CAPTURE\_NOT\_FOUND TRACE\_CSV\_AUDIT\_COMPUTED\_NOT\_APPROVED BLOCKED\_MISSING\_TRACE\_OR\_SCHEMA\_EVIDENCE        TON-IoT/Zeek or dataset-specific network log extraction                       Requires exact official schema, original logs/traces, and feature-extractor mapping.

13. CICIoT2023 RECOVERED SPLIT / PATTERN AUDIT COMPUTED

CICIoMT2024 RECOVERED SPLIT / PATTERN AUDIT COMPUTED

CSE RECOVERED SPLIT / PATTERN AUDIT COMPUTED

NSL RECOVERED SPLIT / PATTERN AUDIT COMPUTED

TONIoT RECOVERED SPLIT / PATTERN AUDIT COMPUTED



GROUP A1 RECOVERY RECEIPT

{

&#x20; "A1\_status": "POST\_RECOVERY\_LOCAL\_SNAPSHOT\_AND\_SPLIT\_AUDIT\_CREATED",

&#x20; "local\_repository": "/kaggle/working/group\_A1\_development\_source\_freeze\_v1/private\_source\_snapshot",

&#x20; "local\_tag": "v1-development-recovery-freeze",

&#x20; "git\_commit": "7267a36ebcadaa81d270147ae5841b2e064f53c2",

&#x20; "earlier\_reported\_commit\_not\_reconstructed": "5c2a604f53027f4a05bafb23a076daee16ca9283",

&#x20; "remote\_push\_performed": false,

&#x20; "data\_changed": false,

&#x20; "models\_retrained": false,

&#x20; "source\_snapshots": 2,

&#x20; "source\_coverage\_status": "Recovered candidates and NEW runtime history; full original executed-source coverage unverified",

&#x20; "unexpected\_exact\_record\_overlap\_count": 0,

&#x20; "source\_group\_independence\_status": "NOT\_ESTABLISHED\_BY\_RECORD\_IDS",

&#x20; "exposure\_registry\_scope": "Current fresh bundles only, not all legacy exposures",

&#x20; "A2\_confirmation\_status": "NOT\_RUN; final B-E and independent-data design pending",

&#x20; "final\_confirmatory\_protocol\_frozen": false,

&#x20; "public\_release\_approved": false,

&#x20; "next\_group": "B \\u2014 recreate missing source evidence; preserve restored C/D/E/G development results"

}



A1 PRIVATE SOURCE ARCHIVE

{

&#x20; "archive": "/kaggle/working/PRIVATE\_A1\_RECOVERY\_SOURCE\_7267a36ebcad.zip",

&#x20; "sha256": "e6cef1b06d19b9faa33c7eb96d74e693f4b11c6fb41e784da68975b21aff9f26",

&#x20; "private\_only": true,

&#x20; "scope": "A1 source/audit/registry only; experiment models are in the original full backup"

}



ALLOCATION SUMMARY

&#x20;   dataset                         allocation  records  attack\_fraction  source\_files  pattern\_duplicates

&#x20;CICIoT2023                           train\_df    10906         0.500000             3                  15

&#x20;CICIoT2023             primary\_calibration\_df      680         0.000000             3                   0

&#x20;CICIoT2023                  view\_threshold\_df      679         0.000000             3                   0

&#x20;CICIoT2023              normal\_profile\_fit\_df      679         0.000000             3                   0

&#x20;CICIoT2023      normal\_profile\_calibration\_df      679         0.000000             3                   0

&#x20;CICIoT2023                 known\_reference\_df     2038         0.666830             3                   0

&#x20;CICIoT2023       known\_profile\_calibration\_df     2037         0.666667             3                   0

&#x20;CICIoT2023                     source\_test\_df     5472         0.500000             3                   7

&#x20;CICIoT2023  evaluation:natural\_heldout\_family    13776         0.500000             3                  40

CICIoMT2024                           train\_df    10186         0.500000             2                 103

CICIoMT2024             primary\_calibration\_df      636         0.000000             2                   0

CICIoMT2024                  view\_threshold\_df      635         0.000000             2                   0

CICIoMT2024              normal\_profile\_fit\_df      635         0.000000             2                   0

CICIoMT2024      normal\_profile\_calibration\_df      635         0.000000             2                   0

CICIoMT2024                 known\_reference\_df     1906         0.666842             2                  14

CICIoMT2024       known\_profile\_calibration\_df     1905         0.666667             2                   6

CICIoMT2024                     source\_test\_df     5104         0.500000             2                  30

CICIoMT2024  evaluation:natural\_heldout\_family    11112         0.500000             2                 159

&#x20;       CSE                           train\_df     3000         0.500000             1                   0

&#x20;       CSE             primary\_calibration\_df      188         0.000000             1                   0

&#x20;       CSE                  view\_threshold\_df      188         0.000000             1                   0

&#x20;       CSE              normal\_profile\_fit\_df      187         0.000000             1                   0

&#x20;       CSE      normal\_profile\_calibration\_df      187         0.000000             1                   0

&#x20;       CSE                 known\_reference\_df      562         0.667260             1                   0

&#x20;       CSE       known\_profile\_calibration\_df      562         0.667260             1                   0

&#x20;       CSE                     source\_test\_df     1500         0.500000             1                   0

&#x20;       CSE      evaluation:natural\_day\_Botnet     6000         0.500000             1                   0

&#x20;       CSE  evaluation:natural\_day\_Bruteforce     6106         0.500000             1                   0

&#x20;       CSE       evaluation:natural\_day\_DDoS2     9460         0.500000             1                   0

&#x20;       CSE        evaluation:natural\_day\_DoS1    12000         0.500000             1                   0

&#x20;       CSE        evaluation:natural\_day\_DoS2     6110         0.500000             1                   0

&#x20;       CSE      evaluation:natural\_day\_Infil1     6000         0.500000             1                   0

&#x20;       CSE      evaluation:natural\_day\_Infil2     6000         0.500000             1                   0

&#x20;       CSE        evaluation:natural\_day\_Web1      682         0.500000             1                   3

&#x20;       CSE        evaluation:natural\_day\_Web2     1082         0.500000             1                   2

&#x20;       NSL                           train\_df     2982         0.500000             1                   0

&#x20;       NSL             primary\_calibration\_df      186         0.000000             1                   0

&#x20;       NSL                  view\_threshold\_df      186         0.000000             1                   0

&#x20;       NSL              normal\_profile\_fit\_df      186         0.000000             1                   0

&#x20;       NSL      normal\_profile\_calibration\_df      186         0.000000             1                   0

&#x20;       NSL                 known\_reference\_df      558         0.666667             1                   0

&#x20;       NSL       known\_profile\_calibration\_df      558         0.666667             1                   0

&#x20;       NSL                     source\_test\_df     1500         0.500000             1                   0

&#x20;       NSL   evaluation:natural\_official\_test    12000         0.500000             1                   2

&#x20;       NSL evaluation:natural\_official\_test21     4304         0.500000             1                   1

&#x20;    TONIoT                           train\_df     6252         0.500000             1                2440

&#x20;    TONIoT             primary\_calibration\_df      390         0.000000             1                 187

&#x20;    TONIoT                  view\_threshold\_df      390         0.000000             1                 181

&#x20;    TONIoT              normal\_profile\_fit\_df      390         0.000000             1                 204

&#x20;    TONIoT      normal\_profile\_calibration\_df      390         0.000000             1                 189

&#x20;    TONIoT                 known\_reference\_df     1170         0.666667             1                 303

&#x20;    TONIoT       known\_profile\_calibration\_df     1170         0.666667             1                 289

&#x20;    TONIoT                     source\_test\_df     3144         0.500000             1                1146

&#x20;    TONIoT  evaluation:natural\_heldout\_family     6258         0.500000             1                4088

