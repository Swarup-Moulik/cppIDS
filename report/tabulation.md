**SNN with Classifier or LR and R-STDP Readout Tabulation**

| Architecture       | Configuration / Mode         | Dataset         | F1-Score | Recall (DR) | Precision | FPR   | TP      | FP     | FN      | Avg Latency | Throughput  | RAM    |
| ------------------ | ---------------------------- | --------------- | -------- | ----------- | --------- | ----- | ------- | ------ | ------- | ----------- | ----------- | ------ |
| **Core SNN**       | Unsupervised (No Flags)      | Wednesday       | 98.22%   | 99.75%      | 96.74%    | 1.94% | 179,939 | 6,060  | 448     | 1.17 μs     | 75,560 PPS  | 139 MB |
| **Core SNN**       | Unsupervised (No Flags)      | Thurs Afternoon | 90.31%   | 91.30%      | 89.35%    | 3.36% | 56,240  | 6,703  | 5,362   | 1.28 μs     | 91,232 PPS  | 138 MB |
| **Core SNN**       | Unsupervised (No Flags)      | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.02% | 0       | 18     | 2,066   | 0.61 μs     | 33,532 PPS  | 107 MB |
| **Core SNN**       | Test (Combined Weights)      | Wednesday       | 98.23%   | 99.79%      | 96.72%    | 1.96% | 180,010 | 6,096  | 377     | 0.90 μs     | 84,707 PPS  | 140 MB |
| **Core SNN**       | Test (Combined Weights)      | Thurs Afternoon | 90.89%   | 92.45%      | 89.37%    | 3.39% | 56,954  | 6,776  | 4,648   | 0.87 μs     | 122,110 PPS | 138 MB |
| **Core SNN**       | Test (Combined Weights)      | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.01% | 0       | 8      | 2,066   | 0.55 μs     | 30,139 PPS  | 108 MB |
| **Core SNN**       | Test (Wednesday Weights)     | Wednesday       | 98.24%   | 99.78%      | 96.75%    | 1.94% | 179,984 | 6,051  | 403     | 1.05 μs     | 72,264 PPS  | 139 MB |
| **Core SNN**       | Test (Wednesday Weights)     | Thurs Afternoon | 90.67%   | 91.98%      | 89.39%    | 3.37% | 56,663  | 6,725  | 4,939   | 0.78 μs     | 109,075 PPS | 138 MB |
| **Core SNN**       | Test (Wednesday Weights)     | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.01% | 0       | 8      | 2,066   | 0.51 μs     | 32,814 PPS  | 107 MB |
| **Core SNN**       | Transfer (Combined Weights)  | Wednesday       | 98.21%   | 99.79%      | 96.69%    | 1.98% | 180,015 | 6,172  | 372     | 0.84 μs     | 87,992 PPS  | 139 MB |
| **Core SNN**       | Transfer (Combined Weights)  | Thurs Afternoon | 90.85%   | 92.44%      | 89.32%    | 3.41% | 56,943  | 6,806  | 4,659   | 0.85 μs     | 123,243 PPS | 138 MB |
| **Core SNN**       | Transfer (Combined Weights)  | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.01% | 0       | 10     | 2,066   | 0.56 μs     | 32,048 PPS  | 108 MB |
| **Core SNN**       | Transfer (Wednesday Weights) | Wednesday       | 98.22%   | 99.78%      | 96.72%    | 1.96% | 179,982 | 6,102  | 405     | 0.85 μs     | 71,617 PPS  | 139 MB |
| **Core SNN**       | Transfer (Wednesday Weights) | Thurs Afternoon | 90.63%   | 91.94%      | 89.36%    | 3.38% | 56,635  | 6,743  | 4,967   | 0.82 μs     | 100,811 PPS | 138 MB |
| **Core SNN**       | Transfer (Wednesday Weights) | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.01% | 0       | 8      | 2,066   | 0.54 μs     | 29,871 PPS  | 107 MB |
| **Logistic Reg**   | Test (Combined Weights)      | Wednesday       | 93.59%   | 99.53%      | 88.32%    | 7.62% | 179,546 | 23,740 | 841     | 1.18 μs     | 62,070 PPS  | 140 MB |
| **Logistic Reg**   | Test (Combined Weights)      | Thurs Afternoon | 86.04%   | 93.20%      | 79.91%    | 7.23% | 57,414  | 14,437 | 4,188   | 1.15 μs     | 89,192 PPS  | 138 MB |
| **Logistic Reg**   | Test (Combined Weights)      | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 6.58% | 0       | 5,576  | 2,066   | 0.86 μs     | 29,781 PPS  | 108 MB |
| **Logistic Reg**   | Test (Wednesday Weights)     | Wednesday       | 94.50%   | 99.42%      | 90.04%    | 6.36% | 179,348 | 19,828 | 1,039   | 1.08 μs     | 64,828 PPS  | 140 MB |
| **Logistic Reg**   | Test (Wednesday Weights)     | Thurs Afternoon | 1.61%    | 0.91%       | 7.05%     | 3.69% | 559     | 7,374  | 61,043  | 0.65 μs     | 121,470 PPS | 138 MB |
| **Logistic Reg**   | Test (Wednesday Weights)     | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 4.91% | 0       | 4,161  | 2,066   | 0.67 μs     | 30,681 PPS  | 107 MB |
| **R-STDP Readout** | Test (Combined Weights)      | Wednesday       | 98.09%   | 99.84%      | 96.41%    | 2.15% | 180,091 | 6,714  | 296     | 1.34 μs     | 81,218 PPS  | 140 MB |
| **R-STDP Readout** | Test (Combined Weights)      | Thurs Afternoon | 91.97%   | 95.35%      | 88.82%    | 3.70% | 58,739  | 7,391  | 2,863   | 0.89 μs     | 124,616 PPS | 139 MB |
| **R-STDP Readout** | Test (Combined Weights)      | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.14% | 0       | 115    | 2,066   | 0.63 μs     | 31,971 PPS  | 108 MB |
| **R-STDP Readout** | Test (Wednesday Weights)     | Wednesday       | 12.99%   | 6.97%       | 95.31%    | 0.20% | 12,569  | 619    | 167,818 | 0.60 μs     | 86,459 PPS  | 140 MB |
| **R-STDP Readout** | Test (Wednesday Weights)     | Thurs Afternoon | 0.92%    | 0.47%       | 52.18%    | 0.13% | 287     | 263    | 61,315  | 0.73 μs     | 105,621 PPS | 139 MB |
| **R-STDP Readout** | Test (Wednesday Weights)     | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.03% | 0       | 29     | 2,066   | 0.60 μs     | 31,363 PPS  | 108 MB |
