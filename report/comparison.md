**DEEP LEARNING SOTA BENCHMARK TABLE**

| Architecture       | Configuration / Mode     | Dataset         | F1-Score | Recall (DR) | Precision | FPR   | TP      | FP    | FN     | Avg Latency | Throughput | RAM    |
| ------------------ | ------------------------ | --------------- | -------- | ----------- | --------- | ----- | ------- | ----- | ------ | ----------- | ---------- | ------ |
| **Flow LSTM**      | Test (Wednesday Weights) | Wednesday       | 98.61%   | 99.02%      | 98.20%    | 1.05% | 35,723  | 656   | 354    | 16.00 μs    | 62,503 PPS | 598 MB |
| **Flow LSTM**      | Test (Wednesday Weights) | Thurs Afternoon | 1.54%    | 0.78%       | 55.30%    | 0.19% | 480     | 388   | 61,122 | 16.23 μs    | 61,608 PPS | 615 MB |
| **Flow LSTM**      | Test (Wednesday Weights) | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.00% | 0       | 0     | 2,066  | 16.76 μs    | 59,673 PPS | 605 MB |
| **Flow 1D-CNN**    | Test (Wednesday Weights) | Wednesday       | 96.56%   | 98.58%      | 94.61%    | 3.25% | 35,565  | 2,025 | 512    | 15.19 μs    | 65,845 PPS | 617 MB |
| **Flow 1D-CNN**    | Test (Wednesday Weights) | Thurs Afternoon | 1.35%    | 0.72%       | 10.75%    | 1.85% | 445     | 3,695 | 61,157 | 15.43 μs    | 64,827 PPS | 590 MB |
| **Flow 1D-CNN**    | Test (Wednesday Weights) | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 2.03% | 0       | 1,722 | 2,066  | 19.89 μs    | 50,264 PPS | 580 MB |
| **CNN-SNN Hybrid** | Test (Wednesday Weights) | Wednesday       | 97.22%   | 99.07%      | 95.44%    | 2.74% | 35,742  | 1,709 | 335    | 23.96 μs    | 41,732 PPS | 610 MB |
| **CNN-SNN Hybrid** | Test (Wednesday Weights) | Thurs Afternoon | 1.42%    | 0.74%       | 15.45%    | 1.25% | 458     | 2,506 | 61,144 | 24.62 μs    | 40,616 PPS | 620 MB |
| **CNN-SNN Hybrid** | Test (Wednesday Weights) | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 1.35% | 0       | 1,148 | 2,066  | 25.55 μs    | 39,135 PPS | 609 MB |
| **Flow LSTM**      | Test (Combined Weights)  | Wednesday       | 98.46%   | 99.00%      | 97.92%    | 1.21% | 178,575 | 3,786 | 1,812  | 16.49 μs    | 60,642 PPS | 755 MB |
| **Flow LSTM**      | Test (Combined Weights)  | Thurs Afternoon | 95.34%   | 98.87%      | 92.04%    | 2.64% | 60,908  | 5,265 | 694    | 15.94 μs    | 62,724 PPS | 740 MB |
| **Flow LSTM**      | Test (Combined Weights)  | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.21% | 0       | 174   | 2,066  | 16.64 μs    | 60,096 PPS | 730 MB |
| **Flow LSTM**      | Test (Combined Weights)  | Combined Split  | 97.63%   | 98.80%      | 96.49%    | 1.70% | 47,876  | 1,740 | 581    | 15.62 μs    | 64,029 PPS | 736 MB |
| **Flow 1D-CNN**    | Test (Combined Weights)  | Wednesday       | 98.23%   | 98.44%      | 98.01%    | 1.16% | 177,571 | 3,601 | 2,816  | 15.17 μs    | 65,905 PPS | 761 MB |
| **Flow 1D-CNN**    | Test (Combined Weights)  | Thurs Afternoon | 95.01%   | 98.19%      | 92.02%    | 2.62% | 60,486  | 5,242 | 1,116  | 15.15 μs    | 66,013 PPS | 747 MB |
| **Flow 1D-CNN**    | Test (Combined Weights)  | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.22% | 0       | 188   | 2,066  | 15.05 μs    | 66,447 PPS | 737 MB |
| **Flow 1D-CNN**    | Test (Combined Weights)  | Combined Split  | 97.36%   | 98.21%      | 96.52%    | 1.68% | 47,592  | 1,715 | 865    | 14.80 μs    | 67,562 PPS | 697 MB |
| **CNN-SNN Hybrid** | Test (Combined Weights)  | Wednesday       | 98.40%   | 99.33%      | 97.48%    | 1.48% | 179,172 | 4,623 | 1,215  | 25.92 μs    | 38,576 PPS | 741 MB |
| **CNN-SNN Hybrid** | Test (Combined Weights)  | Thurs Afternoon | 94.67%   | 97.88%      | 91.66%    | 2.75% | 60,295  | 5,486 | 1,307  | 26.63 μs    | 37,550 PPS | 729 MB |
| **CNN-SNN Hybrid** | Test (Combined Weights)  | Thurs Morning   | 0.00%    | 0.00%       | 0.00%     | 0.24% | 0       | 202   | 2,066  | 25.88 μs    | 38,639 PPS | 718 MB |
| **CNN-SNN Hybrid** | Test (Combined Weights)  | Combined Split  | 97.42%   | 98.82%      | 96.05%    | 1.93% | 47,885  | 1,968 | 572    | 26.12 μs    | 38,285 PPS | 724 MB |
