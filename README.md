# NeuroEdge-IDS (cppIDS)

### Real-Time Predictive Coding and Spiking Reservoir Computing for Edge Intrusion Detection

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Build System](https://img.shields.io/badge/CMake-3.20%2B-brightgreen.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-Academic%20Use-lightgrey.svg)](<>)

**NeuroEdge-IDS (`cppIDS`)** is a native C++20, high-throughput neuromorphic Network Intrusion Detection System (NIDS) engineered for resource-constrained edge gateways. By pairing statistical **Predictive Coding (PC)** with event-driven **Spiking Neural Network (SNN)** reservoir dynamics and Spike-Timing-Dependent Plasticity (STDP), `cppIDS` detects volumetric, temporal, and reconnaissance network anomalies at line rate with sub-microsecond latency and a minimal working-set memory footprint.

---

## 1. Motivation & Problem Statement

Conventional Machine Learning and Deep Learning Network IDS architectures (e.g., CNN-LSTM, Vision Transformers) rely on offline batch windowing and dense tensor multiplications. This paradigm introduces severe structural limitations:

1. **Inference Latency:** Deep sequence models require collecting sliding time windows, introducing tens to hundreds of milliseconds of buffering delay per classification.
2. **Computational Overhead:** Processing requires powerful GPUs or multithreaded runtimes consuming gigabytes of system RAM, making them unsuitable for hardware-constrained edge routers.
3. **Concept Drift Vulnerability:** Static deep networks struggle with changing network baselines unless continuously retrained via expensive backpropagation.

**NeuroEdge-IDS** addresses these bottlenecks by operating strictly on an asynchronous, event-driven stream. Using online predictive coding to track per-flow statistical invariants and an 8-neuron Leaky Integrate-and-Fire (LIF) reservoir, `cppIDS` executes continuous-time temporal feature extraction directly on raw Ethernet frames without deep packet inspection (DPI) or GPU acceleration.

---

## 2. Core Architecture & Pipeline

```

+-------------------------------------------------------------------------+
|                           PACKET INGESTION                              |
|   Raw Link-Layer Frames (Npcap / libpcap zero-copy packet extraction)   |
+-------------------------------------------------------------------------+
|
v
+-------------------------------------------------------------------------+
|                       STATISTICAL PREDICTIVE CODING                     |
|  Per-flow EWMA tracking: Packet Size, IAT, Burst Rate, Variance, Ratios |
|  Drift Locking Mechanism (freezes baselines during persistent attacks)  |
+-------------------------------------------------------------------------+
| Prediction Error Vectors
v
+-------------------------------------------------------------------------+
|                        LEAKY SPIKE ENCODER                              |
|  6 Presynaptic channels convert statistical deviations to spike trains  |
+-------------------------------------------------------------------------+
| Current Injections
v
+-------------------------------------------------------------------------+
|                    NEUROMORPHIC SNN RESERVOIR CORE                      |
|  8 Hidden LIF Neurons with continuous-time exponential voltage decay    |
|  Unsupervised STDP (Hebbian Potentiation & Lateral Depression)          |
|  Dynamic Homeostatic Refractory Threshold Scaling                       |
+-------------------------------------------------------------------------+
| Anomaly Firings
v
+-------------------------------------------------------------------------+
|                       DUAL READOUT & ALERT ENGINE                       |
|  Path A: Contextual Domain Classifier (Suppression & Pair Density)      |
|  Path B: Reward-Modulated Spiking Readout (FFI + R-STDP Learning)       |
|  Path C: Batch Regularized Logistic Regression Readout                  |
+-------------------------------------------------------------------------+

```

### Key Components

- **Header Extractor (`src/features/extractor.cpp`):** Validates L2/L3 framing and strips Ethernet, IPv4, TCP, and UDP headers in zero-copy buffers.
- **Stateful Flow Tracker (`src/features/flow_tracker.cpp`):** Maintains bidirectional flow records indexed by canonical 5-tuple hash keys. Computes online Exponential Weighted Moving Averages (EWMA) and suppresses parameter drift during sustained anomalies.
- **Spike Encoder (`src/features/spike_encoder.cpp`):** Maps 6 statistical error channels into presynaptic charge accumulators:
  - _Channel 0:_ Packet payload length divergence.
  - _Channel 1:_ Inter-arrival time (IAT) rhythm divergence.
  - _Channel 2:_ Protocol state violations (e.g., unexpected SYN flags).
  - _Channel 3:_ Volumetric packet/byte surge and host-pair density.
  - _Channel 4:_ Packet length structural variance surges.
  - _Channel 5:_ Bidirectional flow asymmetry.
- **SNN Core Engine (`src/neuromorphic/snn_core.cpp`):** An 8-neuron LIF reservoir featuring continuous exponential voltage decay, homeostatic refractory thresholds to prevent runaway excitation, and STDP adaptation.
- **Scorer & Context Engine (`src/detection/scorer.cpp`):** Implements multi-tier threat confirmation, pair-concurrency verification, and routine protocol suppression (DNS, NTP, DHCP, background enterprise management).
- **Supervised Readouts (`src/neuromorphic/snn_readout.cpp` & `src/detection/logistic_model.cpp`):** Supports secondary inference heads via an R-STDP trained spiking output neuron with feed-forward inhibition (FFI) or an L2-regularized logistic regression model.

---

## 3. Build & Requirements Setup

### Prerequisites

- **Operating System:** Windows 10/11 (x64) or Linux (Ubuntu 22.04+ / Debian)
- **Compiler:** C++20 compliant compiler (`Clang 15+`, `GCC 12+`, or `MSVC 2019+`)
- **Build Tool:** `CMake 3.20+` and `Ninja`
- **Packet Capture Library:**
  - Windows: [Npcap SDK](https://npcap.com/#download) (Headers must be in your include path; `wpcap.dll` is dynamically loaded at runtime).
  - Linux: `libpcap-dev` (`sudo apt-get install libpcap-dev`).

### Compiling with CMake & Ninja

```powershell
# From the project root directory
mkdir build
cd build

# Generate build configuration
cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release ..

# Compile both the main daemon and evaluation harness
ninja
```

The build process outputs two primary executables:

1. `cppids.exe` (or `cppids` on Linux): The production real-time capture daemon.
2. `eval_harness.exe` (or `eval_harness`): The offline dataset benchmark and ground-truth validation runner.

---

## 4. Command-Line Arguments Reference

Both `cppids` and `eval_harness` share unified CLI parameter semantics:

| Flag                  | Parameter        | Description                                                                                                   |
| --------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `-i`                  | `<interface>`    | Specifies network interface for live capture (e.g., `-i 0` or adapter UUID).                                  |
| `-filter`             | `"<bpf_filter>"` | Berkeley Packet Filter (BPF) string (e.g., `-filter "ip and not port 22"`).                                   |
| `--config`            | `<file.ini>`     | Path to engine configuration file (defaults to `ids_config.ini`).                                             |
| `--eval`              | `<seconds>`      | Interval in seconds to append periodic telemetry rows to `evaluation_metrics.csv`.                            |
| `--telemetry`         | `<minutes>`      | Interval in minutes to flush structured runtime snapshots to `mokshaids_telemetry.jsonl`.                     |
| `--attackers`         | `<csv_ips>`      | Comma-separated list of ground-truth attacker IPs for supervised scoring.                                     |
| `--victims`           | `<csv_ips>`      | Comma-separated list of targeted victim IPs (optional ground-truth filter).                                   |
| `--ports`             | `<csv_ports>`    | Comma-separated list of targeted destination ports (optional filter).                                         |
| `--stdp`              | _None_           | Runs unsupervised online STDP learning with random weight initialization (default).                           |
| `--train`             | `<model.bin>`    | Enables STDP and exports stratified true-positive baseline weights to binary file upon exit.                  |
| `--test`              | `<model.bin>`    | Freezes synaptic weights, disables STDP, and loads pre-trained baseline weights.                              |
| `--transfer`          | `<model.bin>`    | Hydrates baseline weights from file and keeps STDP active for continuous adaptation.                          |
| `--base-model`        | `<model.bin>`    | Hydrates reservoir baseline weights while allowing downstream readout training.                               |
| `--train-snn-readout` | `<model.bin>`    | Freezes SNN core and trains downstream Threat LIF neuron via R-STDP.                                          |
| `--test-snn-readout`  | `<model.bin>`    | Evaluates pre-trained neuromorphic spiking readout without updating weights.                                  |
| `--train-lr`          | `<model.bin>`    | Buffers flow features into memory and fits an L2-regularized logistic model on exit.                          |
| `--test-lr`           | `<model.bin>`    | Scores flows using a pre-trained logistic regression readout head.                                            |
| `--export-features`   | `<file.csv>`     | Exports 11-dimensional neuromorphic flow features and ground truth labels to CSV for deep learning baselines. |
| `[positional]`        | `<file.pcap>`    | Path(s) to PCAP files for offline replay benchmarking.                                                        |

---

## 5. Usage & Execution Workflows

### A. Live Network Sniffing

To find the network adapters in your system:

```powershell
Get-NetAdapter | Format-Table Name, InterfaceDescription, InterfaceGuid -AutoSize
```

Capture live traffic on the default adapter, applying unsupervised STDP adaptation:

```powershell
./cppids --telemetry 10 -i "{YOUR-ADAPTER-GUID-HERE}"
```

### B. Offline Model Training (Baseline Export)

Train the SNN reservoir on a DoS/DDoS capture (e.g., Wednesday of CIC-IDS2017) and export baseline weights:

```powershell
./eval_harness --train wednesday_model.bin --attackers 172.16.0.1 --victims 192.168.10.50 --ports 80,443 Wednesday-workingHours.pcap
```

### C. Testing Pre-Trained Weights (Inference Mode)

Benchmark the frozen model against an unseen Infiltration and Port Scanning capture:

```powershell
./eval_harness --test wednesday_model.bin --attackers 192.168.10.8 --victims 192.168.10.5,192.168.10.9,192.168.10.12,192.168.10.14,192.168.10.15,192.168.10.16,192.168.10.17,192.168.10.19,192.168.10.25,192.168.10.50 Thursday-Afternoon-Infiltration.pcap
```

### D. Multi-File Benchmark with Continuous CSV Metrics

Replay multiple captures sequentially while exporting 5-second sliding window telemetry to `evaluation_metrics.csv`:

```powershell
./eval_harness --test wednesday_model.bin --eval 5 --attackers 172.16.0.1 capture_part1.pcap capture_part2.pcap
```

### E. Deep Learning Feature Export (SOTA Benchmarking)

Export statistical and neuromorphic reservoir states to a flat CSV file for offline evaluation in PyTorch or TensorFlow, completely bypassing Python PCAP parsing overhead:

```powershell
./eval_harness --base-model combined_model.bin --attackers 172.16.0.1 --export-features dl_dataset.csv capture_part1.pcap
```

---

## 6. Runtime Configuration (`ids_config.ini`)

Fine-tune internal mathematical parameters via `ids_config.ini` without recompiling:

```ini
# SNN Core Parameters
FIRE_THRESHOLD=5000.0        # Hidden LIF membrane firing threshold
TAU=0.5                     # Membrane potential leak time constant (seconds)

# Predictive Coding & Flow Tracker
PREDICTION_ALPHA=0.125      # Base EWMA learning rate
DRIFT_LOCK_THRESHOLD=3.5    # Anomaly distance triggering adaptation suppression
EXPIRATION_SECONDS=60.0     # Flow inactivity timeout before state eviction
MAX_ACTIVE_FLOWS=500000     # Table capacity limit before oldest-flow eviction

# Threat Scoring & Escalation
ALERT_THRESHOLD=45          # Minimum anomaly score required to spawn/escalate an episode
ALERT_COOLDOWN_MS=10000     # Alert suppression window on repeated anomalies
EPISODE_TIMEOUT_MS=30000    # Inactivity window required to resolve an active threat episode
```

---

## 7. Performance & Benchmarks

Refer to the reports folder for detailed performance metrics and benchmark results ran on my PC (HP 15-da0077tx).

**My PC specs (HP 15-da0077tx):**

- **Processor (CPU):** Intel Core i5-8250U (8th Gen, Quad-Core, 1.6 GHz base up to 3.4 GHz, 8 Threads, 6 MB Cache)
- **Memory (RAM):** 8 GB DDR4 (2400 MHz)
- **Graphics (GPU):** NVIDIA GeForce MX110 with 2 GB Dedicated VRAM
- **Storage:** 1 TB SATA HDD (5400 rpm)
- **Display:** 15.6-inch Full HD (1920 x 1080) Anti-Glare LED-backlit
- **Operating System (Factory):** Windows 10

## 8. Acknowledgements & Research Inspirations

The foundational knowledge and inspiration for utilizing Spiking Neural Networks (SNNs) in this project were initially discovered through discussions and resources shared within the **Open Neuromorphic Discord server**.

Additionally, the event-driven architectures and algorithms developed for `cppIDS` draw heavily on recent breakthroughs in neuromorphic cyber-security literature:

- **Event-Driven Intrusion Detection for Edge & IoT:** Prajwalasimha S N et al. (2025) designed an event-driven IDS framework utilizing biologically plausible SNNs and Spike-Timing Dependent Plasticity (STDP). Their research highlights how spike-based communication provides energy-efficient, real-time anomaly detection ideally suited for resource-constrained edge devices.
- **Packet-Observation Spiking Neural Networks:** Phu Nguyen Phan Hai et al. (2026) introduced PON, an SNN architecture that combines 1D convolution and Leaky-Integrate-and-Fire (LIF) neurons for IoT intrusion detection directly from packet headers. Their work proved that highly accurate online intrusion detection can be performed without resorting to computationally expensive Deep Packet Inspection (DPI) of payload data.
