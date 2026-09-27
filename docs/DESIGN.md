# NeuroEdge-IDS (`cppIDS`) System Architecture & Design Specification

This document provides a formal, comprehensive architectural and mathematical specification of the **NeuroEdge-IDS (`cppIDS`)** engine. Designed for high-throughput edge environments, `cppIDS` fuses statistical **Predictive Coding (PC)** with an asynchronous, event-driven **Spiking Neural Network (SNN)** reservoir and multi-paradigm decision readouts.

---

## 1. High-Level Architectural Decomposition

The system processes packets sequentially across five tightly coupled pipeline stages, operating without intermediate allocations or dynamic heap overhead during steady-state packet ingestion.

```

+----------------------------------------------------------------------------------------------------+
| PACKET INGESTION & DECODING |
| (Zero-copy link-layer framing, IPv4 validation, L4 routing) |
+----------------------------------------------------------------------------------------------------+
│
▼
+----------------------------------------------------------------------------------------------------+
| STATEFUL PREDICTIVE TRACKER |
| - MurmurHash3-based canonical 5-tuple flow hashing |
| - Continuous EWMA expectations: size, IAT, rate, variance, byte/packet ratios |
| - Anomaly distance drift-locking mechanism |
+----------------------------------------------------------------------------------------------------+
│ Normalized Prediction Errors
▼
+----------------------------------------------------------------------------------------------------+
| LEAKY SPIKE ENCODER (6 CHANNELS) |
| - Per-channel leaky current accumulators with discrete sub-threshold decay |
| - Channel-bounded discharge thresholds triggering presynaptic spike events |
+----------------------------------------------------------------------------------------------------+
│ Presynaptic Spike Events
▼
+----------------------------------------------------------------------------------------------------+
| NEUROMORPHIC SNN RESERVOIR CORE |
| - 8 Leaky Integrate-and-Fire (LIF) hidden neurons per flow |
| - Exponential membrane voltage decay (tau = 0.5s - 1.5s) |
| - Hebbian STDP potentiation & lateral inter-channel depression |
| - Dynamic homeostatic refractory threshold penalties |
+----------------------------------------------------------------------------------------------------+
│ Post-Synaptic Membrane Potential
▼
+----------------------------------------------------------------------------------------------------+
| DECISION READOUT SUBSYSTEMS |
| ┌───────────────────────────┬─────────────────────────────────────┬──────────────────────────┐ |
| │ Domain Heuristic │ Reward-Modulated Spiking Head │ Batch Logistic Head │ |
| │ (Phase 1) │ (Phase 2) │ (Phase 2) │ |
| │ - Volumetric pair surge │ - Supervised R-STDP output neuron │ - L2-regularized SGD | |
| │ - Slow DoS detection │ - Feed-Forward Inhibition (FFI) │ - Z-score standardized | |
| │ - Contextual suppression │ - Eligibility trace tagging │ - In-memory flow buffer | |
| └───────────────────────────┴─────────────────────────────────────┴──────────────────────────┘ |
| │ |
| [Feature Extraction Bridge] ──┘ |
| Dumps exact R^11 feature vector to CSV |
+----------------------------------------------------------------------------------------------------+

```

---

## 2. Packet Ingestion & Extraction (`extractor.cpp`)

The ingestion layer decodes raw binary packets from the link layer up to the transport layer without copying the packet buffer.

### 2.1 Layer 2/3/4 Framing & Validation

1. **Ethernet Validation:** Packets with captured lengths under 14 bytes are counted as malformed and dropped. The 16-bit EtherType is extracted at byte offsets 12–13. Only IPv4 frames (`0x0800`) are accepted; ARP, LLDP, and IPv6 frames increment the `skipped_packets` counter and exit.

2. **IPv4 Parsing:** The minimum IPv4 frame length is 34 bytes (14 Ethernet + 20 minimum IPv4 header). The Internet Header Length (IHL) is masked from byte 14 (`ihl = bytes[14] & 0x0F`), computing the IP header byte length as $\text{IHL} \times 4$. The packet is verified against $\text{len} \ge 14 + \text{ip\_header\_len}$.

3. **Fragmentation Check:** The 16-bit fragment offset field at bytes 20–21 is checked. Packets with fragment offsets (`frag_field & 0x1FFF != 0`) are skipped to prevent mid-fragment tracking corruption.

4. **Transport Layer Routing:** At `transport_offset = 14 + ip_header_len`:

- **TCP (`protocol == 6`):** Validates $\text{len} \ge \text{transport\_offset} + 20$. Extracts source port (bytes 0–1), destination port (bytes 2–3), and 8-bit TCP flags from byte 13.

- **UDP (`protocol == 17`):** Validates $\text{len} \ge \text{transport\_offset} + 8$. Extracts source and destination ports, passing `flags = 0`.

- Other transport protocols increment `skipped_packets`.

---

## 3. Stateful Predictive Flow Tracking (`flow_tracker.cpp`)

Network flows are tracked bidirectionally across their operational lifetime.

### 3.1 Symmetrical 5-Tuple Canonical Hashing

To map forward and reverse directions of a connection to a single tracking record, the 5-tuple is sorted lexicographically:

$$\text{ip}_{min} = \min(\text{src\_ip}, \text{dest\_ip}), \quad \text{ip}_{max} = \max(\text{src\_ip}, \text{dest\_ip})$$

$$\text{port}_{min} =  \begin{cases}  \text{src\_port} & \text{if } \text{src\_ip} \le \text{dest\_ip} \\  \text{dest\_port} & \text{otherwise}  \end{cases}$$

$$\text{port}_{max} =  \begin{cases}  \text{dest\_port} & \text{if } \text{src\_ip} \le \text{dest\_ip} \\  \text{src\_port} & \text{otherwise}  \end{cases}$$

The fields are packed into two 64-bit keys and hashed using a 64-bit MurmurHash3 avalanche mixer:

$$k_1 = (\text{ip}_{min} \ll 32) \mid \text{ip}_{max}, \quad k_2 = (\text{port}_{min} \ll 24) \mid (\text{port}_{max} \ll 8) \mid \text{proto}$$

$$k_1 \leftarrow k_1 \oplus \left( k_2 + \text{0x9e3779b97f4a7c15ULL} + (k_1 \ll 6) + (k_1 \gg 2) \right)$$

$$k_1 \leftarrow (k_1 \oplus (k_1 \gg 33)) \times \text{0xff51afd7ed558ccdULL}$$

$$k_1 \leftarrow (k_1 \oplus (k_1 \gg 33)) \times \text{0xc4ceb9fe1a85ec53ULL}$$

$$\text{flow\_hash} = k_1 \oplus (k_1 \gg 33)$$

### 3.2 Predictive Coding Dynamics & Online EWMA

Rather than storing historical packet arrays, the flow tracker computes statistical invariants using Exponentially Weighted Moving Averages (EWMA). On the arrival of packet $k$ with length $S_k$ and inter-arrival time $\Delta t_k = t_k - t_{k-1}$:

1. **Feature Derivation:**

$$R_k = \frac{1000}{\Delta t_k} \quad (\text{rate in pkts/sec if } \Delta t_k > 0)$$

$$\text{Ratio}_{\text{byte}} = \frac{\text{bytes}_{\text{fwd}}}{\text{bytes}_{\text{rev}} + 1.0}, \quad \text{Ratio}_{\text{pkt}} = \frac{\text{pkts}_{\text{fwd}}}{\text{pkts}_{\text{rev}} + 1.0}$$

2. **Prediction Error Calculation:**

$$e_{\text{size}} = \vert{}S_k - \hat{S}_{k-1}\vert{}, \quad e_{\text{iat}} = \vert{}\Delta t_k - \widehat{\Delta t}_{k-1}\vert{}$$

$$e_{\text{rate}} = \vert{}R_k - \hat{R}_{k-1}\vert{}, \quad e_{\text{var}} = \vert{}(e_{\text{size}})^2 - \widehat{\text{Var}}_{k-1}\vert{}$$

$$e_{\text{ratio}} = \vert{}\text{Ratio}_{\text{byte}} - \widehat{\text{Ratio}}_{\text{byte}}\vert{}$$

### 3.3 Anomaly Drift-Locking

To prevent high-volume attacks (e.g., DoS floods) from polluting baseline models by forcing EWMA convergence toward malicious values, an anomaly distance metric is evaluated:

$$D_{\text{anomaly}} = \frac{e_{\text{size}}}{\hat{S}_{k-1} + 1.0} + \frac{e_{\text{iat}}}{\widehat{\Delta t}_{k-1} + 1.0} + \frac{e_{\text{ratio}}}{\widehat{\text{Ratio}}_{\text{byte}} + 1.0}$$

$$\alpha_{\text{eff}} = \begin{cases}  \alpha \times 0.05 & \text{if } D_{\text{anomaly}} > \text{DRIFT\_LOCK\_THRESHOLD} \ (3.5) \\ \alpha & \text{otherwise} \end{cases}$$

Statistical expectations are then updated:

$$\hat{\theta}_k = \hat{\theta}_{k-1} + \alpha_{\text{eff}} \cdot (\theta_k - \hat{\theta}_{k-1})$$

### 3.4 Concurrency Tracking & Garbage Collection

- **IP Concurrency Counters:** `active_ips` monitors active outbound flows per source IP, while `active_ip_pairs` tracks concurrent sessions between pairs of endpoints.

- **Eviction Strategy:** If active flows reach `MAX_ACTIVE_FLOWS` (default 500,000), a 32-entry bounded linear scan identifies and evicts the oldest flow.

- **Garbage Collection:** Every 1,000 packets, a sweep evaluates flows against `EXPIRATION_SECONDS` (default 60s). Expired flows commit their ground truth, decrement pair/host counters, and release associated SNN states. Idle episodes with no alerts for longer than `EPISODE_TIMEOUT_MS` (30s) are marked resolved.

---

## 4. Presynaptic Spike Encoding (`spike_encoder.cpp`)

Once a flow passes a 15-packet warmup window, normalized error values are passed to 6 presynaptic accumulator nodes:

```

+---------------+--------------------------------------+---------------------------------------------------+--------------------+
| Channel Index | Biological Interpretation | Mathematical Error Metric | Firing Threshold |
+---------------+--------------------------------------+---------------------------------------------------+--------------------+
| Channel 0 | Payload Size Discrepancy | (e_size / (expected_size + 1.0)) * 100 | Error > 1200 B |
| Channel 1 | Temporal Rhythm Divergence | (e_iat / (expected_iat + 1.0)) * 100 | Error > 250 ms |
| Channel 2 | Protocol State Anomaly | Static impulse on unexpected TCP SYN | SYN flag on est. |
| Channel 3 | Volumetric Rate Surge & Density | (e_rate / (expected_rate + 1.0)) * 100 + Pair Pen.| Error > 250 pps |
| Channel 4 | Structural Variance Surge | (e_var / (expected_var + 1.0)) * 100 | Error > 20000 B^2 |
| Channel 5 | Bidirectional Asymmetry Shift | e_ratio * 100 | Error > 5.0 ratio |
+---------------+--------------------------------------+---------------------------------------------------+--------------------+

```

### 4.1 Presynaptic Charge Integration

Each channel maintains an accumulator $A_c$ with discrete leaky decay:

$$A_c(t) = \left( A_c(t-1) \times 0.75 \right) + \min(e_c, \text{MAX\_IN}_c)$$

Where $\text{MAX\_IN}_3 = 25000.0$ (allowing large volumetric surges) and $\text{MAX\_IN}_{c \ne 3} = 10000.0$ (preventing single-packet behavioral errors from destabilizing synaptic weights).

When $A_c(t) \ge 1500.0$ (the presynaptic threshold), a spike payload $P = \min(\lfloor A_c(t) \rfloor, \text{MAX\_IN}_c)$ is injected into the neuromorphic reservoir, and $A_c(t)$ resets to zero.

---

## 5. Neuromorphic SNN Reservoir Core (`snn_core.cpp`)

The neuromorphic core maintains an 8-neuron Leaky Integrate-and-Fire (LIF) reservoir per flow.

```

Presynaptic Channels (6) Synaptic Matrix (6x8) Hidden Reservoir (8 LIF Neurons)
[Ch 0: Payload Size] ────► W[0][0..7] ─────┐
[Ch 1: Rhythm Diverg] ────► W[1][0..7] ─────┤
[Ch 2: Protocol Stat] ────► W[2][0..7] ─────┼───► [Neuron 0] (Decaying V_m) ──► Anomaly Callback
[Ch 3: Volumetric Rt] ────► W[3][0..7] ─────┼───► [Neuron 1] (Decaying V_m) ──► Anomaly Callback
[Ch 4: Struct Varian] ────► W[4][0..7] ─────┤ ...
[Ch 5: Asymmetry Sft] ────► W[5][0..7] ─────┴───► [Neuron 7] (Decaying V_m) ──► Anomaly Callback

```

### 5.1 Continuous-Time Membrane Potential Dynamics

Between consecutive spike arrivals at times $t_{k-1}$ and $t_k$, membrane potential leaks exponentially:

$$\Delta t_{\text{spike}} = \frac{t_k - t_{k-1}}{10^6} \quad (\text{seconds})$$

$$V_i(t_k^-) = V_i(t_{k-1}) \cdot \exp\left( -\frac{\Delta t_{\text{spike}}}{\tau} \right) \quad \forall i \in \{0, \dots, 7\}$$

Upon arrival of spike payload $P$ on channel $c$, synaptic charge is integrated:

$$V_i(t_k^+) = V_i(t_k^-) + \left( P \cdot W_{c, i} \right)$$

### 5.2 Dynamic Homeostatic Resistance

To prevent long-lived benign flows (such as high-speed file transfers or video streams) from continually firing anomalies, each flow tracks a homeostatic refractory penalty $H(t)$:

$$H(t_k^-) = H(t_{k-1}) \cdot \exp\left( -\frac{\Delta t_{\text{update}}}{60.0} \right)$$

$$\Theta_{\text{dynamic}} = \Theta_{\text{fire}} + H(t_k^-)$$

Where base threshold $\Theta_{\text{fire}} = 5000.0$.

When a neuron fires ($V_i \ge \Theta_{\text{dynamic}}$), its potential resets to $0.0$, and the homeostatic penalty increases:

$$H(t_k^+) = \min\left( H(t_k^-) + 500.0, \ 25000.0 \right)$$

### 5.3 Spike-Timing-Dependent Plasticity (STDP)

Synaptic weights are bounded within $[W_{\min}, W_{\max}] = [0.1, 5.0]$. When channel $c$ triggers a spike in hidden neuron $i$, an unsupervised Hebbian competitive learning step is applied:

1. **Long-Term Potentiation (LTP):** The causative synapse is reinforced:

$$W_{c, i} \leftarrow \min\left( W_{c, i} \times 1.05, \ 5.0 \right)$$

2. **Long-Term Depression (LTD):** Inactive non-causative channels for that neuron are depressed:

$$W_{j, i} \leftarrow \max\left( W_{j, i} \times 0.95, \ 0.1 \right) \quad \forall j \ne c$$

---

## 6. Threat Classification & Detection Architectures

`cppIDS` provides three modular decision paths to evaluate neuron firings.

### 6.1 Path A: Deterministic Contextual Scorer (`scorer.cpp`)

When a reservoir neuron fires, the raw potential overflow is scaled into an anomaly score:

$$\text{Score} = \left\lfloor \frac{V_i - \Theta_{\text{fire}}}{\Theta_{\text{fire}} \times 0.5} \times 100 \right\rfloor$$

If $\text{Score} > 45$, the flow's threat episode lifecycle updates:

1. **Episode Tracking:** Initializes an active episode on the first breach, or escalates if $\text{Score} > \text{last\_mag} + 15$.

2. **Context Classification:** Flow endpoints are inspected for known protocol profiles (DNS, NTP, DHCP, NetBIOS, Active Directory, Web, SSH).

3. **Suppression Matrix:**

- Multicast discovery (mDNS, SSDP, LLMNR) is dropped and homeostatically penalized.

- Standard infrastructure ports (DNS, NTP, DHCP, Enterprise RPC/SMB/LDAP, SSH) are dropped, suppressing benign background noise.

4. **Malicious Threat Confirmation:**

- **Volumetric Pair Flood:** Confirmed if the bidirectional active pair concurrency exceeds 60 flows on web or file-transfer ports with $\text{Score} > 500$.

- **Slow DoS:** Confirmed if temporal or variance anomaly scores exceed 850 with at least 2 persistent spikes.

- **Spike Count Persistence:** Confirmed if cumulative episode spikes exceed 10 (TCP) or 20 (UDP) with $\text{Score} > 600$.

```

```

Neuron Spike
│
▼
Score > 45 Alert? ──── No ────► Ignore / Sub-threshold
│ Yes
▼
Context Matches? (DNS/NTP/Enterprise)
├─── Yes (and not Pair Flood) ───► Suppress & Apply Homeostasis
│
└─── No (or Pair Flood Exception)
│
▼
Confirmation Criteria Check
├── Pair Concurrency > 60 & Score > 500 ──────► CONFIRM_PAIR_FLOOD
├── Slow DoS: Ch 1/4 & Score > 850 ───────────► CONFIRM_SLOW_DOS
└── Spike Count >= 10/20 & Score > 600 ───────► CONFIRM_SPIKE_COUNT

```

```

### 6.2 Path B: Neuromorphic Spiking Readout (`snn_readout.cpp`)

Path B provides a secondary, fully spiking output layer consisting of a single downstream **Threat LIF Neuron** driven by the 8 hidden reservoir neurons:

- **Feed-Forward Inhibition (FFI):** When benign context (DNS, NTP, DHCP, Enterprise RPC) is detected, an Inhibitory Post-Synaptic Potential ($\text{IPSP} = 500.0$) is injected directly into the Threat LIF neuron, hyperpolarizing its membrane and preventing false alarms.

- **Eligibility Traces & Reward-Modulated STDP (R-STDP):** Each input synapse tracks an eligibility trace $e_i$ that increments upon hidden neuron firing and decays over time:

$$e_i \leftarrow \min(e_i + 1.0, \ 10.0)$$

- **Supervisory Reinforcement:** When ground truth is resolved at flow termination:

- _False Negative (Missed Attack):_ Reinforces active synapses using potentiation rate $\eta_{\text{pos}} = 0.02$:

$$W_i \leftarrow \min(W_i + \eta_{\text{pos}} \cdot e_i, \ 200.0)$$

- _False Positive (Benign Alarm):_ Depresses active synapses using depression rate $\eta_{\text{neg}} = 0.0005$ only if not already suppressed by FFI:

$$W_i \leftarrow \max(W_i - \eta_{\text{neg}} \cdot e_i, \ 5.0)$$

### 6.3 Path C: Batch Regularized Logistic Regression Readout (`logistic_model.cpp`)

Path C extracts an 11-dimensional feature vector $\mathbf{x} \in \mathbb{R}^{11}$ from each flow record:

$$\mathbf{x} = \Big[ \text{Mag}_0, \dots, \text{Mag}_5, \ \text{Spikes}_{\text{ep}}, \ \text{Density}_{\text{pair}}, \ \mathbb{I}_{\text{web}}, \ \mathbb{I}_{\text{dns}}, \ \mathbb{I}_{\text{enterprise}} \Big]^T$$

1. **Z-Score Standardization:** Feature dimensions are scaled using running sample statistics:

$$\hat{x}_j = \frac{x_j - \mu_j}{\sigma_j + 10^{-6}}$$

2. **Inference Probability:**

$$P(\text{Malicious} \mid \mathbf{x}) = \sigma\left( b + \sum_{j=0}^{10} w_j \hat{x}_j \right), \quad \sigma(z) = \frac{1}{1 + e^{-z}}$$

If $P > 0.50$, the flow is flagged as a confirmed threat; otherwise, homeostasis is applied.

3. **Balanced Cross-Entropy Optimization with L2 Regularization:**
   To address severe class imbalances between attack and benign flows, class weights are applied during batch training:

$$w_{\text{pos}} = \frac{N}{2 N_{\text{pos}}}, \quad w_{\text{neg}} = \frac{N}{2 N_{\text{neg}}}$$

$$L(\mathbf{w}, b) = -\frac{1}{N} \sum_{k=1}^N c_k \Big[ y_k \ln(p_k) + (1 - y_k) \ln(1 - p_k) \Big] + \frac{\lambda}{2} \Vert{}\mathbf{w}\Vert{}_2^2$$

### 6.4 Path D: Deep Learning Feature Extraction Bridge (SOTA Benchmarking)

To facilitate direct performance comparisons against standard deep learning architectures (e.g., LSTMs, CNNs) without incurring the massive latency and memory penalties of Python-based packet inspection, `cppIDS` provides a direct telemetry bridge.

When the `--export-features` flag is active, the exact 11-dimensional feature vector $\mathbf{x} \in \mathbb{R}^{11}$ extracted for the Logistic Regression readout (Path C) is written to a contiguous CSV file upon flow expiration. This guarantees that offline PyTorch/TensorFlow models evaluate the exact same prediction errors, temporal rhythms, and neuromorphic spike accumulations observed by the native C++ engine, ensuring mathematically rigorous baseline comparisons.

---

## 7. Model Hydration, Serialization & Transfer Learning

`cppIDS` supports exporting, importing, and transferring learned weights across all modules.

```

```

                              OFFLINE TRAINING / CALIBRATION

```

+────────────────────────────+ +─────────────────────────────────+
| eval_harness (--train) | ───────────────► | Stratified Export File (.bin) |
| - Captures true-positives | | - 48 float weights (6x8 matrix) |
| - Stratified reason bins | +─────────────────────────────────+
+────────────────────────────+ │
▼
INSPECTION & HYDRATION AT EDGE
│
┌────────────────────────────────┴────────────────────────────────┐
▼ ▼
+─────────────────────────────+ +─────────────────────────────+
| Test Mode (--test) | | Transfer Mode (--transfer) |
| - Weights frozen | | - Baseline loaded |
| - STDP disabled | | - Deterministic execution |
| - Deterministic execution | | - Online domain adaptation |
+─────────────────────────────+ +─────────────────────────────+

```

### 7.1 Reservoir Weight Stratification & Export

During `--train` execution, synaptic matrices that successfully trigger true-positive detections are accumulated into 5 stratified bins based on their confirmation reason (`CONFIRM_PAIR_FLOOD`, `CONFIRM_SLOW_DOS`, etc.). Upon capture completion, the weights are averaged across active strata:

$$W_{c, i}^{\text{export}} = \frac{1}{K_{\text{valid}}} \sum_{r=0}^4 \left( \frac{1}{N_r} \sum_{k=1}^{N_r} W_{c, i}^{(k, r)} \right)$$

This stratification prevents high-frequency volumetric attacks from dominating the learned synaptic weights of low-rate attacks.

---

## 8. Memory Management & Real-Time Performance Constraints

`cppIDS` is designed for strict deterministic execution on edge systems:

1. **Flat Map Architecture:** `robin_hood::unordered_flat_map` provides hash table lookups with contiguous array storage, minimizing cache misses during packet processing.

2. **Fixed Memory Working Set:** The total heap allocation remains bounded:

$$\text{RAM}_{\text{total}} \approx \left( N_{\text{flows}} \times \left( \text{sizeof}(\text{FlowRecord}) + \text{sizeof}(\text{SNNState}) + \text{sizeof}(\text{EncoderNodes}) \right) \right) + \text{TelemetryBuffers}$$

At 500,000 concurrent flows, the working-set memory stabilizes between **107 MB and 139 MB**, avoiding out-of-memory crashes on embedded devices. 3. **Sub-Microsecond Latency Profile:** With zero runtime memory allocation in the packet path, the per-packet processing pipeline (decoding $\to$ EWMA update $\to$ spike leak $\to$ LIF integration) achieves:

- **P50 (Median) Latency:** $\le 1 \ \mu\text{s}$
- **P99 Latency:** $\le 5 \ \mu\text{s}$
- **Throughput:** $80,000 - 120,000 \ \text{packets per second (PPS)}$ on single-threaded x86_64 commodity hardware.
