import os
import time

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

# Attempt to load optional diagnostic and neuromorphic libraries
try:
    import psutil
except ImportError:
    psutil = None

try:
    import snntorch as snn
    from snntorch import surrogate
except ImportError:
    snn = None

# ==========================================
# 1. NEURAL ARCHITECTURES
# ==========================================

""" @brief Standard Long Short-Term Memory (LSTM) baseline for flow classification.
    Maintains recurrent hidden states to capture long-term temporal dependencies in data. """


class FlowLSTM(nn.Module):
    def __init__(self, input_dim=11, hidden_dim=64, num_layers=2):
        super().__init__()
        # batch_first=True expects tensors of shape (Batch, Sequence, Features)
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)

    def forward(self, x):
        # Treat the 11-dimensional feature vector as a sequence of length 1
        x = x.unsqueeze(1)
        out, _ = self.lstm(x)
        # Extract the hidden state of the final time step and map to a single logit
        return self.fc(out[:, -1, :]).squeeze(-1)


""" @brief 1D Convolutional Neural Network baseline.
    Extracts spatial/structural patterns across the 11-dimensional feature vector. """


class FlowCNN(nn.Module):
    def __init__(self, input_dim=11):
        super().__init__()
        # Sweeps a size-3 kernel across the 11 features to find local feature correlations
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=16, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.pool = nn.MaxPool1d(2)
        # Downsample dimensions via MaxPool before the fully connected classification head
        self.fc = nn.Linear(16 * (input_dim // 2), 1)

    def forward(self, x):
        # Reshape input to (Batch, Channels=1, Length=Features)
        x = x.unsqueeze(1)
        x = self.pool(self.relu(self.conv1(x)))
        # Flatten the convolutional maps for the dense readout layer
        x = x.view(x.size(0), -1)
        return self.fc(x).squeeze(-1)


""" @brief Neuromorphic Hybrid Architecture (CNN-SNN).
    Fuses spatial convolution with temporal Leaky Integrate-and-Fire (LIF) neurons.
    Trained via Backpropagation Through Time (BPTT) using surrogate gradients. """


class HybridCNNSNN(nn.Module):
    def __init__(self, input_dim=11, num_steps=5):
        super().__init__()
        if snn is None:
            raise ImportError("snntorch is required. Run: pip install snntorch")
        self.num_steps = num_steps

        # Fast sigmoid surrogate gradient allows backprop through non-differentiable spikes
        spike_grad = surrogate.fast_sigmoid(slope=25)

        self.conv1 = nn.Conv1d(1, 16, kernel_size=3, padding=1)
        self.lif1 = snn.Leaky(beta=0.9, spike_grad=spike_grad)
        self.pool = nn.MaxPool1d(2)

        self.fc = nn.Linear(16 * (input_dim // 2), 1)
        self.lif2 = snn.Leaky(beta=0.9, spike_grad=spike_grad)

    def forward(self, x):
        x = x.unsqueeze(1)

        # Initialize decaying membrane potentials for the LIF neuron layers
        mem1 = self.lif1.init_leaky()
        mem2 = self.lif2.init_leaky()
        mem2_rec = []

        # Simulate neuromorphic dynamics over discrete time steps
        for _ in range(self.num_steps):
            cur1 = self.pool(self.conv1(x))
            spk1, mem1 = self.lif1(cur1, mem1)

            # Map hidden layer spikes to the output Threat LIF neuron
            cur2 = self.fc(spk1.view(spk1.size(0), -1))
            spk2, mem2 = self.lif2(cur2, mem2)

            # Record membrane voltage to use as the differentiable logit for BCE Loss
            mem2_rec.append(mem2)

        # Average the membrane potential across all simulation steps
        return torch.stack(mem2_rec).mean(dim=0).squeeze(-1)


# ==========================================
# 2. DATA UTILITIES
# ==========================================

""" @brief Queries the OS for the current process RAM utilization (in Megabytes) """


def get_process_ram_mb():
    if psutil:
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    return 0.0


""" @brief Parses the cppIDS exported CSV, isolating the 11 continuous/categorical features
           from the networking identifiers (IPs, Ports). """


def extract_features(filepath):
    if not os.path.exists(filepath):
        return None, None
    df = pd.read_csv(filepath)

    feature_cols = [
        "ch0_size",
        "ch1_iat",
        "ch2_proto",
        "ch3_rate",
        "ch4_var",
        "ch5_asym",
        "spike_count",
        "pair_density",
        "is_web",
        "is_dns",
        "is_ent",
    ]

    # Safely extract target columns or fallback to dropping routing features
    if all(col in df.columns for col in feature_cols):
        X = df[feature_cols].values
    else:
        X = df.drop(
            columns=["src_ip", "dst_ip", "src_port", "dst_port", "proto", "label"]
        ).values

    y = df["label"].values.astype(np.float32)
    return X, y


""" @brief Executes the PyTorch training loop over the provided DataLoader.
           Uses BCEWithLogitsLoss to handle binary cross-entropy on raw, unscaled logits. """


def train_model(model, train_loader, pos_weight, device, epochs=5, lr=0.001):
    model.train()

    # pos_weight heavily penalizes false negatives in highly imbalanced datasets
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight.to(device))
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    for epoch in range(1, epochs + 1):
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)

            optimizer.zero_grad()
            logits = model(X_batch)
            loss = criterion(logits, y_batch)

            loss.backward()
            optimizer.step()


""" @brief Benchmarks model inference speed, memory footprint, and classification metrics.
           Executes a warmup pass to initialize CUDA caches before starting the timer. """


def evaluate_model(
    model, X_test, y_test, scaler, device, arch_name, config_name, dataset_name
):
    model.eval()

    # Apply standard zero-mean, unit-variance scaling derived from the training set
    X_scaled = scaler.transform(X_test).astype(np.float32)
    test_loader = DataLoader(
        TensorDataset(torch.from_numpy(X_scaled), torch.from_numpy(y_test)),
        batch_size=2048,
        shuffle=False,
    )

    all_preds = []
    total_samples = 0

    # 1. Warmup Pass (Prevents CUDA initialization overhead from corrupting latency metrics)
    with torch.no_grad():
        for X_batch, _ in test_loader:
            _ = model(X_batch.to(device))
            break

    # 2. Timing block start
    if device.type == "cuda":
        torch.cuda.synchronize()
    start_time = time.perf_counter()

    # 3. Execution loop
    with torch.no_grad():
        for X_batch, _ in test_loader:
            X_batch = X_batch.to(device)
            logits = model(X_batch)

            # Apply Sigmoid activation and threshold at 0.5 for binary classification
            preds = (torch.sigmoid(logits) >= 0.5).cpu().numpy().astype(int)
            all_preds.extend(preds)
            total_samples += X_batch.size(0)

    # 4. Timing block end
    if device.type == "cuda":
        torch.cuda.synchronize()
    elapsed = time.perf_counter() - start_time

    # Calculate hardware performance metrics
    avg_latency = (elapsed / total_samples) * 1_000_000 if total_samples > 0 else 0
    throughput = total_samples / elapsed if elapsed > 0 else 0
    ram = get_process_ram_mb()

    # Calculate statistical classification metrics
    y_pred = np.array(all_preds)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    precision = (tp / (tp + fp) * 100.0) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )
    fpr = (fp / (fp + tn) * 100.0) if (fp + tn) > 0 else 0.0

    # Return structured dictionary matching tabulation.md format
    return {
        "Architecture": f"**{arch_name}**",
        "Configuration": config_name,
        "Dataset": dataset_name,
        "F1": f1,
        "Recall": recall,
        "Precision": precision,
        "FPR": fpr,
        "TP": int(tp),
        "FP": int(fp),
        "FN": int(fn),
        "Latency": avg_latency,
        "Throughput": throughput,
        "RAM": ram,
    }


# ==========================================
# 3. EXPERIMENT PIPELINE
# ==========================================

""" @brief Coordinates the end-to-end evaluation suite across single-domain
           and multi-domain plasticity configurations. """


def run_suite():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[SYSTEM] Hardware Accelerator: {device}")

    # Index available datasets generated by cppIDS eval_harness
    datasets = {
        "Wednesday": extract_features("dl_wednesday.csv"),
        "Thurs Afternoon": extract_features("dl_thurs_afternoon.csv"),
        "Thurs Morning": extract_features("dl_thurs_morning.csv"),
        "Combined": extract_features("dl_combined.csv"),
    }

    results = []

    # Helper factory to reset model weights between training regimes
    def build_models():
        return [
            ("Flow LSTM", FlowLSTM(input_dim=11, hidden_dim=64, num_layers=2)),
            ("Flow 1D-CNN", FlowCNN(input_dim=11)),
            ("CNN-SNN Hybrid", HybridCNNSNN(input_dim=11, num_steps=5)),
        ]

    # -------------------------------------------------------------
    # REGIME 1: Test (Wednesday Weights)
    # Goal: Evaluate zero-shot generalization of models trained purely on DoS traffic
    # -------------------------------------------------------------
    if datasets["Wednesday"][0] is not None:
        print("\n" + "=" * 80)
        print(" TRAINING ON WEDNESDAY (Single-Domain Plasticity)")
        print("=" * 80)
        X_wed, y_wed = datasets["Wednesday"]
        scaler_wed = StandardScaler()

        # Stratified split ensures anomaly ratio is preserved in training
        X_train_w, X_test_w, y_train_w, y_test_w = train_test_split(
            X_wed, y_wed, test_size=0.2, random_state=42, stratify=y_wed
        )
        X_train_w_scaled = scaler_wed.fit_transform(X_train_w).astype(np.float32)

        # Dynamically scale loss weighting based on class imbalance
        pos_weight_w = torch.tensor(
            [(y_train_w == 0).sum() / max(1, (y_train_w == 1).sum())],
            dtype=torch.float32,
        )

        train_loader_w = DataLoader(
            TensorDataset(
                torch.from_numpy(X_train_w_scaled), torch.from_numpy(y_train_w)
            ),
            batch_size=2048,
            shuffle=True,
        )

        for arch_name, model in build_models():
            print(f"  Fitting {arch_name} on Wednesday...")
            model = model.to(device)
            train_model(model, train_loader_w, pos_weight_w, device, epochs=5)

            # Evaluate: In-Domain Test
            results.append(
                evaluate_model(
                    model,
                    X_test_w,
                    y_test_w,
                    scaler_wed,
                    device,
                    arch_name,
                    "Test (Wednesday Weights)",
                    "Wednesday",
                )
            )

            # Evaluate: Zero-Shot Lateral Infiltration Test
            if datasets["Thurs Afternoon"][0] is not None:
                X_ta, y_ta = datasets["Thurs Afternoon"]
                results.append(
                    evaluate_model(
                        model,
                        X_ta,
                        y_ta,
                        scaler_wed,
                        device,
                        arch_name,
                        "Test (Wednesday Weights)",
                        "Thurs Afternoon",
                    )
                )

            # Evaluate: Zero-Shot Web Attack Test
            if datasets["Thurs Morning"][0] is not None:
                X_tm, y_tm = datasets["Thurs Morning"]
                results.append(
                    evaluate_model(
                        model,
                        X_tm,
                        y_tm,
                        scaler_wed,
                        device,
                        arch_name,
                        "Test (Wednesday Weights)",
                        "Thurs Morning",
                    )
                )

    # -------------------------------------------------------------
    # REGIME 2: Test (Combined Weights)
    # Goal: Evaluate performance when exposed to diverse multi-domain pre-training
    # -------------------------------------------------------------
    if datasets["Combined"][0] is not None:
        print("\n" + "=" * 80)
        print(" TRAINING ON COMBINED (Multi-Domain Plasticity)")
        print("=" * 80)
        X_comb, y_comb = datasets["Combined"]
        scaler_comb = StandardScaler()

        X_train_c, X_test_c, y_train_c, y_test_c = train_test_split(
            X_comb, y_comb, test_size=0.2, random_state=42, stratify=y_comb
        )
        X_train_c_scaled = scaler_comb.fit_transform(X_train_c).astype(np.float32)

        pos_weight_c = torch.tensor(
            [(y_train_c == 0).sum() / max(1, (y_train_c == 1).sum())],
            dtype=torch.float32,
        )

        train_loader_c = DataLoader(
            TensorDataset(
                torch.from_numpy(X_train_c_scaled), torch.from_numpy(y_train_c)
            ),
            batch_size=2048,
            shuffle=True,
        )

        for arch_name, model in build_models():
            print(f"  Fitting {arch_name} on Combined...")
            model = model.to(device)
            train_model(model, train_loader_c, pos_weight_c, device, epochs=5)

            # Evaluate: Individual Isolated Datasets
            if datasets["Wednesday"][0] is not None:
                X_w_full, y_w_full = datasets["Wednesday"]
                results.append(
                    evaluate_model(
                        model,
                        X_w_full,
                        y_w_full,
                        scaler_comb,
                        device,
                        arch_name,
                        "Test (Combined Weights)",
                        "Wednesday",
                    )
                )

            if datasets["Thurs Afternoon"][0] is not None:
                X_ta, y_ta = datasets["Thurs Afternoon"]
                results.append(
                    evaluate_model(
                        model,
                        X_ta,
                        y_ta,
                        scaler_comb,
                        device,
                        arch_name,
                        "Test (Combined Weights)",
                        "Thurs Afternoon",
                    )
                )

            if datasets["Thurs Morning"][0] is not None:
                X_tm, y_tm = datasets["Thurs Morning"]
                results.append(
                    evaluate_model(
                        model,
                        X_tm,
                        y_tm,
                        scaler_comb,
                        device,
                        arch_name,
                        "Test (Combined Weights)",
                        "Thurs Morning",
                    )
                )

            # Evaluate: Combined Holdout Split
            results.append(
                evaluate_model(
                    model,
                    X_test_c,
                    y_test_c,
                    scaler_comb,
                    device,
                    arch_name,
                    "Test (Combined Weights)",
                    "Combined Split",
                )
            )

    # Print tabulated output directly compatible with Markdown documentation
    print("\n" + "=" * 110)
    print("                      DEEP LEARNING SOTA BENCHMARK TABLE")
    print("=" * 110)
    print(
        "| Architecture | Configuration / Mode | Dataset | F1-Score | Recall (DR) | Precision | FPR | TP | FP | FN | Avg Latency | Throughput | RAM |"
    )
    print(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    )
    for r in results:
        print(
            f"| {r['Architecture']} | {r['Configuration']} | {r['Dataset']} | {r['F1']:.2f}% | {r['Recall']:.2f}% | {r['Precision']:.2f}% | {r['FPR']:.2f}% | {r['TP']:,} | {r['FP']:,} | {r['FN']:,} | {r['Latency']:.2f} μs | {int(r['Throughput']):,} PPS | {int(r['RAM'])} MB |"
        )


if __name__ == "__main__":
    run_suite()
