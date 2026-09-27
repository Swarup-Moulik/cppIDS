#include "logistic_model.h"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>

// Global states managing the logistic readout subsystem
static bool g_lr_enabled = false;
static bool g_lr_collecting = false;
static LogisticModel g_global_model;
static std::vector<TrainingExample> g_training_data;

/* @brief Allocates buffer capacity for collecting flow training examples */
void lr_readout_init() {
  g_training_data.clear();
  g_training_data.reserve(500000);
}

/* @brief Updates operational state and training data collection flags */
void lr_readout_set_mode(bool enabled, bool is_collecting) {
  g_lr_enabled = enabled;
  g_lr_collecting = is_collecting;
}

/* @brief Checks whether logistic regression scoring is active */
bool lr_readout_is_enabled() { return g_lr_enabled; }

/* @brief Checks whether incoming flow records are being collected for training */
bool lr_readout_is_collecting() { return g_lr_collecting; }

/* @brief Provides access to the static global LogisticModel instance */
LogisticModel &lr_get_model() { return g_global_model; }

/* @brief Provides access to the accumulated flow training dataset */
std::vector<TrainingExample> &lr_get_training_buffer() {
  return g_training_data;
}

/* @brief Numerically stable standard logistic sigmoid activation function */
static inline float sigmoid(float z) {
  if (z > 20.0f)
    return 1.0f;
  if (z < -20.0f)
    return 0.0f;
  return 1.0f / (1.0f + std::exp(-z));
}

/* @brief Calculates population mean and standard deviation per feature and scales data */
void LogisticModel::standardize(std::vector<TrainingExample> &data) {
  size_t n = data.size();
  if (n == 0)
    return;

  for (size_t i = 0; i < LR_DIM; ++i) {
    double sum = 0.0;
    for (const auto &ex : data)
      sum += ex.features[i];
    feat_mean_[i] = static_cast<float>(sum / n);

    double sq = 0.0;
    for (const auto &ex : data) {
      double d = ex.features[i] - feat_mean_[i];
      sq += d * d;
    }
    feat_std_[i] = static_cast<float>(std::sqrt(sq / n));
    // Guard against division by zero for constant features
    if (feat_std_[i] < 1e-6f)
      feat_std_[i] = 1.0f;

    // Apply Z-score transformation
    for (auto &ex : data) {
      ex.features[i] = (ex.features[i] - feat_mean_[i]) / feat_std_[i];
    }
  }
}

/* @brief Normalizes an arbitrary raw feature array using the trained baseline statistics */
std::array<float, LR_DIM>
LogisticModel::apply_standardize(const std::array<float, LR_DIM> &raw) const {
  std::array<float, LR_DIM> out{};
  for (size_t i = 0; i < LR_DIM; ++i) {
    out[i] = (raw[i] - feat_mean_[i]) / feat_std_[i];
  }
  return out;
}

/* @brief Trains model parameters using balanced cross-entropy loss and gradient descent */
void LogisticModel::fit(std::vector<TrainingExample> &data, int epochs,
                        float lr, float l2) {
  if (data.empty()) {
    std::cerr << "[LR ERROR] Cannot fit model on empty training buffer.\n";
    return;
  }

  // Standardize dataset before gradient updates
  standardize(data);

  // Compute balanced class weights to prevent majority class dominance
  size_t n_pos = 0;
  for (const auto &ex : data) {
    if (ex.label)
      n_pos++;
  }
  size_t n_neg = data.size() - n_pos;

  float w_pos =
      n_pos > 0 ? static_cast<float>(data.size()) / (2.0f * n_pos) : 1.0f;
  float w_neg =
      n_neg > 0 ? static_cast<float>(data.size()) / (2.0f * n_neg) : 1.0f;

  std::cout << "[LR TRAIN] Total Flows=" << data.size() << " | Pos=" << n_pos
            << " | Neg=" << n_neg << " | w_pos=" << w_pos
            << " | w_neg=" << w_neg << "\n";

  // Reset model parameters
  weights_.fill(0.0f);
  bias_ = 0.0f;

  float n = static_cast<float>(data.size());

  // Run gradient descent optimization
  for (int epoch = 0; epoch < epochs; ++epoch) {
    std::array<float, LR_DIM> grad_w{};
    float grad_b = 0.0f;
    double total_loss = 0.0;

    for (const auto &ex : data) {
      float logit = bias_;
      for (size_t i = 0; i < LR_DIM; ++i) {
        logit += weights_[i] * ex.features[i];
      }
      float pred = sigmoid(logit);
      float target = ex.label ? 1.0f : 0.0f;
      float cw = ex.label ? w_pos : w_neg;
      float err = cw * (pred - target);

      // Accumulate batch weight and bias gradients
      for (size_t i = 0; i < LR_DIM; ++i) {
        grad_w[i] += err * ex.features[i];
      }
      grad_b += err;

      // Track cross-entropy loss with numerical bounds in double precision
      double p_dbl = static_cast<double>(std::clamp(pred, 1e-7f, 1.0f - 1e-7f));
      double target_dbl = static_cast<double>(target);
        
      total_loss +=
          static_cast<double>(-cw) * (target_dbl * std::log(p_dbl) + (1.0 - target_dbl) * std::log(1.0 - p_dbl));
    }

    // Apply weight updates including L2 weight decay regularization
    for (size_t i = 0; i < LR_DIM; ++i) {
      float g = (grad_w[i] / n) + (l2 * weights_[i]);
      weights_[i] -= lr * g;
    }
    bias_ -= lr * (grad_b / n);

    if (epoch % 20 == 0 || epoch == epochs - 1) {
      std::cout << "  Epoch " << epoch << " | Loss: " << (total_loss / n)
                << "\n";
    }
  }
}

/* @brief Computes predicted probability of malicious threat using normalized features */
float LogisticModel::predict_proba(const std::array<float, LR_DIM> &raw) const {
  auto x = apply_standardize(raw);
  float logit = bias_;
  for (size_t i = 0; i < LR_DIM; ++i) {
    logit += weights_[i] * x[i];
  }
  return sigmoid(logit);
}

/* @brief Serializes model coefficients and feature scaling baselines to disk */
bool LogisticModel::save(const std::string &path) const {
  std::ofstream out(path, std::ios::binary);
  if (!out)
    return false;
  out.write(reinterpret_cast<const char *>(weights_.data()),
            sizeof(float) * LR_DIM);
  out.write(reinterpret_cast<const char *>(&bias_), sizeof(float));
  out.write(reinterpret_cast<const char *>(feat_mean_.data()),
            sizeof(float) * LR_DIM);
  out.write(reinterpret_cast<const char *>(feat_std_.data()),
            sizeof(float) * LR_DIM);
  return out.good();
}

/* @brief Restores model coefficients and feature scaling baselines from disk */
bool LogisticModel::load(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return false;
  in.read(reinterpret_cast<char *>(weights_.data()), sizeof(float) * LR_DIM);
  in.read(reinterpret_cast<char *>(&bias_), sizeof(float));
  in.read(reinterpret_cast<char *>(feat_mean_.data()), sizeof(float) * LR_DIM);
  in.read(reinterpret_cast<char *>(feat_std_.data()), sizeof(float) * LR_DIM);
  return in.good();
}

/* @brief Outputs formatted feature weights and standardization metrics */
void LogisticModel::print_weights() const {
  const char *names[LR_DIM] = {"Ch0_Payload", "Ch1_Rhythm",   "Ch2_Protocol",
                               "Ch3_Rate",    "Ch4_Variance", "Ch5_Asym",
                               "SpikeCount",  "PairDensity",  "IsWeb",
                               "IsDNS",       "IsEnterprise"};
  std::cout << "\n[LOGISTIC REGRESSION READOUT PARAMETERS]\n";
  std::cout << "  Bias: " << bias_ << "\n";
  for (size_t i = 0; i < LR_DIM; ++i) {
    std::cout << "  " << names[i] << ": " << weights_[i]
              << " (mean=" << feat_mean_[i] << ", std=" << feat_std_[i]
              << ")\n";
  }
  std::cout << "\n";
}
