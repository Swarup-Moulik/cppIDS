#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

/* @brief Dimensionality of the input feature vector for logistic readout */
constexpr size_t LR_DIM = 11;

/* @brief Represents a single labeled training sample extracted from flow
 * features */
struct TrainingExample {
  std::array<float, LR_DIM> features; // Extracted feature vector
  bool label; // Ground truth label: true for attack, false for benign
};

/* @brief Regularized Logistic Regression model for secondary classification
 * readout */
class LogisticModel {
public:
  /* @brief Trains model parameters using mini-batch gradient descent with L2
   * regularization */
  void fit(std::vector<TrainingExample> &data, int epochs, float lr, float l2);

  /* @brief Computes predicted threat probability for a raw feature array using
   * learned weights */
  float predict_proba(const std::array<float, LR_DIM> &raw_features) const;

  /* @brief Serializes model weights, bias, and standardization vectors to a
   * binary file */
  bool save(const std::string &path) const;

  /* @brief Deserializes model weights, bias, and standardization vectors from a
   * binary file */
  bool load(const std::string &path);

  /* @brief Prints model coefficients and normalization baselines to stdout */
  void print_weights() const;

private:
  std::array<float, LR_DIM> weights_{}; // Synaptic/feature weights
  float bias_ = 0.0f;                   // Classification intercept bias
  std::array<float, LR_DIM>
      feat_mean_{}; // Feature means for Z-score standardization
  std::array<float, LR_DIM>
      feat_std_{}; // Feature standard deviations for Z-score standardization

  /* @brief Computes feature means and standard deviations across the dataset
   * and standardizes in-place */
  void standardize(std::vector<TrainingExample> &data);

  /* @brief Applies precomputed mean and standard deviation scaling to an
   * incoming feature array */
  std::array<float, LR_DIM>
  apply_standardize(const std::array<float, LR_DIM> &raw) const;
};

/* @brief Initializes memory buffers for the logistic regression readout */
void lr_readout_init();

/* @brief Sets readout execution mode flags for inference and sample collection
 */
void lr_readout_set_mode(bool enabled, bool is_collecting);

/* @brief Returns true if logistic regression readout integration is enabled */
bool lr_readout_is_enabled();

/* @brief Returns true if the system is currently gathering training examples
 * into memory */
bool lr_readout_is_collecting();

/* @brief Returns a reference to the global LogisticModel singleton */
LogisticModel &lr_get_model();

/* @brief Returns a reference to the in-memory training dataset buffer */
std::vector<TrainingExample> &lr_get_training_buffer();
