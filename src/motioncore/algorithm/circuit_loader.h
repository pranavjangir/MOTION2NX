// MIT License
//
// Copyright (c) 2020 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <filesystem>
#include <unordered_map>
#include <vector>

#include "algorithm_description.h"

namespace MOTION {

enum class CircuitFormat {
  ABY,
  Bristol,
  BristolFashion,
};

class CircuitLoader {
 public:
  CircuitLoader();
  ~CircuitLoader();
  const ENCRYPTO::AlgorithmDescription& load_circuit(std::string name, CircuitFormat);
  const ENCRYPTO::AlgorithmDescription& load_relu_circuit(std::size_t bit_size);
  const ENCRYPTO::AlgorithmDescription& load_gt_circuit(std::size_t bit_size,
                                                        bool depth_optimized = false);
  const ENCRYPTO::AlgorithmDescription& load_eq_circuit(std::size_t bit_size);
  const ENCRYPTO::AlgorithmDescription& load_gtmux_circuit(std::size_t bit_size,
                                                           bool depth_optimized = false);
  const ENCRYPTO::AlgorithmDescription& load_tree_circuit(const std::string& algo_name,
                                                          std::size_t bit_size,
                                                          std::size_t num_inputs);
  const ENCRYPTO::AlgorithmDescription& load_maxpool_circuit(std::size_t bit_size,
                                                             std::size_t num_inputs,
                                                             bool depth_optimized = false);

 private:
  std::vector<std::filesystem::path> circuit_search_path_;
  std::unordered_map<std::string, ENCRYPTO::AlgorithmDescription> algo_cache_;
};

}  // namespace MOTION
