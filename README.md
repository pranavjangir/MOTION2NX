# MPClan -- Protocol Suite for Privacy-Conscious Computations

This software is the preliminary version of the semi-honest MPC protocol of MPClan which builds on the MOTION2NX framework available at https://github.com/encryptogroup/MOTION2NX. Our implementation currently includes basic MPC protocols for input sharing, addition, multiplication and output reconstruction. The support for securely performing neural network inference is also present. For this, building blocks required to evaluate neural networks have been implemented. 

We re-iterate that the code is still in its initial stages and under development.


## Build Instructions


This software was developed and tested in the following environment (it might
also work with older versions):

- [Arch Linux](https://archlinux.org/)
- [GCC 11.1.0](https://gcc.gnu.org/) or [Clang/LLVM 12.0.1](https://clang.llvm.org/)
- [CMake 3.21.4](https://cmake.org/)
- [Boost 1.76.0](https://www.boost.org/)
- [OpenSSL 1.1.1.l](https://openssl.org/)
- [Eigen 3.4.0](https://eigen.tuxfamily.org/)
- [fmt 8.0.1](https://github.com/fmtlib/fmt)
- [flatbuffers 2.0.0](https://github.com/google/flatbuffers)
- [GoogleTest 1.11.0 (optional, for tests, build automatically)](https://github.com/google/googletest)
- [Google Benchmark 1.6.0 (optional, for some benchmarks, build automatically)](https://github.com/google/benchmark)
- [HyCC (optional, for the HyCCAdapter)](https://gitlab.com/securityengineering/HyCC)
- [ONNX 1.10.2 (optional, for the ONNXAdapter)](https://github.com/onnx/onnx)

The build system downloads and builds GoogleTest and Benchmark if required.
It also tries to download and build Boost, fmt, and flatbuffers if it cannot
find these libraries in the system.

The framework can for example be compiled as follows:
```
$ CC=gcc CXX=g++ cmake \
    -B build_debwithrelinfo_gcc \
    -DCMAKE_BUILD_TYPE=DebWithRelInfo \
    -DMOTION_BUILD_EXE=On \
    -DMOTION_BUILD_TESTS=On \
    -DMOTION_USE_AVX=AVX2
$ cmake --build build_debwithrelinfo_gcc
```
Explanation of the flags:

- `CC=gcc CXX=g++`: select GCC as compiler
- `-B build_debwithrelinfo_gcc`: create a build directory
- `-DCMAKE_BUILD_TYPE=DebWithRelInfo`: compile with optimization and also add
  debug symbols -- makes tests run faster and debugging easier
- `-DMOTION_BUILD_EXE=On`: build example executables and benchmarks
- `-DMOTION_BUILD_TESTS=On`: build tests
- `-DMOTION_USE_AVX=AVX2`: compile with AVX2 instructions (choose one of `AVX`/`AVX2`/`AVX512`)

### HyCC Support for Hybrid Circuits

To enable support for HyCC circuits, the HyCC library must be compiled and the
following flags need additionally be passed to CMake:

- `-DMOTION_BUILD_HYCC_ADAPTER=On`
- `-DMOTION_HYCC_PATH=/path/to/HyCC` where `/path/to/HyCC` points to the HyCC
  directory, i.e., the top-level directory of the cloned repository

This builds the library target `motion_hycc` and the `hycc2motion` executable.



### ONNX Support for Neural Networks

For ONNX support, the ONNX library must be installed and the following flag
needs additionally be passed to CMake:

- `-DMOTION_BUILD_ONNX_ADAPTER=On`

This builds the library target `motion_onnx` and the `onnx2motion` executable.



### Examples


#### Using the MOTION2NX Low-Level API

See [here](src/examples/millionaires_problem) for an example solution of Yao's
Millionaires' Problem.


#### Using the `onnx2motion` Application

```
$ ./bin/onnx2motion \
    --my-id ${PARTY_ID} \
    --party 0,::1,7000 \
    --party 1,::1,7001 \
    --arithmetic-protocol GMW \
    --boolean-protocol GMW \
    --model /path/to/model.onnx \
    --json
```
with "${PARTY_ID}" either 0 or 1.
