# MPClan -- Protocol Suite for Privacy-Conscious Computations

This software is the preliminary version of the semi-honest MPC protocol of MPClan (https://eprint.iacr.org/2022/675) which builds on the MOTION2NX framework available at https://github.com/encryptogroup/MOTION2NX. Our implementation currently includes basic MPC protocols for input sharing, addition, multiplication and output reconstruction. The support for securely performing neural network inference is also present. For this, building blocks required to evaluate neural networks have been implemented. 


We re-iterate that the code is still in its initial stages and under development.

# Example MPCLan arithmetic multiplication

Commands to check the working of multiplication with `n` parties.
Parties `1` and `2` provide the two integers to be multiplied.

The input is shared among all `n` parties and output is reconstructed towards all the parties. 

Build project using 
```
$ CC=gcc CXX=g++ cmake \
    -B build_debwithrelinfo_gcc \
    -DCMAKE_BUILD_TYPE=DebWithRelInfo \
    -DMOTION_BUILD_EXE=On \
    -DMOTION_BUILD_TESTS=On \
    -DMOTION_USE_AVX=AVX2
$ cmake --build build_debwithrelinfo_gcc
```

Then run :
```
./dbg/bin/mpclan_multiplication --my-id 0 \
 --num_parties 3 \
 --party 0,<PARTY_0_IP_ADDRESS> \
 --party 1,<PARTY_1_IP_ADDRESS> \
 --party 2,<PARTY_2_IP_ADDRESS> \
 --arithmetic-protocol beavy --boolean-protocol yao --repetitions 5 --input-value 10

 ./dbg/bin/mpclan_multiplication --my-id 1 \
 --num_parties 3 \
 --party 0,<PARTY_0_IP_ADDRESS> \
 --party 1,<PARTY_1_IP_ADDRESS> \
 --party 2,<PARTY_2_IP_ADDRESS> \
 --arithmetic-protocol beavy --boolean-protocol yao --repetitions 5 --input-value 20

 ./dbg/bin/mpclan_multiplication --my-id 2 \
 --num_parties 3 \
 --party 0,<PARTY_0_IP_ADDRESS> \
 --party 1,<PARTY_1_IP_ADDRESS> \
 --party 2,<PARTY_2_IP_ADDRESS> \
 --arithmetic-protocol beavy --boolean-protocol yao --repetitions 5 --input-value 30
```

`Output = 200`

The `num_parties` option is configurable, and `my-id` option and IP addresses change accordingly.




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
