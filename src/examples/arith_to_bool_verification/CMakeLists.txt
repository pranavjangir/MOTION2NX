add_executable(arith_to_bool_verification arith_to_bool_verification.cpp)
target_compile_features(arith_to_bool_verification PRIVATE cxx_std_17)

find_package(Boost COMPONENTS program_options REQUIRED)

target_link_libraries(arith_to_bool_verification
  MOTION::motion
  Boost::program_options
  benchmark::benchmark_main
  benchmark::benchmark
)
