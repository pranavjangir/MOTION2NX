add_executable(benchmark_integers benchmark_integers_main.cpp common/benchmark_integers.cpp)

find_package(Boost
        COMPONENTS
        program_options
        REQUIRED)

target_compile_features(benchmark_integers PRIVATE cxx_std_17)

target_link_libraries(benchmark_integers
        MOTION::motion
        Boost::program_options
        )

target_compile_features(benchmark_integers PRIVATE cxx_std_17)
