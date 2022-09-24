add_executable(private_heavy_hitters_simul private_heavy_hitters_simul.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(private_heavy_hitters_simul PRIVATE cxx_std_20)

target_link_libraries(private_heavy_hitters_simul
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)