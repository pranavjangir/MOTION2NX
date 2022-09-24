add_executable(private_heavy_hitters private_heavy_hitters.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(private_heavy_hitters PRIVATE cxx_std_20)

target_link_libraries(private_heavy_hitters
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)