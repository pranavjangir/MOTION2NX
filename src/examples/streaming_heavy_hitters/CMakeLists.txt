add_executable(streaming_heavy_hitters streaming_heavy_hitters.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(streaming_heavy_hitters PRIVATE cxx_std_20)

target_link_libraries(streaming_heavy_hitters
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)