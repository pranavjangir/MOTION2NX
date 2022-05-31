add_executable(a_to_b_conversion a_to_b_conversion.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(a_to_b_conversion PRIVATE cxx_std_20)

target_link_libraries(a_to_b_conversion
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)
