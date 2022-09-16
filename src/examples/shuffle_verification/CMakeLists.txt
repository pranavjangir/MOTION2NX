add_executable(shuffle_verification shuffle_verification.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(shuffle_verification PRIVATE cxx_std_20)

target_link_libraries(shuffle_verification
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)