add_executable(bit2a_verification bit2a_verification.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(bit2a_verification PRIVATE cxx_std_20)

target_link_libraries(bit2a_verification
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)