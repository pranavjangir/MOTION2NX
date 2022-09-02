add_executable(swift_basic_verification swift_basic_verification.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(swift_basic_verification PRIVATE cxx_std_20)

target_link_libraries(swift_basic_verification
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)
