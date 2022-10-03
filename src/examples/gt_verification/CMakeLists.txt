add_executable(gt_verification gt_verification.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(gt_verification PRIVATE cxx_std_20)

target_link_libraries(gt_verification
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)