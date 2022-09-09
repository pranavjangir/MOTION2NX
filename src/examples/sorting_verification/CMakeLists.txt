add_executable(sorting_verification sorting_verification.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(sorting_verification PRIVATE cxx_std_20)

target_link_libraries(sorting_verification
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)