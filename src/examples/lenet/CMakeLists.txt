add_executable(lenet lenet.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(lenet PRIVATE cxx_std_20)

target_link_libraries(lenet
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)
