add_executable(mpclan_multiplication mpclan_multiplication.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(mpclan_multiplication PRIVATE cxx_std_20)

target_link_libraries(mpclan_multiplication
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)
