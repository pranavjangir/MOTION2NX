add_executable(mpclan_addition mpclan_addition.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(mpclan_addition PRIVATE cxx_std_20)

target_link_libraries(mpclan_addition
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)
