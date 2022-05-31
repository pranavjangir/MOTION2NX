add_executable(mpclan_and mpclan_and.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(mpclan_and PRIVATE cxx_std_20)

target_link_libraries(mpclan_and
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)