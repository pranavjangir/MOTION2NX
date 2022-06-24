add_executable(nn_fully_connected nn_fully_connected.cpp)

find_package(Boost COMPONENTS json log program_options REQUIRED)

target_compile_features(nn_fully_connected PRIVATE cxx_std_20)

target_link_libraries(nn_fully_connected
    MOTION::motion
    Boost::json
    Boost::log
    Boost::program_options
)
