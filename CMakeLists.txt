cmake_minimum_required(VERSION 3.5)

project(BruvChatClient2 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5 COMPONENTS Core Widgets Websockets REQUIRED)

# include lib sodium
include_directories(deps/libsodium-win64/include)
link_directories(deps/libsodium-win64/lib)

add_executable(BruvChatClient2
src/main.cpp
src/crypto.h
src/crypto.cpp
src/chatwindow.cpp
src/chatwindow.h
src/chatwindow.ui
src/user.h
src/user.cpp
src/device.h
src/device.cpp
src/session.h
src/session.cpp
src/utils.h
src/x25519.h
src/x25519.cpp
src/ed25519.h
src/ed25519.cpp
src/message.h
src/message.cpp
src/loginwindow.ui
src/loginwindow.cpp
src/loginwindow.h
src/messageui.h
)

target_link_libraries(BruvChatClient2 PRIVATE Qt5::Widgets Qt5::WebSockets libsodium)
