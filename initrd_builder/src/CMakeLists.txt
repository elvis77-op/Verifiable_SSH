cmake_minimum_required(VERSION 3.16)
project(attestation_service)

set(CMAKE_CXX_STANDARD 17)

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

include_directories(
  ${Protobuf_INCLUDE_DIRS}
  ${CMAKE_CURRENT_BINARY_DIR}
)

set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/attestation_service.proto)

get_filename_component(PROTO_PATH ${PROTO_FILE} PATH)

set(PROTO_SRC
  ${CMAKE_CURRENT_BINARY_DIR}/attestation_service.pb.cc
  ${CMAKE_CURRENT_BINARY_DIR}/attestation_service.grpc.pb.cc
)

set(PROTO_HDR
  ${CMAKE_CURRENT_BINARY_DIR}/attestation_service.pb.h
  ${CMAKE_CURRENT_BINARY_DIR}/attestation_service.grpc.pb.h
)

add_custom_command(
  OUTPUT ${PROTO_SRC} ${PROTO_HDR}
  COMMAND protoc
  ARGS -I ${PROTO_PATH}
       --cpp_out ${CMAKE_CURRENT_BINARY_DIR}
       --grpc_out ${CMAKE_CURRENT_BINARY_DIR}
       --plugin=protoc-gen-grpc=`which grpc_cpp_plugin`
       ${PROTO_FILE}
  DEPENDS ${PROTO_FILE}
)

# ===== client =====
add_executable(attestation_client
  attestation_client.cc
  ${PROTO_SRC}
)

target_link_libraries(attestation_client
  gRPC::grpc++
  protobuf::libprotobuf
)

# ===== server =====
add_executable(attestation_server
  attestation_server.cc
  ${PROTO_SRC}
)

target_link_libraries(attestation_server
  gRPC::grpc++
  protobuf::libprotobuf
)

install(TARGETS attestation_client attestation_server DESTINATION bin)