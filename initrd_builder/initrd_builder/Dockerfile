# 使用 Ubuntu 22.04 作为基础镜像
FROM ubuntu:22.04

# 避免交互式安装时的时区选择提示
ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装基础工具
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    curl \
    cpio \
    busybox-static \
    kmod \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# 2. 安装 gRPC 和 Protobuf 依赖 (使用系统包管理器，最稳定)
# 注意：这里安装的是开发库，不是运行时
RUN apt-get update && apt-get install -y \
    pkg-config \
    libprotobuf-dev \
    protobuf-compiler \
    protobuf-compiler-grpc \
    libgrpc++-dev \
    libssl-dev \
    zlib1g-dev \
    iproute2 \
    udhcpc \
    bash \
    ca-certificates \
    openssl \
    libssl3 \
    libprotobuf23 \
    libgrpc++1 \
    && rm -rf /var/lib/apt/lists/*


RUN git clone --recurse-submodules -b v1.45.2 --shallow-submodules \
https://github.com/grpc/grpc && \
cd grpc && \
mkdir -p cmake/build && \
cd cmake/build && \
cmake ../.. \
    -DgRPC_INSTALL=ON \
    -DgRPC_BUILD_TESTS=OFF \
    -DCMAKE_INSTALL_PREFIX=/usr/local && \
make -j$(nproc) && \
make install && \
cd ../../.. && \
rm -rf grpc  


# 3. 设置工作目录
WORKDIR /workspace

# 4. (可选) 预编译 gRPC 源码 (如果系统源版本太老，可以用这种方式，这里先省略以简化流程)
# 如果需要最新版 gRPC，可以在这里添加从源码编译的步骤

CMD ["/bin/bash"]