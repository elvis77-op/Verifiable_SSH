#!/bin/bash

# 定义镜像名称
IMAGE_NAME="initrd-builder-image"
# 定义当前目录
PROJECT_DIR=$(pwd)

echo "🚀 步骤 1: 强制检查并构建 Docker 镜像..."
# 修改点：
# 1. 移除了 if 判断，每次都尝试 build
# 2. 加上 --progress=plain 可以看到更详细的编译日志（方便看 gRPC 编译进度）
# 3. 加上 --pull 确保基础镜像是最新的（可选，如果网络慢可以去掉）
docker build --pull --progress=plain -t $IMAGE_NAME .

# 检查上一步是否成功，如果构建镜像失败，直接退出脚本，防止用旧镜像运行
if [ $? -ne 0 ]; then
    echo "❌ Docker 镜像构建失败！请检查 Dockerfile 或网络环境。"
    exit 1
fi

echo "🔨 步骤 2: 在隔离容器中执行构建..."
# 运行容器
docker run --rm \
    -v ${PROJECT_DIR}:/workspace \
    -v /lib/modules:/host/lib/modules:ro \
    -w /workspace \
    --network=host \
    $IMAGE_NAME \
    bash -c "
        # 在容器内执行的命令
        echo '清理旧的构建缓存...';
        rm -rf build src/build rootfs output;
        
        echo '开始 CMake 配置...';
        cmake -S . -B build;
        
        echo '开始构建 Initrd...';
        cmake --build build --target initrd;
        
        echo '构建完成！产物在 output/ 目录';
    "

echo "✅ 所有操作完成，容器已自动销毁，宿主机环境未受污染。"