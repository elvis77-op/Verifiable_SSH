#!/bin/bash
# set -e

PROJECT_ROOT=$1
THIRD_PARTY="${PROJECT_ROOT}/third_party"
ROOTFS="${PROJECT_ROOT}/rootfs"
SOCAT_VERSION="1.7.4.4"
SOCAT_DIR="socat-${SOCAT_VERSION}"

echo "=== Building static socat with VSOCK support ==="

mkdir -p "${THIRD_PARTY}"

# 下载 socat
if [ ! -d "${THIRD_PARTY}/${SOCAT_DIR}" ]; then
    echo "Downloading socat ${SOCAT_VERSION}..."
    cd "${THIRD_PARTY}"
    # 使用官方源，如果下载失败请检查网络或更换版本
    wget -q "http://www.dest-unreach.org/socat/download/socat-${SOCAT_VERSION}.tar.gz"
    tar xzf "socat-${SOCAT_VERSION}.tar.gz"
    rm -f "socat-${SOCAT_VERSION}.tar.gz"
fi

cd "${THIRD_PARTY}/${SOCAT_DIR}"

# 清理旧的编译文件
make clean 2>/dev/null || true
make distclean 2>/dev/null || true

echo "Configuring socat with VSOCK..."

# 关键配置步骤：
# 1. 明确指定 CFLAGS 和 LDFLAGS 进行静态编译
# 2. 使用 --enable-vsock 显式启用 VSOCK 功能
CFLAGS="-static -O2" \
LDFLAGS="-static" \
./configure \
    --prefix=/usr \
    --disable-openssl \
    --disable-readline \
    --disable-libwrap \
    --enable-vsock

# 检查配置输出，确认 VSOCK 是否被启用
echo "Checking VSOCK support in config..."
if grep -q "WITH_VSOCK 1" config.h; then
    echo "✓ VSOCK enabled successfully!"
else
    echo "✗ ERROR: Failed to enable VSOCK. Checking config.log..."
    grep -i vsock config.log | head -10
    exit 1
fi

# 编译
echo "Building..."
make -j$(nproc)

# 验证最终二进制文件
echo "Verifying compiled binary..."
if ./socat -V 2>&1 | grep -q "WITH_VSOCK 1"; then
    echo "✓ Compiled socat supports VSOCK!"
else
    echo "✗ ERROR: Compiled socat does NOT support VSOCK."
    exit 1
fi

# 安装到 rootfs
echo "Installing socat to rootfs..."
mkdir -p "${ROOTFS}/bin"
cp -v ./socat "${ROOTFS}/bin/socat"
chmod 755 "${ROOTFS}/bin/socat"

echo "=== socat build complete ==="