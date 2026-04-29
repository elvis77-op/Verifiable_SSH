#!/bin/bash
set -e

PROJECT_ROOT=$1
ROOTFS_DIR="${PROJECT_ROOT}/rootfs"
OUTPUT_DIR="${PROJECT_ROOT}/output"

echo "=== Packing Initrd into CPIO ==="

# 1. 创建 Init 脚本
cat > ${ROOTFS_DIR}/init << 'EOF'
#!/bin/sh
echo "=== Early Boot Init Started ==="

# 挂载虚拟文件系统
mount -t proc proc /proc
mount -t sysfs sys /sys

# 关键：如果没有 devtmpfs，必须手动创建 console，否则 echo 会失败
if [ ! -e /dev/console ]; then
    mknod -m 600 /dev/console c 5 1
fi

# 尝试挂载 devtmpfs
if ! mount -t devtmpfs dev /dev 2>/dev/null; then
    mkdir -p /dev/pts
    mknod /dev/null c 1 3
    mknod /dev/zero c 1 5
fi

echo "Starting Client..."
/attestation_client &

echo "Entering shell..."
exec /bin/sh
EOF
chmod 755 ${ROOTFS_DIR}/init

# 2. 复制动态库 (核心修复部分)
echo "=== Copying Dynamic Libraries ==="

# 定义需要扫描依赖的二进制文件列表 (使用绝对路径)
# 必须包含你的程序，以及系统必须的 /bin/sh (如果 sh 是二进制文件)
BINARIES=(
    "${ROOTFS_DIR}/bin/attestation_client"
    "${ROOTFS_DIR}/bin/attestation_server"
    "/bin/sh"  # 关键：确保宿主机的 /bin/sh 的依赖也被复制进去！
)

for binary in "${BINARIES[@]}"; do
    if [ -f "$binary" ]; then
        echo "Scanning dependencies for: $binary"
        
        # 使用 ldd 获取依赖列表
        # 格式: libname => /path/to/lib (addr) 或 /path/to/lib (addr)
        LIBS=$(ldd "$binary" 2>/dev/null | grep "=> /" | awk '{print $3}')
        
        # 显式获取动态链接器 (ld-linux)
        # ldd 输出中 ld-linux 通常不在 "=> /" 这一列，需要单独提取
        INTERPRETER=$(ldd "$binary" 2>/dev/null | grep "ld-linux" | awk '{print $1}')
        
        # 合并列表
        ALL_LIBS="$LIBS $INTERPRETER"
        
        for lib in $ALL_LIBS; do
            if [ -n "$lib" ] && [ -f "$lib" ]; then
                # 复制库文件，保留目录结构
                # 例如: /lib/x86_64-linux-gnu/libc.so.6 -> rootfs/lib/x86_64-linux-gnu/libc.so.6
                cp -v --parents "$lib" ${ROOTFS_DIR} 2>/dev/null || true
            fi
        done
    else
        echo "Warning: Binary not found: $binary"
    fi
done

echo "=== Integrating BusyBox ==="

# 1. 复制 busybox 二进制文件 (假设你安装了 busybox-static)
# 如果没有安装，可以用 apt-get install busybox
cp -v /bin/busybox ${ROOTFS_DIR}/bin/

# 2. 创建常用命令的软链接 (指向 busybox)
# 这样 /bin/sh, /bin/mount, /bin/mkdir 就都“存在”了
cd ${ROOTFS_DIR}/bin
for cmd in sh mount mkdir mknod cat ls cp mv rm ln grep sed ash; do
    ln -sf busybox $cmd
done
cd ${ROOTFS_DIR}

# 3. 生成 CPIO 归档
echo "=== Generating CPIO Archive ==="
cd ${ROOTFS_DIR}

# 确保 output 目录存在
mkdir -p ${OUTPUT_DIR}

# 打包
find . | cpio -H newc -o | gzip -9 > ${OUTPUT_DIR}/initramfs.cpio.gz

echo "Success! Initrd created at: ${OUTPUT_DIR}/initramfs.cpio.gz"