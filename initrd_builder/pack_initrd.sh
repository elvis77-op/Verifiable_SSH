#!/bin/bash

# ============================================================
# pack_initrd.sh
# 在 Docker 容器内运行，收集二进制依赖并打包 initrd
# 用法: ./pack_initrd.sh <PROJECT_ROOT>
# ============================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

PROJECT_ROOT="${1:?Usage: $0 <PROJECT_ROOT>}"
ROOTFS_DIR="${PROJECT_ROOT}/rootfs"
OUTPUT_DIR="${PROJECT_ROOT}/output"

echo "=== Packing Initrd into CPIO ==="

# ============================================================
# 收集容器内二进制文件的动态库依赖
# ============================================================
collect_binary_deps() {
    echo ""
    echo "========================================"
    echo "  Collecting Binary Dependencies"
    echo "========================================"
    
    # 需要扫描依赖的二进制列表
    BINARIES=(
        "${ROOTFS_DIR}/bin/attestation_client"
        "${ROOTFS_DIR}/bin/attestation_server"
        "${ROOTFS_DIR}/bin/socat"
    )
    
    for binary in "${BINARIES[@]}"; do
        if [ ! -f "$binary" ]; then
            echo "  ⚠ Binary not found: $binary (skipping)"
            continue
        fi
        
        echo "  Scanning: $binary"
        
        # 获取所有动态库依赖
        LIBS=$(ldd "$binary" 2>/dev/null | grep "=> /" | awk '{print $3}')
        # 获取动态链接器
        INTERPRETER=$(ldd "$binary" 2>/dev/null | grep "ld-linux" | awk '{print $1}')
        
        for lib in $LIBS $INTERPRETER; do
            if [ -n "$lib" ] && [ -f "$lib" ]; then
                target_dir="${ROOTFS_DIR}$(dirname "$lib")"
                mkdir -p "$target_dir"
                
                if [ ! -f "${target_dir}/$(basename "$lib")" ]; then
                    cp -v "$lib" "$target_dir/"
                fi
            fi
        done
    done
    
    # 复制 busybox（init 脚本需要）
    if command -v busybox &> /dev/null; then
        BUSYBOX_PATH=$(which busybox)
        cp -v "$BUSYBOX_PATH" "${ROOTFS_DIR}/bin/"
        echo "  ✓ BusyBox copied from: $BUSYBOX_PATH"
        
        # 也收集 busybox 的依赖（通常是静态编译，但以防万一）
        BUSYBOX_LIBS=$(ldd "$BUSYBOX_PATH" 2>/dev/null | grep "=> /" | awk '{print $3}')
        for lib in $BUSYBOX_LIBS; do
            if [ -n "$lib" ] && [ -f "$lib" ]; then
                target_dir="${ROOTFS_DIR}$(dirname "$lib")"
                mkdir -p "$target_dir"
                if [ ! -f "${target_dir}/$(basename "$lib")" ]; then
                    cp -v "$lib" "$target_dir/"
                fi
            fi
        done
    else
        echo "  ✗ BusyBox not found! Please install: apt-get install busybox-static"
        exit 1
    fi
}

# ============================================================
# 创建 Init 脚本
# ============================================================
create_init_script() {
    echo ""
    echo "=== Creating Init Script ==="
    
    cat > ${ROOTFS_DIR}/init << 'EOF'
#!/bin/busybox sh

echo "=== Early Boot Init Started ==="

# 确保 /bin/sh 可用
[ ! -L /bin/sh ] && ln -s /bin/busybox /bin/sh

# 挂载基础文件系统
mount -t proc proc /proc
mount -t sysfs sys /sys

# 创建设备节点
[ ! -e /dev/console ] && mknod -m 600 /dev/console c 5 1
if ! mount -t devtmpfs dev /dev 2>/dev/null; then
    mkdir -p /dev/pts
    mknod /dev/null c 1 3
fi

# 激活 loopback
echo "=== Activating loopback ==="
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null
sleep 1

if ! ip addr show lo | grep -q "inet 127.0.0.1"; then
    ifconfig lo 127.0.0.1 up 2>/dev/null || ip addr add 127.0.0.1/8 dev lo 2>/dev/null
fi
echo "✓ Loopback activated"

# 加载 VSOCK 模块
echo "=== Loading VSOCK Modules ==="
KERNEL_VER=$(uname -r)
MODULE_BASE="/lib/modules/${KERNEL_VER}"

find "$MODULE_BASE" -name "*vsock*.ko" -type f 2>/dev/null | sort | while read mod; do
    echo "  Loading: $mod"
    insmod "$mod" 2>&1
done

# 检查加载结果
sleep 1
if lsmod | grep -q vsock; then
    echo "✓ VSOCK modules loaded"
else
    echo "⚠ VSOCK modules not loaded, falling back to TCP"
fi

# 启动 VSOCK 代理
echo "=== Starting VSOCK Proxy ==="
/bin/socat TCP-LISTEN:50051,reuseaddr,fork VSOCK-CONNECT:2:50051 &
sleep 1

# 启动业务
echo "Starting attestation_client..."
/bin/attestation_client &

# 保持 Shell
exec /bin/sh
EOF
    chmod 755 ${ROOTFS_DIR}/init
    
    echo "Init script created"
}

# ============================================================
# 创建 BusyBox 软链接
# ============================================================
create_busybox_symlinks() {
    echo ""
    echo "=== Creating BusyBox Symlinks ==="
    
    cd ${ROOTFS_DIR}/bin
    for cmd in sh mount mkdir mknod cat ls cp mv rm ln grep sed ash; do
        ln -sf busybox $cmd 2>/dev/null || true
    done
    cd ${ROOTFS_DIR}
    
    echo "BusyBox symlinks created"
}

# ============================================================
# 打包 CPIO
# ============================================================
pack_cpio() {
    echo ""
    echo "=== Generating CPIO Archive ==="
    
    cd ${ROOTFS_DIR}
    mkdir -p ${OUTPUT_DIR}
    
    find . | cpio -H newc -o | gzip -9 > ${OUTPUT_DIR}/initramfs.cpio.gz
    
    echo ""
    echo "============================================"
    echo "  SUCCESS!"
    echo "============================================"
    echo "Initrd created at: ${OUTPUT_DIR}/initramfs.cpio.gz"
    echo "Size: $(du -h ${OUTPUT_DIR}/initramfs.cpio.gz | cut -f1)"
}

# ============================================================
# 主执行流程
# ============================================================

mkdir -p ${ROOTFS_DIR}/bin
mkdir -p ${ROOTFS_DIR}/lib
mkdir -p ${ROOTFS_DIR}/usr/lib

collect_binary_deps
create_init_script
create_busybox_symlinks
pack_cpio