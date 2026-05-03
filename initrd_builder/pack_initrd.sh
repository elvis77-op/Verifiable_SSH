#!/bin/bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

PROJECT_ROOT=$1
ROOTFS_DIR="${PROJECT_ROOT}/rootfs"
OUTPUT_DIR="${PROJECT_ROOT}/output"

echo "=== Packing Initrd into CPIO ==="

# 1. 创建 Init 脚本
cat > ${ROOTFS_DIR}/init << 'EOF'
#!/bin/busybox sh
# 注意：这里直接写死为 /bin/busybox sh，这是最稳妥的写法

echo "=== Early Boot Init Started ==="

# 1. 确保 /bin/sh 链接存在 (双重保险)
if [ ! -L /bin/sh ]; then
    ln -s /bin/busybox /bin/sh
fi

# 2. 挂载基础文件系统
mount -t proc proc /proc
mount -t sysfs sys /sys

# 3. 创建设备节点
if [ ! -e /dev/console ]; then
    mknod -m 600 /dev/console c 5 1
fi

if ! mount -t devtmpfs dev /dev 2>/dev/null; then
    mkdir -p /dev/pts
    mknod /dev/null c 1 3
fi
echo "=== Activating loopback ==="
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null
sleep 1

# 验证 lo 状态
if ip addr show lo | grep -q "inet 127.0.0.1"; then
    echo "✓ Loopback activated"
else
    echo "Adding 127.0.0.1 to lo..."
    ifconfig lo 127.0.0.1 up 2>/dev/null || ip addr add 127.0.0.1/8 dev lo 2>/dev/null
fi

echo "=== Loading VSOCK Modules ==="

KERNEL_VER=$(uname -r)
MODULE_BASE="/lib/modules/${KERNEL_VER}"

# 查找所有 VSOCK 模块
VSOCK_MODULES=$(find "$MODULE_BASE" -name "*vsock*.ko" -type f 2>/dev/null | sort)

if [ -z "$VSOCK_MODULES" ]; then
    echo "✗ No VSOCK modules found!"
    
    # 尝试其他位置
    find /lib/modules -name "*vsock*.ko" 2>/dev/null
    
    echo "Falling back to TCP mode..."
    FALLBACK_TO_TCP=1
else
    echo "Found VSOCK modules:"
    echo "$VSOCK_MODULES"
    
    # 按依赖顺序加载
    # 1. 先加载核心 vsock 模块
    echo "Loading vsock core..."
    find "$MODULE_BASE" -name "vsock.ko" -o -name "vsock.ko.gz" | while read mod; do
        echo "  insmod $mod"
        insmod "$mod" 2>&1
    done
    
    # 2. 加载 transport common
    echo "Loading vsock transport common..."
    find "$MODULE_BASE" -name "*vsock*virtio_transport_common*" | while read mod; do
        echo "  insmod $mod"
        insmod "$mod" 2>&1
    done
    
    # 3. 加载 virtio transport
    echo "Loading vsock virtio transport..."
    find "$MODULE_BASE" \( -name "*vsock*virtio_transport.ko" -o -name "*virtio_vsock*" \) | while read mod; do
        # 排除 common
        if ! echo "$mod" | grep -q "common"; then
            echo "  insmod $mod"
            insmod "$mod" 2>&1
        fi
    done
    
    # 4. 加载其他 vsock 模块（hv_sock, vmci, loopback）
    echo "Loading additional VSOCK modules..."
    find "$MODULE_BASE" -name "*vsock*" | while read mod; do
        if ! echo "$mod" | grep -qE "core|common|virtio_transport"; then
            echo "  insmod $mod"
            insmod "$mod" 2>&1
        fi
    done
    
    # 检查是否加载成功
    sleep 1
    echo ""
    echo "Loaded VSOCK modules:"
    cat /proc/modules | grep -i vsock || echo "  No modules loaded!"
fi

# 检查设备
echo ""
echo "Checking VSOCK device..."
if [ -e /dev/vsock ] || [ -e /dev/vhost-vsock ]; then
    echo "✓ VSOCK device found"
else
    # 尝试手动创建
    VSOCK_MAJOR=$(grep -i vsock /proc/devices | awk '{print $1}')
    if [ -n "$VSOCK_MAJOR" ]; then
        echo "Creating /dev/vsock (major=$VSOCK_MAJOR)..."
        mknod /dev/vsock c $VSOCK_MAJOR 0
    fi
fi

# ... 之前的网络初始化代码 ...

echo "=== Starting VSOCK Proxy with Socat ==="

/bin/socat TCP-LISTEN:50051,reuseaddr,fork VSOCK-CONNECT:2:50051 &

# 等待 socat ready
sleep 1

# ... 启动你的 attestation_client ...

# 启动业务
echo "Starting attestation_client..."
/bin/attestation_client &

# 保持 Shell
exec /bin/sh
EOF
chmod 755 ${ROOTFS_DIR}/init


echo "=== Copying Dynamic Libraries ==="

# 定义需要扫描依赖的二进制文件列表
BINARIES=(
    "${ROOTFS_DIR}/bin/attestation_client"
    "${ROOTFS_DIR}/bin/attestation_server"
    "${ROOTFS_DIR}/bin/socat"
    "/bin/sh"
)

for binary in "${BINARIES[@]}"; do
    if [ -f "$binary" ]; then
        echo "Scanning dependencies for: $binary"
        
        # 使用 ldd 获取依赖列表
        LIBS=$(ldd "$binary" 2>/dev/null | grep "=> /" | awk '{print $3}')
        INTERPRETER=$(ldd "$binary" 2>/dev/null | grep "ld-linux" | awk '{print $1}')
        
        ALL_LIBS="$LIBS $INTERPRETER"
        
        for lib in $ALL_LIBS; do
            if [ -n "$lib" ] && [ -f "$lib" ]; then
                # --- 修改开始 ---
                # 1. 计算目标目录路径 (例如: ${ROOTFS_DIR}/lib/x86_64-linux-gnu)
                TARGET_DIR="${ROOTFS_DIR}$(dirname "$lib")"
                
                # 2. 手动创建目录
                mkdir -p "$TARGET_DIR"
                
                # 3. 复制文件
                cp -v "$lib" "$TARGET_DIR/"
                # --- 修改结束 ---
            fi
        done
    else
        echo "Warning: Binary not found: $binary"
    fi
done

# === 通用 VSOCK 模块查找和复制（带完整调试） ===

echo "=== Adding VSOCK Kernel Modules ==="
echo ""
echo "========== VSOCK DEBUG INFORMATION =========="

# 确定模块源路径
if [ -d "/host/lib/modules" ]; then
    MODULES_BASE="/host/lib/modules"
    echo "MODULES_BASE: $MODULES_BASE (from /host mount)"
elif [ -d "/lib/modules" ]; then
    MODULES_BASE="/lib/modules"
    echo "MODULES_BASE: $MODULES_BASE (from system)"
else
    echo "ERROR: Cannot find kernel modules directory"
    echo "Checking possible locations:"
    ls -la /host/lib/modules 2>&1
    ls -la /lib/modules 2>&1
    exit 1
fi

# 获取当前运行的内核版本，而不是目录列表的第一个
KERNEL_VER=$(uname -r)
echo "Running kernel: $KERNEL_VER"

# 检查这个版本是否在挂载的模块中存在
if [ -d "${MODULES_BASE}/${KERNEL_VER}" ]; then
    echo "✓ Found modules for running kernel: $KERNEL_VER"
else
    echo "⚠ Running kernel modules not found, searching for alternatives..."
    
    # 如果当前内核版本不存在，找最接近的
    KERNEL_VER=$(ls "$MODULES_BASE" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1)
    echo "Using: $KERNEL_VER"
fi

echo "Selected kernel version: $KERNEL_VER"
HOST_MODULES="${MODULES_BASE}/${KERNEL_VER}"
TARGET_MODULES="${ROOTFS_DIR}/lib/modules/${KERNEL_VER}"

echo "HOST_MODULES: $HOST_MODULES"
echo "TARGET_MODULES: $TARGET_MODULES"
echo ""

# 显示 host modules 目录结构
echo "=== Directory structure of $HOST_MODULES ==="
find "$HOST_MODULES" -maxdepth 4 -type d 2>/dev/null | head -50
echo ""

echo "=== All .ko files in kernel/ (first 50) ==="
find "$HOST_MODULES/kernel" -name "*.ko" -o -name "*.ko.gz" 2>/dev/null | head -50
echo ""

# ============================================
# 通用 VSOCK 模块查找策略
# ============================================

VSOCK_PATTERNS=(
    "kernel/net/vmw_vsock/vsock.ko"
    "kernel/net/vmw_vsock/vsock.ko.gz"
    "*virtio_transport*.ko"
    "*vsock_virtio*.ko"
    "*hv_sock*.ko"
    "*vmw_vsock_vmci*.ko"
    "*vsock_loopback*.ko"
    "*vsock_diag*.ko"
    "kernel/drivers/vhost/vsock.ko"
    "kernel/drivers/vhost/vhost_vsock.ko"
    "kernel/net/vmw_vsock/*.ko"
)

echo "=== SEARCH PATTERNS AND PATHS ==="

# 创建目标目录
mkdir -p "${TARGET_MODULES}/kernel/net/vmw_vsock"
mkdir -p "${TARGET_MODULES}/kernel/drivers/vhost"

declare -A copied_modules

search_and_copy() {
    local pattern=$1
    local search_base="${HOST_MODULES}"
    local found=0
    
    echo ""
    echo "--- Pattern: '$pattern' ---"
    echo "Search base: $search_base"
    
    # 构建完整的搜索路径
    if [[ "$pattern" == *"/"* ]] && [[ "$pattern" != "*"* ]]; then
        # 这是具体路径，直接检查
        local full_path="${search_base}/${pattern}"
        echo "Checking exact path: $full_path"
        if [ -f "$full_path" ]; then
            echo "  ✓ FOUND: $full_path"
        else
            echo "  ✗ NOT FOUND: $full_path"
        fi
    fi

    # 使用 find 搜索
    local find_cmd="find \"$search_base\" -path \"*/$pattern\" -type f 2>/dev/null"
    echo "Running: $find_cmd"
    
    while IFS= read -r module_path; do
        [ -f "$module_path" ] || continue
        found=1
        
        local module_name=$(basename "$module_path")
        echo "  → Found: $module_path"
        
        if [ -n "${copied_modules[$module_name]}" ]; then
            echo "    (Already copied, skipping)"
            continue
        fi
        
        local rel_path="${module_path#${HOST_MODULES}/}"
        local dst="${TARGET_MODULES}/${rel_path}"
        
        echo "    Relative path: $rel_path"
        echo "    Destination: $dst"
        
        mkdir -p "$(dirname "$dst")"
        cp -v "$module_path" "$dst"
        copied_modules[$module_name]=1
        echo "  ✓ Copied: $module_name"
        
    done < <(find "$search_base" -path "*/$pattern" -type f 2>/dev/null)
    
    if [ $found -eq 0 ]; then
        echo "  ✗ No files matched this pattern"
    fi
}

# 执行搜索
for pattern in "${VSOCK_PATTERNS[@]}"; do
    search_and_copy "$pattern"
done

echo ""
echo "=== RESULTS ==="
echo "Total modules copied: ${#copied_modules[@]}"

if [ ${#copied_modules[@]} -gt 0 ]; then
    echo "Copied modules:"
    for mod in "${!copied_modules[@]}"; do
        echo "  - $mod"
    done
fi

# 如果没找到任何模块
if [ ${#copied_modules[@]} -eq 0 ]; then
    echo ""
    echo "========== EXTENDED SEARCH =========="
    echo "No VSOCK modules found. Extending search..."
    
    # 调试：列出所有包含 vsock 或 virtio 的文件
    echo ""
    echo "=== Searching for '*vsock*' ==="
    find "${HOST_MODULES}" -type f -iname "*vsock*" 2>/dev/null | while read f; do
        echo "  FOUND: $f"
    done
    
    echo ""
    echo "=== Searching for '*virtio*' ==="
    find "${HOST_MODULES}" -type f -iname "*virtio*" 2>/dev/null | while read f; do
        echo "  FOUND: $f"
    done
    
    echo ""
    echo "=== Complete module listing ==="
    find "${HOST_MODULES}/kernel" -type f \( -name "*.ko" -o -name "*.ko.gz" \) 2>/dev/null | while read f; do
        echo "  $f"
    done
    
    # 尝试复制所有找到的模块
    echo ""
    echo "Trying to copy any found modules..."
    find "${HOST_MODULES}" -type f \( -iname "*vsock*" -o -iname "*virtio*" \) 2>/dev/null | while read module; do
        rel_path="${module#${HOST_MODULES}/}"
        dst="${TARGET_MODULES}/${rel_path}"
        mkdir -p "$(dirname "$dst")"
        cp -v "$module" "$dst" 2>&1
    done
fi

# 复制依赖文件
echo ""
echo "=== Copying dependency files ==="
for dep_file in modules.dep modules.order modules.builtin modules.builtin.modinfo; do
    if [ -f "${HOST_MODULES}/${dep_file}" ]; then
        cp -v "${HOST_MODULES}/${dep_file}" "${TARGET_MODULES}/${dep_file}" 2>/dev/null
    else
        echo "  ${dep_file} not found"
    fi
done

# 生成 modules.dep
cat > "${TARGET_MODULES}/modules.dep" << 'MODDEP'
kernel/net/vmw_vsock/vsock.ko:
kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko: kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/virtio_transport.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/virtio_transport_common.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vsock_loopback.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vsock_diag.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/hv_sock.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vmw_vsock_vmci_transport.ko: kernel/net/vmw_vsock/vsock.ko
MODDEP

# ============================================
# 验证
# ============================================

echo ""
echo "=== Verification ==="
echo "Modules copied to rootfs:"
find "${TARGET_MODULES}" -name "*vsock*" -type f 2>/dev/null | sort
echo ""
echo "Total VSOCK modules: $(find "${TARGET_MODULES}" -name '*vsock*' -type f 2>/dev/null | wc -l)"

# 检查关键模块
echo ""
echo "=== Critical modules check ==="

check_module() {
    local name=$1
    if find "${TARGET_MODULES}" -name "$name" -type f 2>/dev/null | grep -q .; then
        echo "  ✓ $name found"
    else
        echo "  ✗ $name NOT FOUND (may cause issues)"
    fi
}

check_module "*vsock.ko*"
check_module "*virtio_transport_common*"
check_module "*virtio_transport*"

echo ""
echo "=== VSOCK module installation complete ==="

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