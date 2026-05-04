#!/bin/bash

# ============================================================
# prepare_host_deps.sh
# 在宿主机运行，收集需要访问宿主机硬件/设备节点的依赖
# 用法: ./prepare_host_deps.sh <PROJECT_ROOT>
# ============================================================

set -e

PROJECT_ROOT="${1:?Usage: $0 <PROJECT_ROOT>}"
ROOTFS_DIR="${PROJECT_ROOT}/rootfs"
OUTPUT_DIR="${PROJECT_ROOT}/output"

echo "============================================"
echo "  Prepare Host-Side Dependencies"
echo "============================================"
echo "Project root: $PROJECT_ROOT"
echo "RootFS dir:   $ROOTFS_DIR"
echo ""

# ============================================================
# 第一部分：收集 VSOCK 内核模块
# ============================================================
collect_vsock_modules() {
    echo "========================================"
    echo "  Collecting VSOCK Kernel Modules"
    echo "========================================"
    
    # 确定模块源路径
    if [ -d "/host/lib/modules" ]; then
        MODULES_BASE="/host/lib/modules"
        echo "Modules source: $MODULES_BASE (from /host mount)"
    elif [ -d "/lib/modules" ]; then
        MODULES_BASE="/lib/modules"
        echo "Modules source: $MODULES_BASE (from system)"
    else
        echo "ERROR: Cannot find kernel modules directory"
        ls -la /host/lib/modules 2>&1 || true
        ls -la /lib/modules 2>&1 || true
        return 1
    fi
    
    # 获取运行内核版本
    KERNEL_VER=$(uname -r)
    echo "Running kernel version: $KERNEL_VER"
    
    # 检查内核版本是否匹配
    if [ ! -d "${MODULES_BASE}/${KERNEL_VER}" ]; then
        echo "⚠ Running kernel modules not found, searching for closest match..."
        KERNEL_VER=$(ls "$MODULES_BASE" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1)
        echo "Using kernel version: $KERNEL_VER"
        if [ -z "$KERNEL_VER" ]; then
            echo "ERROR: No kernel modules found at all"
            return 1
        fi
    fi
    
    HOST_MODULES="${MODULES_BASE}/${KERNEL_VER}"
    TARGET_MODULES="${ROOTFS_DIR}/lib/modules/${KERNEL_VER}"
    
    echo "Source: $HOST_MODULES"
    echo "Target: $TARGET_MODULES"
    echo ""
    
    # 创建目标目录
    mkdir -p "${TARGET_MODULES}"
    
    # 查找并复制所有 VSOCK 相关模块
    echo "Searching for VSOCK modules..."
    VSOCK_FILES=$(find "$HOST_MODULES" -type f \( -iname "*vsock*" -o -iname "*virtio*" \) 2>/dev/null)
    
    if [ -z "$VSOCK_FILES" ]; then
        echo "⚠ No VSOCK modules found!"
    else
        echo "$VSOCK_FILES" | while read module_path; do
            rel_path="${module_path#${HOST_MODULES}/}"
            dst="${TARGET_MODULES}/${rel_path}"
            
            mkdir -p "$(dirname "$dst")"
            cp -v "$module_path" "$dst"
            echo "  ✓ Copied: $(basename "$module_path")"
        done
    fi
    
    # 复制模块依赖文件
    echo ""
    echo "Copying module metadata..."
    for dep_file in modules.dep modules.order modules.builtin modules.builtin.modinfo; do
        if [ -f "${HOST_MODULES}/${dep_file}" ]; then
            cp -v "${HOST_MODULES}/${dep_file}" "${TARGET_MODULES}/${dep_file}"
        fi
    done
    
    # 生成 modules.dep（如果原文件不存在或不完整）
    if [ ! -f "${TARGET_MODULES}/modules.dep" ] || ! grep -q "vsock" "${TARGET_MODULES}/modules.dep" 2>/dev/null; then
        echo "Generating modules.dep for VSOCK modules..."
        cat > "${TARGET_MODULES}/modules.dep" << 'MODDEP'
kernel/net/vmw_vsock/vsock.ko:
kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko: kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/hv_sock.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vmw_vsock_vmci_transport.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vsock_loopback.ko: kernel/net/vmw_vsock/vsock.ko
kernel/net/vmw_vsock/vsock_diag.ko: kernel/net/vmw_vsock/vsock.ko
MODDEP
    fi
    
    echo ""
    echo "VSOCK modules collected:"
    find "${TARGET_MODULES}" -name "*vsock*" -type f 2>/dev/null | sort
}

# ============================================================
# 第二部分：收集 TDX 库依赖
# ============================================================
collect_tdx_libs() {
    echo ""
    echo "========================================"
    echo "  Collecting TDX Libraries"
    echo "========================================"
    
    # TDX 库搜索路径
    TDX_SEARCH_PATHS=(
        "/usr/lib"
        "/usr/local/lib"
        "/opt/tdx/lib"
        "/opt/intel/lib"
        "/host/usr/lib"
        "/host/opt/tdx/lib"
    )
    
    # TDX 库文件名模式
    TDX_LIB_PATTERNS=(
        "libtdx*"
        "libsgx*"
        "libquote*"
        "libpccs*"
        "libtdx_attest*"
        "libtdx_verify*"
        "libtdx_guest*"
    )
    
    local found_any=false
    
    for search_path in "${TDX_SEARCH_PATHS[@]}"; do
        [ -d "$search_path" ] || continue
        
        for pattern in "${TDX_LIB_PATTERNS[@]}"; do
            find "$search_path" -name "$pattern" -type f 2>/dev/null | while read lib_path; do
                lib_name=$(basename "$lib_path")
                target_dir="${ROOTFS_DIR}$(dirname "$lib_path")"
                
                mkdir -p "$target_dir"
                echo "  ✓ Copying TDX lib: $lib_name"
                cp -v "$lib_path" "$target_dir/"
                
                # 复制软链接目标
                if [ -L "$lib_path" ]; then
                    real_path=$(readlink -f "$lib_path")
                    if [ -f "$real_path" ]; then
                        cp -v "$real_path" "$target_dir/"
                    fi
                fi
                
                found_any=true
            done
        done
    done
    
    if ! $found_any; then
        echo "⚠ No TDX libraries found. If TDX is needed, please install TDX SDK first."
    fi
}

# ============================================================
# 主执行流程
# ============================================================

mkdir -p "${ROOTFS_DIR}/bin"
mkdir -p "${ROOTFS_DIR}/lib/modules"
mkdir -p "${ROOTFS_DIR}/usr/lib"
mkdir -p "${ROOTFS_DIR}/dev"
mkdir -p "${OUTPUT_DIR}"

collect_vsock_modules
collect_tdx_libs

# 创建标记文件，告知容器内脚本宿主依赖已收集完成
mkdir -p "${ROOTFS_DIR}/.host_deps"
echo "DONE" > "${ROOTFS_DIR}/.host_deps/ready"

echo ""
echo "============================================"
echo "  Host Dependencies Collected Successfully"
echo "============================================"