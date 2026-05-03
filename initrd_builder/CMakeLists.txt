cmake_minimum_required(VERSION 3.10)
project(InitrdPackager)

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/output)
file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# 定义目标：构建 initrd
add_custom_target(initrd
    # 1. 清理并创建 RootFS 目录
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/rootfs
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/rootfs
    
    # 2. 创建基础目录结构 (bin, lib, lib64 等)
    COMMAND ${CMAKE_COMMAND} -E make_directory 
        ${CMAKE_SOURCE_DIR}/rootfs/bin
        ${CMAKE_SOURCE_DIR}/rootfs/lib
        ${CMAKE_SOURCE_DIR}/rootfs/lib64
        ${CMAKE_SOURCE_DIR}/rootfs/dev
        ${CMAKE_SOURCE_DIR}/rootfs/proc
        ${CMAKE_SOURCE_DIR}/rootfs/sys
        ${CMAKE_SOURCE_DIR}/rootfs/run

    # 3. 编译并安装你的程序到 rootfs
    # 注意：这里不需要 WORKING_DIRECTORY，CMake 会自动处理路径
    COMMAND ${CMAKE_COMMAND} 
        -S ${CMAKE_SOURCE_DIR}/src 
        -B ${CMAKE_SOURCE_DIR}/src/build 
        -DCMAKE_INSTALL_PREFIX=${CMAKE_SOURCE_DIR}/rootfs
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_SOURCE_DIR}/src/build --target install

    COMMAND bash ${CMAKE_SOURCE_DIR}/build_socat.sh ${CMAKE_SOURCE_DIR}
    
    # 4. 调用打包脚本
    COMMAND bash ${CMAKE_SOURCE_DIR}/pack_initrd.sh ${CMAKE_SOURCE_DIR}
    
    # 工作目录
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    
    COMMENT "Building Isolated Initrd Environment..."

    # 4. 调用打包脚本
    # 关键修复：将工作目录改回项目根目录，或者确保脚本接收正确的绝对路径
    COMMAND env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ${CMAKE_SOURCE_DIR}/pack_initrd.sh ${CMAKE_SOURCE_DIR}
    
    # 【关键修复】：工作目录应该是项目根目录，而不是 src
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    
    COMMENT "Building Isolated Initrd Environment..."
    # VERBATIM
)