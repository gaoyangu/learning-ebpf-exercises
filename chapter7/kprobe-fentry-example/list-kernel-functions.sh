#!/bin/bash

echo "=== 内核函数查看工具 ==="
echo "当前内核版本: $(uname -r)"
echo ""

echo "1. 查看进程相关函数 (do_ 前缀):"
grep -E " [Tt] " /proc/kallsyms | grep -E "^.* do_" | head -10
echo ""

echo "2. 查看系统调用函数 (sys_ 前缀):"
grep -E " [Tt] " /proc/kallsyms | grep -E "^.* sys_" | head -10
echo ""

echo "3. 查看网络相关函数:"
grep -E " [Tt] " /proc/kallsyms | grep -i -E "(tcp|udp|ip|net)" | head -10
echo ""

echo "4. 查看文件系统相关函数 (vfs_ 前缀):"
grep -E " [Tt] " /proc/kallsyms | grep -E " vfs_" | head -10
echo ""

echo "5. 查看内存管理函数:"
grep -E " [Tt] " /proc/kallsyms | grep -i -E "(kmalloc|kfree|malloc|free)" | head -10
echo ""

echo "6. 查看调度器相关函数:"
grep -E " [Tt] " /proc/kallsyms | grep -i -E "(sched|schedule)" | head -10
echo ""

echo "=== 搜索特定函数示例 ==="
echo "要搜索特定函数，使用:"
echo "grep -E ' [Tt] ' /proc/kallsyms | grep 'your_function_name'"
echo ""
echo "例如，搜索 'do_fork':"
grep -E " [Tt] " /proc/kallsyms | grep "do_fork" || echo "未找到 do_fork 函数"