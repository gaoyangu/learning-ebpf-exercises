# kprobe 和 fentry eBPF 示例

这个示例展示了如何使用 kprobe 和 fentry 类型的 eBPF 程序来监控内核函数调用。

## 功能特性

### kprobe 探针
- `do_fork` - 监控进程创建
- `do_exit` - 监控进程退出
- `tcp_connect` - 监控 TCP 连接建立
- `__kmalloc` - 监控内存分配

### fentry 探针
- `vfs_read` - 监控文件读取操作
- `vfs_write` - 监控文件写入操作

## 编译和运行

### 前置条件
确保已经安装了必要的依赖：
```bash
# 在主目录中构建 libbpf
cd ../../libbpf/src && make install && cd ../..
```

### 编译
```bash
make
```

### 运行
```bash
# 需要 root 权限
sudo ./kernel-probe
```

程序会显示实时的事件流：
```
时间戳          PID    UID    进程名           函数名
--------------------------------------------------------
1234567890     1234   0      bash             do_fork
1234567891     1235   0      ls               vfs_read
...
```

按 Ctrl+C 停止程序。

## 查看可用的内核函数

你可以通过查看 `/proc/kallsyms` 文件来找到当前内核版本中可探测的所有内核函数：

```bash
# 查看所有内核符号
cat /proc/kallsyms

# 查看文本符号（函数）
grep -E " [Tt] " /proc/kallsyms

# 查找特定类型的函数
grep -E " [Tt] " /proc/kallsyms | grep -E "(do_|sys_|__)" | head -20

# 查找网络相关函数
grep -E " [Tt] " /proc/kallsyms | grep -i tcp | head -10

# 查找文件系统相关函数
grep -E " [Tt] " /proc/kallsyms | grep -i vfs | head -10
```

## 内核函数符号说明

`/proc/kallsyms` 文件中的每一行格式为：
```
地址 类型 符号名
```

类型标识符：
- `T` - 全局文本符号（函数）
- `t` - 局部文本符号（静态函数）
- `D` - 全局数据符号
- `d` - 局部数据符号

## 添加新的探针

要添加新的探针，请：

1. 在 `kernel-probe.bpf.c` 中添加新的 SEC 声明：
```c
SEC("kprobe/your_function_name")
int trace_your_function(struct pt_regs *ctx)
{
    // 你的代码
    return 0;
}
```

2. 在 `kernel-probe.c` 中附加新探针：
```c
link_new = bpf_program__attach(skel->progs.trace_your_function);
```

3. 重新编译：`make`

## 注意事项

- fentry 探针需要较新的内核版本（5.5+）
- 某些内核函数可能无法在某些内核版本中使用
- 运行 eBPF 程序需要 CAP_BPF 权限或 root 权限
- 在生产环境中使用时要注意性能影响

## 故障排除

如果遇到 "Failed to attach" 错误：
1. 检查内核版本是否支持该探针类型
2. 确认目标函数在当前内核中存在
3. 检查是否有足够的权限

如果遇到编译错误：
1. 确保已正确安装 libbpf
2. 检查 clang 版本是否支持 eBPF 目标
3. 确认 bpftool 可用