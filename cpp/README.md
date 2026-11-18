# RocketEbpf C/C++（libbpf）

这是不依赖 Rust/Aya 的实现：内核探针使用 C，用户态加载器使用 C++17 和 libbpf。当前覆盖：

- `exec`
- `open`
- `func hz`
- `func latency`
- `sched latency`

## Orin 构建依赖

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config clang llvm libbpf-dev libelf-dev zlib1g-dev
```

不需要安装 Rust、Cargo、nightly、Aya 或 `bpf-linker`。这些依赖中，clang/LLVM 只在编译 eBPF 对象时使用；目标机如果直接复制已编译的 `rocket-ebpf-cpp`、`rocket_ebpf.bpf.o` 以及所需动态库，就不需要保留整套编译工具。

在 Jetson AGX Orin（L4T R36.4.4 / 5.15.148-rt-tegra）上构建：

```bash
cd cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

CMake 在 ARM64 上会自动定义 `ROCKET_ORIN_R36_RT`，使用已核对的 Orin RT tracepoint 偏移。该布局不是所有 ARM64 内核通用布局。

## 使用

可执行文件会优先读取环境变量 `ROCKET_EBPF_BPF_OBJECT`，否则读取与它同目录的 `rocket_ebpf.bpf.o`。

```bash
cd cpp/build
sudo ./rocket-ebpf-cpp exec
sudo ./rocket-ebpf-cpp open
sudo ./rocket-ebpf-cpp func hz /path/to/lib.so symbol --pid 1234 --interval 1
sudo ./rocket-ebpf-cpp func latency /path/to/lib.so symbol --pid 1234 --interval 1
sudo ./rocket-ebpf-cpp func hz /path/to/lib.so 'rcl_publish' --cxx --pid 1234
sudo ./rocket-ebpf-cpp sched latency --pid 1234 --threshold-ms 5 --prev
```

监控 Docker 内的 ROS 2 进程时，应在宿主机运行并传入宿主机 PID。加载器会通过 `/proc/<pid>/maps` 和 `/proc/<pid>/root` 找到容器内共享库。

## 依赖结论

C/C++ 版本会明显减少项目专属依赖，但并非“零依赖”：

- 构建时：C/C++ 编译器、clang/LLVM、CMake、libbpf headers、libelf headers。
- 运行时：libbpf、libelf、zlib（若动态链接）以及支持 BPF/BTF/tracepoint/uprobe 的 Linux 内核。
- 若希望目标机依赖最少，可在另一台同架构、同系统 ABI 的 Orin 上构建，再复制二进制和 `.bpf.o`；也可后续将 libbpf 静态链接并把 `.bpf.o` 嵌入二进制。
