#include "rocket_ebpf.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cxxabi.h>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

static std::atomic_bool stop_requested{false};

static void on_signal(int) { stop_requested.store(true); }

[[noreturn]] static void fail(const std::string &message)
{
    throw std::runtime_error(message);
}

static long parse_long(const std::string &text, const char *name)
{
    std::size_t pos = 0;
    long value;
    try {
        value = std::stol(text, &pos, 10);
    } catch (...) {
        fail(std::string("参数 ") + name + " 不是整数: " + text);
    }
    if (pos != text.size())
        fail(std::string("参数 ") + name + " 不是整数: " + text);
    return value;
}

static std::string error_string(int error)
{
    if (error < 0)
        error = -error;
    return std::strerror(error);
}

#ifndef ROCKET_EMBEDDED_BPF
static fs::path executable_dir()
{
    std::vector<char> buffer(4096);
    const ssize_t n = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
    if (n < 0)
        return fs::current_path();
    buffer[static_cast<std::size_t>(n)] = '\0';
    return fs::path(buffer.data()).parent_path();
}

static fs::path bpf_object_path() { return executable_dir() / "rocket_ebpf.bpf.o"; }
#endif

#ifdef ROCKET_EMBEDDED_BPF
extern "C" {
extern const unsigned char _binary_rocket_ebpf_bpf_o_start[];
extern const unsigned char _binary_rocket_ebpf_bpf_o_end[];
}
#endif

struct ObjectDeleter {
    void operator()(bpf_object *object) const
    {
        if (object)
            bpf_object__close(object);
    }
};
using ObjectPtr = std::unique_ptr<bpf_object, ObjectDeleter>;

struct LinkDeleter {
    void operator()(bpf_link *link) const
    {
        if (link)
            bpf_link__destroy(link);
    }
};
using LinkPtr = std::unique_ptr<bpf_link, LinkDeleter>;

struct RingDeleter {
    void operator()(ring_buffer *ring) const
    {
        if (ring)
            ring_buffer__free(ring);
    }
};
using RingPtr = std::unique_ptr<ring_buffer, RingDeleter>;

class LoadedBpf {
public:
    explicit LoadedBpf(const std::set<std::string> &program_names)
    {
        bpf_object *raw = nullptr;
        std::string source;
        if (const char *override_path = std::getenv("ROCKET_EBPF_BPF_OBJECT")) {
            source = override_path;
            raw = bpf_object__open_file(override_path, nullptr);
        } else {
#ifdef ROCKET_EMBEDDED_BPF
            const auto *begin = _binary_rocket_ebpf_bpf_o_start;
            const auto *end = _binary_rocket_ebpf_bpf_o_end;
            const std::size_t size = static_cast<std::size_t>(end - begin);
            source = "embedded rocket_ebpf.bpf.o (" + std::to_string(size) + " bytes)";
            raw = bpf_object__open_mem(begin, size, nullptr);
#else
            const fs::path path = bpf_object_path();
            source = path.string();
            raw = bpf_object__open_file(path.c_str(), nullptr);
#endif
        }
        const long open_error = libbpf_get_error(raw);
        if (open_error)
            fail("打开 eBPF 对象失败: " + source + ": " +
                 error_string(static_cast<int>(open_error)));
        object_.reset(raw);

        bpf_program *program = nullptr;
        bpf_object__for_each_program(program, object_.get()) {
            const char *name = bpf_program__name(program);
            const bool enabled = name && program_names.count(name) != 0;
            const int error = bpf_program__set_autoload(program, enabled);
            if (error)
                fail("设置 eBPF program autoload 失败: " + error_string(error));
        }
        const int error = bpf_object__load(object_.get());
        if (error)
            fail("加载 eBPF 对象失败（请使用 sudo 并检查内核能力）: " + error_string(error));
    }

    bpf_program *program(const char *name)
    {
        bpf_program *value = bpf_object__find_program_by_name(object_.get(), name);
        if (!value)
            fail(std::string("找不到 eBPF program: ") + name);
        return value;
    }

    int map_fd(const char *name)
    {
        const int fd = bpf_object__find_map_fd_by_name(object_.get(), name);
        if (fd < 0)
            fail(std::string("找不到 eBPF map: ") + name);
        return fd;
    }

private:
    ObjectPtr object_;
};

static LinkPtr attach_tracepoint(bpf_program *program, const char *category, const char *name)
{
    bpf_link *raw = bpf_program__attach_tracepoint(program, category, name);
    const long error = libbpf_get_error(raw);
    if (error)
        fail(std::string("附加 tracepoint ") + category + ":" + name + " 失败: " +
             error_string(static_cast<int>(error)));
    return LinkPtr(raw);
}

static std::string basename_of(const fs::path &path) { return path.filename().string(); }

static fs::path resolve_library_path(const fs::path &requested, std::optional<pid_t> pid)
{
    if (fs::exists(requested))
        return fs::canonical(requested);
    if (!pid)
        fail("共享库不存在，且未提供 --pid: " + requested.string());

    std::ifstream maps("/proc/" + std::to_string(*pid) + "/maps");
    if (!maps)
        fail("无法读取目标进程 maps");
    const std::string wanted = basename_of(requested);
    std::string line;
    while (std::getline(maps, line)) {
        const std::size_t slash = line.find('/');
        if (slash == std::string::npos)
            continue;
        std::string mapped = line.substr(slash);
        const std::string deleted = " (deleted)";
        if (mapped.size() > deleted.size() &&
            mapped.compare(mapped.size() - deleted.size(), deleted.size(), deleted) == 0)
            mapped.resize(mapped.size() - deleted.size());
        if (basename_of(mapped) != wanted)
            continue;
        if (fs::exists(mapped))
            return mapped;
        fs::path proc_path = fs::path("/proc") / std::to_string(*pid) / "root" /
                             fs::path(mapped).relative_path();
        if (fs::exists(proc_path))
            return proc_path;
    }
    fail("未在 /proc/" + std::to_string(*pid) + "/maps 中找到共享库: " +
         requested.string());
}

struct SymbolInfo {
    std::string name;
    std::uint64_t file_offset;
};

static std::string demangle(const char *name)
{
    int status = 0;
    std::unique_ptr<char, decltype(&std::free)> value(
        abi::__cxa_demangle(name, nullptr, nullptr, &status), &std::free);
    return status == 0 && value ? value.get() : name;
}

static std::uint64_t symbol_file_offset(Elf *elf, const GElf_Ehdr &header,
                                        std::uint64_t virtual_address)
{
    for (std::size_t i = 0; i < header.e_phnum; ++i) {
        GElf_Phdr phdr{};
        if (!gelf_getphdr(elf, static_cast<int>(i), &phdr))
            continue;
        if (phdr.p_type == PT_LOAD && virtual_address >= phdr.p_vaddr &&
            virtual_address < phdr.p_vaddr + phdr.p_memsz)
            return phdr.p_offset + virtual_address - phdr.p_vaddr;
    }
    return virtual_address;
}

static SymbolInfo resolve_symbol(const fs::path &library, const std::string &query, bool cxx)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        fail("初始化 libelf 失败");
    const int fd = open(library.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fail("打开 ELF 失败: " + library.string() + ": " + std::strerror(errno));
    struct FdGuard {
        int fd;
        ~FdGuard() { close(fd); }
    } fd_guard{fd};
    Elf *raw_elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!raw_elf)
        fail("elf_begin 失败: " + std::string(elf_errmsg(-1)));
    struct ElfGuard {
        Elf *elf;
        ~ElfGuard() { elf_end(elf); }
    } elf_guard{raw_elf};

    GElf_Ehdr header{};
    if (!gelf_getehdr(raw_elf, &header))
        fail("读取 ELF header 失败");

    // Keep exact and substring matches separate.  A compiler-generated clone
    // such as `foo() [clone .cold]` contains `foo()`, but it must not make an
    // exact match for the primary function ambiguous.  This mirrors the Rust
    // implementation's exact-match-first behaviour.
    std::vector<SymbolInfo> exact_matches;
    std::vector<SymbolInfo> partial_matches;
    Elf_Scn *section = nullptr;
    while ((section = elf_nextscn(raw_elf, section)) != nullptr) {
        GElf_Shdr shdr{};
        if (!gelf_getshdr(section, &shdr) ||
            (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB))
            continue;
        Elf_Data *data = elf_getdata(section, nullptr);
        if (!data || !shdr.sh_entsize)
            continue;
        const std::size_t count = shdr.sh_size / shdr.sh_entsize;
        for (std::size_t i = 0; i < count; ++i) {
            GElf_Sym symbol{};
            if (!gelf_getsym(data, static_cast<int>(i), &symbol) || symbol.st_shndx == SHN_UNDEF)
                continue;
            const unsigned type = GELF_ST_TYPE(symbol.st_info);
            if (type != STT_FUNC
#ifdef STT_GNU_IFUNC
                && type != STT_GNU_IFUNC
#endif
            )
                continue;
            const char *name = elf_strptr(raw_elf, shdr.sh_link, symbol.st_name);
            if (!name || !*name)
                continue;
            const SymbolInfo match{name,
                                   symbol_file_offset(raw_elf, header, symbol.st_value)};
            if (!cxx) {
                if (query == name)
                    exact_matches.push_back(match);
                continue;
            }

            const std::string shown = demangle(name);
            if (query == name || query == shown)
                exact_matches.push_back(match);
            else if (shown.find(query) != std::string::npos)
                partial_matches.push_back(match);
        }
    }

    const auto deduplicate = [](std::vector<SymbolInfo> &matches) {
        std::sort(matches.begin(), matches.end(), [](const auto &a, const auto &b) {
            return std::tie(a.name, a.file_offset) < std::tie(b.name, b.file_offset);
        });
        matches.erase(
            std::unique(matches.begin(), matches.end(), [](const auto &a, const auto &b) {
                return a.name == b.name && a.file_offset == b.file_offset;
            }),
            matches.end());
    };
    deduplicate(exact_matches);
    deduplicate(partial_matches);

    // An exact raw or demangled name always wins over substring matches.  For
    // example, `foo()` wins over `foo() [clone .cold]`.
    const std::vector<SymbolInfo> &matches =
        exact_matches.empty() ? partial_matches : exact_matches;
    if (matches.empty())
        fail("ELF 中找不到符号: " + query);
    if (matches.size() != 1) {
        std::ostringstream out;
        out << "符号匹配不唯一:";
        for (const auto &item : matches)
            out << " " << item.name;
        fail(out.str());
    }
    return matches.front();
}

static LinkPtr attach_uprobe(bpf_program *program, bool retprobe, pid_t pid,
                             const fs::path &library, std::uint64_t offset)
{
    bpf_link *raw = bpf_program__attach_uprobe(program, retprobe, pid, library.c_str(), offset);
    const long error = libbpf_get_error(raw);
    if (error)
        fail("附加 uprobe 失败: " + error_string(static_cast<int>(error)));
    return LinkPtr(raw);
}

static void raise_memlock_limit()
{
    rlimit limit{RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0 && errno != EPERM)
        fail("设置 RLIMIT_MEMLOCK 失败: " + std::string(std::strerror(errno)));
}

static int trace_event_callback(void *, void *data, std::size_t size)
{
    if (size < sizeof(rocket_trace_event))
        return 0;
    const auto &event = *static_cast<const rocket_trace_event *>(data);
    if (event.kind == ROCKET_EVENT_EXEC)
        std::cout << "exec pid=" << event.pid << " tgid=" << event.tgid
                  << " comm=" << event.comm << " file=" << event.path << '\n';
    else if (event.kind == ROCKET_EVENT_OPENAT)
        std::cout << "openat pid=" << event.pid << " tgid=" << event.tgid
                  << " comm=" << event.comm << '\n';
    return 0;
}

static int run_trace(bool exec_mode)
{
    const char *program_name = exec_mode ? "sched_process_exec" : "sys_enter_openat";
    LoadedBpf bpf({program_name});
    auto link = exec_mode ? attach_tracepoint(bpf.program(program_name), "sched", "sched_process_exec")
                          : attach_tracepoint(bpf.program(program_name), "syscalls", "sys_enter_openat");
    ring_buffer *raw_ring = ring_buffer__new(bpf.map_fd("trace_events"), trace_event_callback,
                                             nullptr, nullptr);
    const long ring_error = libbpf_get_error(raw_ring);
    if (ring_error)
        fail("创建 ring buffer 失败: " + error_string(static_cast<int>(ring_error)));
    RingPtr ring(raw_ring);
    std::cerr << "已附加 " << (exec_mode ? "sched:sched_process_exec" : "syscalls:sys_enter_openat")
              << "；Ctrl-C 退出…\n";
    while (!stop_requested.load()) {
        const int error = ring_buffer__poll(ring.get(), 200);
        if (error < 0 && error != -EINTR)
            fail("轮询 ring buffer 失败: " + error_string(error));
    }
    return 0;
}

struct FuncArgs {
    fs::path library;
    std::string symbol;
    bool cxx = false;
    std::optional<pid_t> pid;
    unsigned interval = 1;
};

static FuncArgs parse_func_args(int argc, char **argv, int start)
{
    if (start + 1 >= argc)
        fail("func 需要 LIBRARY 和 SYMBOL");
    FuncArgs result;
    result.library = argv[start];
    result.symbol = argv[start + 1];
    for (int i = start + 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--cxx") {
            result.cxx = true;
        } else if ((arg == "--pid" || arg == "--interval") && i + 1 < argc) {
            const long value = parse_long(argv[++i], arg.c_str());
            if (value <= 0 || value > std::numeric_limits<int>::max())
                fail(arg + " 必须为正整数");
            if (arg == "--pid")
                result.pid = static_cast<pid_t>(value);
            else
                result.interval = static_cast<unsigned>(value);
        } else {
            fail("未知 func 参数: " + arg);
        }
    }
    return result;
}

template <typename T>
static std::vector<T> read_per_cpu(int fd, __u32 key)
{
    const int cpu_count = libbpf_num_possible_cpus();
    if (cpu_count <= 0)
        fail("无法确定 possible CPU 数量");
    const std::size_t stride = (sizeof(T) + 7u) & ~std::size_t(7u);
    std::vector<unsigned char> bytes(stride * static_cast<std::size_t>(cpu_count));
    if (bpf_map_lookup_elem(fd, &key, bytes.data()) != 0)
        fail("读取 per-CPU map 失败: " + std::string(std::strerror(errno)));
    std::vector<T> result(static_cast<std::size_t>(cpu_count));
    for (int i = 0; i < cpu_count; ++i)
        std::memcpy(&result[static_cast<std::size_t>(i)], bytes.data() + stride * i, sizeof(T));
    return result;
}

template <typename T>
static void zero_per_cpu(int fd, __u32 key)
{
    const int cpu_count = libbpf_num_possible_cpus();
    const std::size_t stride = (sizeof(T) + 7u) & ~std::size_t(7u);
    std::vector<unsigned char> zeros(stride * static_cast<std::size_t>(cpu_count));
    if (bpf_map_update_elem(fd, &key, zeros.data(), BPF_ANY) != 0)
        fail("清零 per-CPU map 失败: " + std::string(std::strerror(errno)));
}

static void wait_interval(unsigned seconds)
{
    for (unsigned i = 0; i < seconds * 10 && !stop_requested.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

static int run_func_hz(const FuncArgs &args)
{
    const fs::path library = resolve_library_path(args.library, args.pid);
    const SymbolInfo symbol = resolve_symbol(library, args.symbol, args.cxx);
    LoadedBpf bpf({"func_hz_hit"});
    auto link = attach_uprobe(bpf.program("func_hz_hit"), false, args.pid.value_or(-1), library,
                              symbol.file_offset);
    const int stats_fd = bpf.map_fd("func_hz_stats");
    const int gap_fd = bpf.map_fd("func_hz_gap");
    __u32 zero = 0;
    std::uint64_t previous = 0;
    std::cerr << "已附加 uprobe：" << library << " symbol=" << symbol.name
              << " offset=0x" << std::hex << symbol.file_offset << std::dec << "；Ctrl-C 退出…\n";
    while (!stop_requested.load()) {
        wait_interval(args.interval);
        if (stop_requested.load())
            break;
        const auto values = read_per_cpu<rocket_func_hz_cpu>(stats_fd, zero);
        std::uint64_t total = 0;
        for (const auto &value : values)
            total += value.hits;
        rocket_func_hz_gap gap{};
        if (bpf_map_lookup_elem(gap_fd, &zero, &gap) != 0)
            fail("读取 func_hz_gap 失败");
        std::cout << "hits=" << total << " (+" << (total - previous) << ") max_gap_ms="
                  << std::fixed << std::setprecision(3) << gap.max_gap_ns / 1e6 << '\n';
        previous = total;
        gap.max_gap_ns = 0;
        bpf_map_update_elem(gap_fd, &zero, &gap, BPF_ANY);
    }
    return 0;
}

static int run_func_latency(const FuncArgs &args)
{
    const fs::path library = resolve_library_path(args.library, args.pid);
    const SymbolInfo symbol = resolve_symbol(library, args.symbol, args.cxx);
    LoadedBpf bpf({"func_lat_entry", "func_lat_ret"});
    auto entry = attach_uprobe(bpf.program("func_lat_entry"), false, args.pid.value_or(-1), library,
                               symbol.file_offset);
    auto ret = attach_uprobe(bpf.program("func_lat_ret"), true, args.pid.value_or(-1), library,
                             symbol.file_offset);
    const int agg_fd = bpf.map_fd("func_lat_agg");
    __u32 zero = 0;
    std::uint64_t total_count = 0;
    std::uint64_t total_sum = 0;
    std::cerr << "已附加 uprobe + uretprobe：" << library << " symbol=" << symbol.name
              << "；Ctrl-C 退出…\n";
    while (!stop_requested.load()) {
        wait_interval(args.interval);
        if (stop_requested.load())
            break;
        const auto values = read_per_cpu<rocket_func_latency_agg>(agg_fd, zero);
        __u64 count = 0, sum = 0, minimum = UINT64_MAX, maximum = 0;
        for (const auto &value : values) {
            count += value.count;
            sum += value.sum_ns;
            if (value.count) {
                minimum = std::min(minimum, value.min_ns);
                maximum = std::max(maximum, value.max_ns);
            }
        }
        total_count += count;
        total_sum += sum;
        std::cout << "calls=" << total_count << " (+" << count << ") avg_ns="
                  << (total_count ? total_sum / total_count : 0) << " interval_avg_ns="
                  << (count ? sum / count : 0);
        if (count)
            std::cout << " interval_min_ns=" << minimum << " interval_max_ns=" << maximum;
        else
            std::cout << " interval_min_ns=n/a interval_max_ns=n/a";
        std::cout << '\n';
        zero_per_cpu<rocket_func_latency_agg>(agg_fd, zero);
    }
    return 0;
}

struct SchedArgs {
    pid_t pid = 0;
    std::uint64_t threshold_ms = 0;
    unsigned refresh_seconds = 2;
    bool prev = false;
};

static SchedArgs parse_sched_args(int argc, char **argv, int start)
{
    SchedArgs result;
    bool have_pid = false, have_threshold = false;
    for (int i = start; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--prev") {
            result.prev = true;
        } else if ((arg == "--pid" || arg == "--threshold-ms" || arg == "--task-refresh-secs") &&
                   i + 1 < argc) {
            const long value = parse_long(argv[++i], arg.c_str());
            if (value < 0 || (arg != "--threshold-ms" && value == 0))
                fail(arg + " 参数范围错误");
            if (arg == "--pid") {
                result.pid = static_cast<pid_t>(value);
                have_pid = true;
            } else if (arg == "--threshold-ms") {
                result.threshold_ms = static_cast<std::uint64_t>(value);
                have_threshold = true;
            } else {
                result.refresh_seconds = static_cast<unsigned>(value);
            }
        } else {
            fail("未知 sched 参数: " + arg);
        }
    }
    if (!have_pid || !have_threshold)
        fail("sched latency 需要 --pid 和 --threshold-ms");
    return result;
}

static std::set<__u32> task_tids(pid_t pid)
{
    std::set<__u32> result;
    const fs::path directory = fs::path("/proc") / std::to_string(pid) / "task";
    for (const auto &entry : fs::directory_iterator(directory)) {
        try {
            const unsigned long value = std::stoul(entry.path().filename().string());
            if (value <= UINT32_MAX)
                result.insert(static_cast<__u32>(value));
        } catch (...) {
        }
    }
    if (result.empty())
        fail("目标进程没有可见线程: " + std::to_string(pid));
    return result;
}

static void refresh_task_filter(int map_fd, pid_t pid)
{
    const std::set<__u32> live = task_tids(pid);
    std::vector<__u32> existing;
    __u32 current = 0, next = 0;
    int error = bpf_map_get_next_key(map_fd, nullptr, &next);
    while (error == 0) {
        existing.push_back(next);
        current = next;
        error = bpf_map_get_next_key(map_fd, &current, &next);
    }
    for (const __u32 tid : existing) {
        if (!live.count(tid))
            bpf_map_delete_elem(map_fd, &tid);
    }
    const __u8 one = 1;
    for (const __u32 tid : live) {
        if (bpf_map_update_elem(map_fd, &tid, &one, BPF_ANY) != 0)
            fail("更新线程过滤 map 失败");
    }
}

struct SchedCallbackContext {
    bool show_prev;
    std::int64_t realtime_minus_monotonic_ns;
};

static std::uint64_t clock_ns(clockid_t id)
{
    timespec value{};
    if (clock_gettime(id, &value) != 0)
        fail("clock_gettime 失败");
    return static_cast<std::uint64_t>(value.tv_sec) * 1000000000ULL + value.tv_nsec;
}

static std::string format_local_time(std::int64_t unix_ns)
{
    const std::time_t seconds = unix_ns / 1000000000LL;
    const long micros = (unix_ns % 1000000000LL) / 1000;
    std::tm local{};
    localtime_r(&seconds, &local);
    std::ostringstream out;
    out << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0')
        << std::setw(6) << micros;
    return out.str();
}

static int sched_event_callback(void *context, void *data, std::size_t size)
{
    if (size < sizeof(rocket_sched_event))
        return 0;
    const auto &event = *static_cast<const rocket_sched_event *>(data);
    const auto &config = *static_cast<const SchedCallbackContext *>(context);
    const std::int64_t wall_ns = static_cast<std::int64_t>(event.ktime_ns) +
                                 config.realtime_minus_monotonic_ns;
    std::cout << "wall_local=" << format_local_time(wall_ns) << " tid=" << event.tid
              << " cpu=" << event.cpu << " latency_ms=" << std::fixed << std::setprecision(3)
              << event.latency_ns / 1e6;
    if (config.show_prev)
        std::cout << " prev_tid=" << event.prev_tid << " prev_comm=" << event.prev_comm;
    std::cout << '\n';
    return 0;
}

static int run_sched(const SchedArgs &args)
{
    LoadedBpf bpf({"sched_lat_waking", "sched_lat_switch"});
    __u32 zero = 0;
    const rocket_sched_config config{args.threshold_ms * 1000000ULL, args.prev ? 1u : 0u, 0};
    if (bpf_map_update_elem(bpf.map_fd("sched_lat_config"), &zero, &config, BPF_ANY) != 0)
        fail("写入调度配置失败");
    const int filter_fd = bpf.map_fd("sched_lat_filter");
    refresh_task_filter(filter_fd, args.pid);
    auto waking = attach_tracepoint(bpf.program("sched_lat_waking"), "sched", "sched_waking");
    auto switching = attach_tracepoint(bpf.program("sched_lat_switch"), "sched", "sched_switch");
    SchedCallbackContext callback{args.prev,
                                  static_cast<std::int64_t>(clock_ns(CLOCK_REALTIME)) -
                                      static_cast<std::int64_t>(clock_ns(CLOCK_MONOTONIC))};
    ring_buffer *raw_ring = ring_buffer__new(bpf.map_fd("sched_lat_events"), sched_event_callback,
                                             &callback, nullptr);
    const long ring_error = libbpf_get_error(raw_ring);
    if (ring_error)
        fail("创建调度 ring buffer 失败: " + error_string(static_cast<int>(ring_error)));
    RingPtr ring(raw_ring);
    auto next_refresh = std::chrono::steady_clock::now() + std::chrono::seconds(args.refresh_seconds);
    std::cerr << "已附加 sched latency：pid=" << args.pid << " threshold_ms="
              << args.threshold_ms << "；Ctrl-C 退出…\n";
    while (!stop_requested.load()) {
        const int error = ring_buffer__poll(ring.get(), 100);
        if (error < 0 && error != -EINTR)
            fail("轮询调度 ring buffer 失败: " + error_string(error));
        if (std::chrono::steady_clock::now() >= next_refresh) {
            refresh_task_filter(filter_fd, args.pid);
            next_refresh = std::chrono::steady_clock::now() +
                           std::chrono::seconds(args.refresh_seconds);
        }
    }
    return 0;
}

static void usage(const char *program)
{
    std::cerr
        << "用法:\n"
        << "  " << program << " exec\n"
        << "  " << program << " open\n"
        << "  " << program
        << " func hz LIBRARY SYMBOL [--cxx] [--pid PID] [--interval SEC]\n"
        << "  " << program
        << " func latency LIBRARY SYMBOL [--cxx] [--pid PID] [--interval SEC]\n"
        << "  " << program
        << " sched latency --pid PID --threshold-ms MS [--task-refresh-secs SEC] [--prev]\n";
}

int main(int argc, char **argv)
{
    try {
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
        raise_memlock_limit();
        if (argc == 2 && std::string(argv[1]) == "exec")
            return run_trace(true);
        if (argc == 2 && std::string(argv[1]) == "open")
            return run_trace(false);
        if (argc >= 5 && std::string(argv[1]) == "func") {
            const FuncArgs args = parse_func_args(argc, argv, 3);
            if (std::string(argv[2]) == "hz")
                return run_func_hz(args);
            if (std::string(argv[2]) == "latency")
                return run_func_latency(args);
        }
        if (argc >= 3 && std::string(argv[1]) == "sched" && std::string(argv[2]) == "latency")
            return run_sched(parse_sched_args(argc, argv, 3));
        usage(argv[0]);
        return 2;
    } catch (const std::exception &error) {
        std::cerr << "错误: " << error.what() << '\n';
        return 1;
    }
}
