#include <windows.h>
#include <winhvplatform.h>
#include <winhvemulation.h>
#include <exception>
#include <stdexcept>

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <type_traits>

#include <thread>
#include <mutex>
#include <barrier>

#include <optional>
#include <string>
#include <vector>
#include <array>
#include <list>
#include <span>

#include "arm_cpu_ctx.h"

#define THROW_IF_FAILED(x) do { if(auto __my_r = (x); FAILED(__my_r)) { \
    auto __my_r_s = GetLastErrorAsString(); \
    printf("err : %08lx : %s\n", __my_r, __my_r_s.c_str()); \
    assert(false); } } while(0)

namespace test {

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if(errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }
    
    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPSTR)&messageBuffer, 0, NULL);
    
    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);
    
    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}

#define ROUND_UP_TO_POWER2(Value, Alignment) \
    (((Value) + (Alignment) - 1) & ~((Alignment) - 1))

template<typename T, auto Deleter>
struct MyDeletorThingy {
    T data{};

    ~MyDeletorThingy()
    {
        Deleter(data);
    }

    T* ptr()
    {
        return &data;
    }
    T& get()
    {
        return data;
    }
};

struct unique_virtualalloc_ptr {
    void* ptr;

    operator bool() const
    {
        return ptr != nullptr;
    }

    void* get()
    {
        return ptr;
    }

    bool operator==(std::nullptr_t n) const
    {
        return ptr == nullptr;
    }
    bool operator!=(std::nullptr_t n) const
    {
        return ptr != nullptr;
    }

    ~unique_virtualalloc_ptr()
    {
        if(ptr)
            VirtualFree(ptr, 0, MEM_RELEASE);
    }

    unique_virtualalloc_ptr(void* p = nullptr)
        : ptr{p}
    {
        
    }
    unique_virtualalloc_ptr(const unique_virtualalloc_ptr& other) = delete;
    unique_virtualalloc_ptr& operator=(const unique_virtualalloc_ptr& other) = delete;
    unique_virtualalloc_ptr(unique_virtualalloc_ptr&& other)
        : ptr{other.ptr}
    {
        other.ptr = nullptr;
    }
    unique_virtualalloc_ptr& operator=(unique_virtualalloc_ptr&& other)
    {
        ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
    }

    static unique_virtualalloc_ptr make(auto&&... args)
    {
        return unique_virtualalloc_ptr(VirtualAlloc(args...));
    }
};

using unique_whv_partition = MyDeletorThingy<WHV_PARTITION_HANDLE, &WHvDeletePartition>;

static inline constexpr SIZE_T PageSize = 0x1000;

struct MyMappedGuestPhysMemThingy {
    MyMappedGuestPhysMemThingy()
        : m_partition{nullptr}
        , m_guestPhysAddr{0}
        , m_sizeInBytes{0}
    {

    }

    MyMappedGuestPhysMemThingy(WHV_PARTITION_HANDLE Partition, const WHV_GUEST_PHYSICAL_ADDRESS guestPhysAddr, const SIZE_T sizeInBytes)
        : m_partition{Partition}
        , m_guestPhysAddr{guestPhysAddr}
        , m_sizeInBytes{sizeInBytes}
    {
        
    }

    void Reset()
    {
        if(m_partition != nullptr)
        {
            WHvUnmapGpaRange(m_partition, m_guestPhysAddr, m_sizeInBytes);
            m_partition = nullptr;
            m_guestPhysAddr = 0;
            m_sizeInBytes = 0;
        }
    }
    ~MyMappedGuestPhysMemThingy()
    {
        Reset();
    }

    MyMappedGuestPhysMemThingy(const MyMappedGuestPhysMemThingy&) = delete;
    MyMappedGuestPhysMemThingy& operator=(const MyMappedGuestPhysMemThingy&) = delete;
    MyMappedGuestPhysMemThingy(MyMappedGuestPhysMemThingy&& other)
        : m_partition{other.m_partition}
        , m_guestPhysAddr{other.m_guestPhysAddr}
        , m_sizeInBytes{other.m_sizeInBytes}
    {
        other.m_partition = nullptr;
        other.m_guestPhysAddr = 0;
        other.m_sizeInBytes = 0;
    }
    MyMappedGuestPhysMemThingy& operator=(MyMappedGuestPhysMemThingy&& other)
    {
        Reset();

        m_partition = other.m_partition;
        m_guestPhysAddr = other.m_guestPhysAddr;
        m_sizeInBytes = other.m_sizeInBytes;

        other.m_partition = nullptr;
        other.m_guestPhysAddr = 0;
        other.m_sizeInBytes = 0;

        return *this;
    }

private:
    WHV_PARTITION_HANDLE m_partition;
    WHV_GUEST_PHYSICAL_ADDRESS m_guestPhysAddr;
    SIZE_T m_sizeInBytes;
};

struct MyVirtualProcessorThingy {
    MyVirtualProcessorThingy()
        : m_Partition{nullptr}
        , m_VpIndex{-1}
    {

    }

    MyVirtualProcessorThingy(WHV_PARTITION_HANDLE Partition, int VpIndex)
        : m_Partition{Partition}
        , m_VpIndex{VpIndex}
    {
        if(auto r = WHvCreateVirtualProcessor(Partition, VpIndex, 0); r != S_OK)
        {
            auto s = GetLastErrorAsString();
            printf("WHvCreateVirtualProcessor : %08lx : %s\n", r, s.c_str());
            throw std::runtime_error("WHvCreateVirtualProcessor");
        }
    }

    void Reset()
    {
        if(m_Partition != nullptr && m_VpIndex != -1)
        {
            WHvDeleteVirtualProcessor(m_Partition, m_VpIndex);
            m_Partition = nullptr;
            m_VpIndex = -1;
        }
    }

    ~MyVirtualProcessorThingy()
    {
        Reset();
    }

    MyVirtualProcessorThingy(const MyVirtualProcessorThingy&) = delete;
    MyVirtualProcessorThingy& operator=(const MyVirtualProcessorThingy&) = delete;
    MyVirtualProcessorThingy(MyVirtualProcessorThingy&& other)
        : m_Partition{other.m_Partition}
        , m_VpIndex{other.m_VpIndex}
    {
        other.m_Partition = nullptr;
        other.m_VpIndex = -1;
    }
    MyVirtualProcessorThingy& operator=(MyVirtualProcessorThingy&& other)
    {
        Reset();

        m_Partition = other.m_Partition;
        m_VpIndex = other.m_VpIndex;

        other.m_Partition = nullptr;
        other.m_VpIndex = -1;

        return *this;
    }

    HRESULT Cancel()
    {
        return WHvCancelRunVirtualProcessor(m_Partition, m_VpIndex, 0);
    }
    HRESULT Run(WHV_RUN_VP_EXIT_CONTEXT& exitContext)
    {
        return WHvRunVirtualProcessor(m_Partition, m_VpIndex, &exitContext, sizeof(exitContext));
    }
    HRESULT GetRegisters(const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, WHV_REGISTER_VALUE* RegisterValues)
    {
        return WHvGetVirtualProcessorRegisters(m_Partition, m_VpIndex, RegisterNames, RegisterCount, RegisterValues);
    }
    HRESULT SetRegisters(const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, const WHV_REGISTER_VALUE* RegisterValues)
    {
        return WHvSetVirtualProcessorRegisters(m_Partition, m_VpIndex, RegisterNames, RegisterCount, RegisterValues);
    }
    HRESULT TranslateGva(WHV_GUEST_VIRTUAL_ADDRESS Gva, WHV_TRANSLATE_GVA_FLAGS TranslateFlags, WHV_TRANSLATE_GVA_RESULT* res, WHV_GUEST_PHYSICAL_ADDRESS* Gpa)
    {
        WHvTranslateGva(m_Partition, m_VpIndex, Gva, TranslateFlags, res, Gpa);
    }

private:
    WHV_PARTITION_HANDLE m_Partition;
    int m_VpIndex;
};

struct MyPartitionThingy {

    MyPartitionThingy()
    {
        if(auto r = WHvCreatePartition(&m_partition); r != S_OK)
        {
            auto s = GetLastErrorAsString();
            printf("WHvCreatePartition : %08lx : %s\n", r, s.c_str());
            throw std::runtime_error("WHvCreatePartition");
        }
    }
    ~MyPartitionThingy()
    {
        WHvDeletePartition(m_partition);
    }

    WHV_PARTITION_HANDLE& get()
    {
        return m_partition;
    }

    // SizeInBytes should be page-aligned
    [[nodiscard]] static unique_virtualalloc_ptr AllocateForGuestUsage(SIZE_T SizeInBytes)
    {
        assert(ROUND_UP_TO_POWER2(SizeInBytes, PageSize) == SizeInBytes);
        return unique_virtualalloc_ptr::make(nullptr, SizeInBytes, MEM_RESERVE, PAGE_NOACCESS);
    }
    [[nodiscard]] MyMappedGuestPhysMemThingy MapToGuestPhysical(unique_virtualalloc_ptr& hostPtr, SIZE_T OffsetInBytes, const WHV_GUEST_PHYSICAL_ADDRESS guestPhysAddr, const SIZE_T sizeInBytes, const WHV_MAP_GPA_RANGE_FLAGS flags)
    {
        THROW_IF_FAILED(WHvMapGpaRange(m_partition, static_cast<void*>(static_cast<unsigned char*>(hostPtr.get()) + OffsetInBytes), guestPhysAddr, sizeInBytes, flags));
        return MyMappedGuestPhysMemThingy(m_partition, guestPhysAddr, sizeInBytes);
    }
    // OffsetInBytes and SizeInBytes should be page-aligned
    [[nodiscard]] static void* PrepareForHostUsageRaw(unique_virtualalloc_ptr& ptr, SIZE_T OffsetInBytes, SIZE_T SizeInBytes, DWORD Protection)
    {
        return VirtualAlloc(static_cast<void*>(static_cast<unsigned char*>(ptr.get()) + OffsetInBytes), SizeInBytes, MEM_COMMIT, Protection);
    }
    template<typename T>
    requires std::is_trivial_v<T>
    [[nodiscard]] static T* PrepareForHostUsage(unique_virtualalloc_ptr& ptr, SIZE_T OffsetInBytes, SIZE_T SizeInBytes, DWORD Protection)
    {
        return static_cast<T*>(PrepareForHostUsageRaw(ptr, OffsetInBytes, SizeInBytes, Protection));
    }

private:
    WHV_PARTITION_HANDLE m_partition;
};

struct MyEmulatorThingy {
    explicit MyEmulatorThingy(const WHV_EMULATOR_CALLBACKS *Callbacks)
    {
        if(auto r = WHvEmulatorCreateEmulator(Callbacks, &m_emulator); r != S_OK)
        {
            auto s = GetLastErrorAsString();
            printf("WHvEmulatorCreateEmulator : %08lx : %s\n", r, s.c_str());
            throw std::runtime_error("WHvEmulatorCreateEmulator");
        }
    }
    ~MyEmulatorThingy()
    {
        WHvEmulatorDestroyEmulator(m_emulator);
    }

    WHV_EMULATOR_HANDLE& get()
    {
        return m_emulator;
    }

private:
    WHV_EMULATOR_HANDLE m_emulator;
};

struct MyPageThingy {
    static constexpr inline int PAGE_SIZE = 0x1000; // 4096
    static constexpr inline int NUM_ENTRIES = PAGE_SIZE / sizeof(uint64_t);
    uint64_t entries[NUM_ENTRIES];

    struct MyFlagsThingy {
        bool present{false};
        bool allow_write{false};
        bool disable_execute{false};
    };
    void clear()
    {
        std::fill_n(entries, NUM_ENTRIES, 0);
    }
    static uint64_t make_entry(const uint64_t ptr, const uint64_t page_index, const MyFlagsThingy flags, const uint64_t extra_flags = 0)
    {
        uint64_t out = ptr + page_index * PAGE_SIZE;
        if(flags.present)
            out |= 1ull << 0;
        if(flags.allow_write)
            out |= 1ull << 1;
        if(flags.disable_execute)
            out |= 1ull << 63;
        
        out |= extra_flags;
        return out;
    }
    void skip_entry(int& index)
    {
        index++;
    }
    void set_entry(const int at_index, const uint64_t value)
    {
        if(at_index >= NUM_ENTRIES)
            throw std::runtime_error("MyPageThingy::append_entry index");
        entries[at_index] = value;
    }
    void append_entry(int& at_index, const uint64_t value)
    {
        if(at_index >= NUM_ENTRIES)
            throw std::runtime_error("MyPageThingy::append_entry index");
        entries[at_index++] = value;
    }
};

namespace virtual_memory {

struct paging {
    // from page pointed to by cr3
    uint64_t pml4_offset;
    // from page pointed to by cr3[pml4_offset]
    uint64_t pdp_offset;
    // from page pointed to by cr3[pml4_offset][pdp_offset]
    uint64_t pd_offset;
    // from page pointed to by cr3[pml4_offset][pdp_offset][pd_offset]
    uint64_t pt_offset;
    // from page pointed to by cr3[pml4_offset][pdp_offset][pd_offset][pt_offset]
    // final resolved address in physmem
    uint64_t page_offset;

    uint64_t to_page_vaddr() const
    { 
        return  (pml4_offset << 39)
                | (pdp_offset << 30)
                | (pd_offset << 21)
                | (pt_offset << 12);
    }

    uint64_t to_vaddr() const
    { 
        return  to_page_vaddr() | page_offset;
    }

    static paging from_vaddr(const uint64_t vaddr)
    {
        return paging{
            .pml4_offset = (((0x1FFull << 39) & vaddr) >> 39) & 0x1FFull,
            .pdp_offset = (((0x1FFull << 30) & vaddr) >> 30) & 0x1FFull,
            .pd_offset = (((0x1FFull << 21) & vaddr) >> 21) & 0x1FFull,
            .pt_offset = (((0x1FFull << 12) & vaddr) >> 12) & 0x1FFull,
            .page_offset = (vaddr & 0xFFFull)
        };
    }
};

}

struct MyKernelThingy {
    static HRESULT CALLBACK IoPortCallback(void* ctx, WHV_EMULATOR_IO_ACCESS_INFO* IoAccess)
    {
        printf("IoPortCallback : %04x %04x %02x\n", IoAccess->Port, IoAccess->AccessSize, IoAccess->Direction);
        return S_OK;
    }
    static HRESULT CALLBACK MemoryCallback(void* ctx, WHV_EMULATOR_MEMORY_ACCESS_INFO* MemoryAccess)
    {
        auto& core = *(VirtualCore*)ctx;
        return core.parent_kernel->handle_mmio(core, MemoryAccess);
    }
    static HRESULT CALLBACK GetVirtualProcessorRegisters(void* ctx, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, WHV_REGISTER_VALUE* RegisterValues)
    {
        auto& core = *(VirtualCore*)ctx;
        HRESULT hr = core.vcpu.GetRegisters(RegisterNames, RegisterCount, RegisterValues);
        if (FAILED(hr)) {
            printf("GetVirtualProcessorRegisters err: %08lx\n", hr);
        }
        return hr;
    }
    static HRESULT CALLBACK SetVirtualProcessorRegisters(void* ctx, const WHV_REGISTER_NAME* RegisterNames, UINT32 RegisterCount, const WHV_REGISTER_VALUE* RegisterValues)
    {
        auto& core = *(VirtualCore*)ctx;
        HRESULT hr = core.vcpu.SetRegisters(RegisterNames, RegisterCount, RegisterValues);
        if (FAILED(hr)) {
            printf("SetVirtualProcessorRegisters err: %08lx\n", hr);
        }
        return hr;
    }
    static HRESULT CALLBACK TranslateGvaPage(void* ctx, WHV_GUEST_VIRTUAL_ADDRESS Gva, WHV_TRANSLATE_GVA_FLAGS TranslateFlags, WHV_TRANSLATE_GVA_RESULT_CODE* TranslationResult, WHV_GUEST_PHYSICAL_ADDRESS* Gpa)
    {
        auto& core = *(VirtualCore*)ctx;
        WHV_TRANSLATE_GVA_RESULT res;
        HRESULT hr = core.vcpu.TranslateGva(Gva, TranslateFlags, &res, Gpa);
        if (FAILED(hr)) {
            printf("TranslateGvaPage err: %08lx\n", hr);
        } else {
            *TranslationResult = res.ResultCode;
        }

        return hr;
    }

    static inline constexpr int NUM_CORES = 2;
    static inline constexpr WHV_EMULATOR_CALLBACKS EMU_WIN_CALLBACKS = {
        .Size = sizeof(WHV_EMULATOR_CALLBACKS),
        .Reserved = 0,
        .WHvEmulatorIoPortCallback = &MyKernelThingy::IoPortCallback,
        .WHvEmulatorMemoryCallback = &MyKernelThingy::MemoryCallback,
        .WHvEmulatorGetVirtualProcessorRegisters = &MyKernelThingy::GetVirtualProcessorRegisters,
        .WHvEmulatorSetVirtualProcessorRegisters = &MyKernelThingy::SetVirtualProcessorRegisters,
        .WHvEmulatorTranslateGvaPage = &MyKernelThingy::TranslateGvaPage,
    };

    struct MyProcessThingy {
        unique_virtualalloc_ptr m_code_pages_ptr, m_ram_pages_ptr;
        std::optional<MyMappedGuestPhysMemThingy> m_ram_pages_guest; // ram mappings for this process
        MyPageThingy* m_ram_pages_host{nullptr};
        std::optional<MyMappedGuestPhysMemThingy> m_code_pages_guest; // code mappings for this process
        uint8_t* m_code_pages_host{nullptr};

        struct SaveContext {
            static constexpr inline WHV_REGISTER_NAME REGISTERS_CTX_SWITCH[] = {
                WHvX64RegisterRax,
                WHvX64RegisterRcx,
                WHvX64RegisterRdx,
                WHvX64RegisterRbx,
                WHvX64RegisterRsp,
                WHvX64RegisterRbp,
                WHvX64RegisterRsi,
                WHvX64RegisterRdi,
                WHvX64RegisterR8,
                WHvX64RegisterR9,
                WHvX64RegisterR10,
                WHvX64RegisterR11,
                WHvX64RegisterR12,
                WHvX64RegisterR13,
                WHvX64RegisterR14,
                WHvX64RegisterR15,
                WHvX64RegisterRip,
                WHvX64RegisterRflags,
            };
            static constexpr inline int REGISTERS_XSAVE_SIZE = 16384;
            WHV_REGISTER_VALUE values[std::size(REGISTERS_CTX_SWITCH)];
            uint8_t xsave_value[REGISTERS_XSAVE_SIZE];
        };

        struct MyThreadThingy {
            SaveContext saved;
        };
        std::list<MyThreadThingy> m_threads;
    };
    using ProcessId = MyProcessThingy*;

    struct VirtualCore {
        MyKernelThingy* parent_kernel;
        MyVirtualProcessorThingy vcpu;
        int vcpu_id;
        bool started;
        std::jthread core_thread;
        std::mutex core_mutex;
        std::barrier<void()> start_barrier;
        /*
         * PML4 is unchanging
         * PDP 0 PD 0 will contain the core's active process' base mappings
         * X = <after the N cores PML4 and PDP 0>
         * Y = (active process' code size in bytes) >> (9 + 12)
         * PDP 0 PD (X through X+Y) will contain the core's active process' code mapping
         */
        MyPageThingy* base_pml4_page;
        std::optional<MyMappedGuestPhysMemThingy> base_pagetable_guest;
        uint64_t pagetable_start_paddr;
        arm_cpu_ctx* vcpu_arm_context;
        uint8_t* vcpu_stack;
        uint64_t vcpu_arm_context_guest_vaddr;
        uint64_t vcpu_stack_guest_vaddr;
        uint64_t vcpu_code_guest_vaddr;

        VirtualCore(MyKernelThingy& kernel, int core_id);
        void core_thread_func(std::stop_token token);
    };

    MyKernelThingy();
    MyKernelThingy::MyKernelThingy(std::span<const unsigned char> code);
    ~MyKernelThingy()
    {
        for(auto& core : m_virtual_cores)
        {
            core->core_thread.request_stop();
            core->vcpu.Cancel();
            core->start_barrier.arrive_and_wait();
            core->core_thread.join();
        }
    }

    /// @brief  
    /// @return Process ID
    [[nodiscard]] int load_process(std::string code_path)
    {

    }

    void start_process_on_core(int pid, int core_id)
    {
        auto& core = *(m_virtual_cores[core_id]);

        WHV_REGISTER_NAME initialNames[] = {
            WHvX64RegisterRip,
            WHvX64RegisterRsp,
            WHvX64RegisterRbp,
            WHvX64RegisterRcx,
        };
        WHV_REGISTER_VALUE initialValues[std::size(initialNames)] = {};
        
        initialValues[0].Reg64 = core.vcpu_code_guest_vaddr;
        initialValues[1].Reg64 = core.vcpu_stack_guest_vaddr;
        initialValues[2].Reg64 = core.vcpu_stack_guest_vaddr;
        initialValues[3].Reg64 = core.vcpu_arm_context_guest_vaddr;
        THROW_IF_FAILED(core.vcpu.SetRegisters(initialNames, std::size(initialNames), initialValues));
    }

    void yield(int core_id)
    {

    }

    void start_core(int core_id)
    {
        auto& core = *(m_virtual_cores[core_id]);

        WHV_REGISTER_NAME initialNames[] = {WHvX64RegisterCs,
                                            WHvX64RegisterDs,
                                            WHvX64RegisterGdtr,
                                            WHvX64RegisterCr0,
                                            WHvX64RegisterCr3,
                                            WHvX64RegisterCr4,
                                            WHvX64RegisterEfer,
                                            WHvX64RegisterPat,
                                            };

        WHV_REGISTER_VALUE initialValues[std::size(initialNames)] = {};
        initialValues[0].Segment.Base = 0;
        initialValues[0].Segment.Limit = codeSegmentLimit;
        initialValues[0].Segment.Selector = gdtCodeSegmentEntryIndex * sizeof(uint64_t);
        initialValues[0].Segment.Attributes = codeSegmentAttributes;
        initialValues[1].Segment.Base = 0;
        initialValues[1].Segment.Limit = dataSegmentLimit;
        initialValues[1].Segment.Selector = gdtDataSegmentEntryIndex * sizeof(uint64_t);
        initialValues[1].Segment.Attributes = dataSegmentAttributes;
        initialValues[2].Table.Base = gdt_start_paddr;
        initialValues[2].Table.Limit = (gdtCount * sizeof(uint64_t)) - 1;
        initialValues[3].Reg64 = cr0;
        initialValues[4].Reg64 = m_virtual_cores[core_id]->pagetable_start_paddr;
        initialValues[5].Reg64 = cr4;
        initialValues[6].Reg64 = efer;
        initialValues[7].Reg64 = pat;

        THROW_IF_FAILED(core.vcpu.SetRegisters(initialNames, std::size(initialNames), initialValues));
        core.started = true;
        core.start_barrier.arrive_and_wait();
    }

    void stop()
    {
        m_requested_exit = true;
    }

    bool requested_exit() const
    {
        return m_requested_exit;
    }

    void run_cores()
    {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1000ms);
        stop();
    }

    HRESULT handle_mmio(VirtualCore& core, WHV_EMULATOR_MEMORY_ACCESS_INFO* MemoryAccess)
    {
        return S_OK;
    }

    void handle_svc(VirtualCore& core, const int svc_id, arm_cpu_ctx* ctx)
    {
        if(svc_id == -1)
        {
            printf("STOP SVC ID (-1) REQUESTED\n");
            stop();
        }
    }

private:
    bool m_requested_exit{false};
    MyPartitionThingy m_partition;

    unique_virtualalloc_ptr m_fcram_ptr, m_vram_ptr, m_dspmem_ptr;
    unique_virtualalloc_ptr m_base_pagetable_gdt_ptr;

    uint8_t* m_fcram_host{nullptr};
    uint8_t* m_vram_host{nullptr};
    uint8_t* m_dspmem_host{nullptr};
    uint64_t* m_gdt_page{nullptr};
    uint32_t* m_sync_page{nullptr};

    // always put the mapped guest physaddr after the virtualalloc_ptr they're from
    std::optional<MyMappedGuestPhysMemThingy> m_fcram_guest, m_vram_guest, m_dspmem_guest;
    std::optional<MyMappedGuestPhysMemThingy> m_gdt_guest, m_sync_guest;
    std::vector<MyProcessThingy> m_processes;

    MyEmulatorThingy m_emulator{&MyKernelThingy::EMU_WIN_CALLBACKS};
    std::array<std::optional<VirtualCore>, NUM_CORES> m_virtual_cores;

    // Setup the GDT for long mode. For the purposes of this sample, a simple GDT is created with
    // a NULL entry followed by a CS entry.
    static inline constexpr SIZE_T gdtCount = 3;
    // GDT NULL entry
    static inline constexpr UINT64 gdtNullEntryValue = 0;
    static inline constexpr UINT64 gdtNullEntryIndex = 0;
    // GDT CS entry - page granularity, long, present, type code, execute\read\accessed
    static inline constexpr UINT16 codeSegmentAttributes = 0xa09b;
    static inline constexpr UINT64 gdtCodeSegmentEntryValue = ((UINT64)codeSegmentAttributes << 20);
    static inline constexpr UINT64 gdtCodeSegmentEntryIndex = 1;
    // GDT DS entry - page granularity, present, type data, read\write\accessed
    static inline constexpr UINT16 dataSegmentAttributes = 0x8093;
    static inline constexpr UINT64 gdtDataSegmentEntryValue = ((UINT64)dataSegmentAttributes << 20);
    static inline constexpr UINT64 gdtDataSegmentEntryIndex = 2;

    // Initial virtual processor state.
    // Cs limit (base is forced to 0 for long mode)
    static inline constexpr UINT32 codeSegmentLimit = 0xFFFFFFFF;
    // Ds limit (base is forced to 0 for long mode)
    static inline constexpr UINT32 dataSegmentLimit = 0xFFFFFFFF;
    // CR0 bits - PG and PE
    static inline constexpr UINT32 cr0 = 0x80000001;
    // CR4 bits - PAE
    static inline constexpr UINT32 cr4 = 0x20;
    // EFER bits - NXE, LMA, LME
    static inline constexpr UINT32 efer = 0xD00;
    // PAT bits - after reset (default) value.
    static inline constexpr uint64_t pat = 0x0007040600070406ull;

    static inline constexpr uint64_t gdt_start_paddr = 1ull << 32;
    static inline constexpr uint64_t pagetable_start_paddr = 2ull << 32;
    static inline constexpr uint64_t codepages_start_paddr = pagetable_start_paddr + ((uint64_t)(NUM_CORES) << 32);
};

MyKernelThingy::VirtualCore::VirtualCore(MyKernelThingy& kernel, int core_id)
    : parent_kernel{&kernel}
    , vcpu{kernel.m_partition.get(), core_id}
    , vcpu_id{core_id}
    , started{false}
    , start_barrier{2, []() -> void {}}
    , base_pml4_page{nullptr}
    , pagetable_start_paddr{0}
    , vcpu_arm_context{nullptr}
    , vcpu_stack{nullptr}
    , vcpu_arm_context_guest_vaddr{0}
    , vcpu_stack_guest_vaddr{0}
    , vcpu_code_guest_vaddr{0}
{

    core_thread = std::jthread(&core_thread_func, this);
}

void MyKernelThingy::VirtualCore::core_thread_func(std::stop_token token)
{
    start_barrier.arrive_and_wait();
    start_barrier.arrive_and_drop();

    while(!token.stop_requested())
    {
        WHV_RUN_VP_EXIT_CONTEXT exitContext = {};
        THROW_IF_FAILED(vcpu.Run(exitContext));
        if (exitContext.ExitReason == WHvRunVpExitReasonException && exitContext.VpException.ExceptionType == WHvX64ExceptionTypeBreakpointTrap)
        {
            printf("svc (int 3) detected for core %d\n", vcpu_id);

            // Display the contents of the registers set by the code sequence.
            WHV_REGISTER_NAME names[] = {WHvX64RegisterRdx};
            WHV_REGISTER_VALUE values[std::size(names)] = {};
            THROW_IF_FAILED(vcpu.GetRegisters(names, std::size(names), values));

            const int32_t svc_id = values[0].Reg32;
            printf("svc id: %d\n", svc_id);
            parent_kernel->handle_svc(*this, svc_id, vcpu_arm_context);
        }
        else if (exitContext.ExitReason == WHvRunVpExitReasonMemoryAccess)
        {
            WHV_EMULATOR_STATUS emu_status{};
            auto r = WHvEmulatorTryMmioEmulation(parent_kernel->m_emulator.get(), this, &exitContext.VpContext, &exitContext.MemoryAccess, &emu_status);
            printf("WHvRunVpExitReasonMemoryAccess: %08lx ; %08x = %d\n", r, emu_status.AsUINT32, emu_status.EmulationSuccessful);
        }
        else if (exitContext.ExitReason == WHvRunVpExitReasonException && exitContext.VpException.ExceptionType == WHvX64ExceptionTypePageFault)
        {
            printf("pagefault: %016llx\n", exitContext.VpException.ExceptionParameter);
            break;
        }
        else if(exitContext.ExitReason == WHvRunVpExitReasonCanceled)
        {
            printf("Cancel requested for core %d\n", vcpu_id);
            break;
        }
        else
        {
            printf("Exit reason %d for core %d\n", exitContext.ExitReason, vcpu_id);
            break;
        }
    }
}

/// Sample demonstrating executing code on a virtual processor in long mode (64 bit). A partition
/// with a single virtual processor is created and configured to execute a code sequence that loads
/// registers rax, rcx, rdx, rbx, r8, and r9 with the byte values of 'W', 'H', 'v', '6', '4' '!'
/// followed by a breakpoint trap. For the processor to execute directly in long mode, the
/// following state is configured which should be adjusted as needed outside of this sample:
///     Page tables - identity mapping for first 2MB of partition address space.
///     Gdt - NULL entry followed by Cs entry.
///     Code region - x64 opcodes mapped into the partition address space.
///     Rip - start of the code region.
///     Cs - references the Cs entry in the Gdt with long mode access.
///     Gdtr - describes the Gdt.
///     Cr0 - bits required for long mode.
///     Cr3 - references the start of the page tables
///     Cr4 - bites required for long mode
///     Efer - bits required for long mode
///     Pat - bits required for long mode
///
/// N.B. The state above reflects a processor already running in long mode. Entering long mode from
///     protected mode through code execution does not set the state above explicitly as some
///     settings are controlled by the processor.
///
/// During execution, the virtual processor will exit for the breakpoint trap and the register
/// state of rcx, rdx, rbx, r8, and r9 will be printed to the screen.
MyKernelThingy::MyKernelThingy()
{
    WHV_PARTITION_PROPERTY property{};
    property.ProcessorCount = NUM_CORES;
    THROW_IF_FAILED(WHvSetPartitionProperty(m_partition.get(), WHvPartitionPropertyCodeProcessorCount, &property, sizeof(property)));

    property = {};
    property.LocalApicEmulationMode = WHvX64LocalApicEmulationModeXApic;
    THROW_IF_FAILED(WHvSetPartitionProperty(m_partition.get(), WHvPartitionPropertyCodeLocalApicEmulationMode, &property, sizeof(property)));

    // Enable exits on the breakpoint trap (int 3 instruction) for the purposes of this sample.
    property = {};
    property.ExtendedVmExits.ExceptionExit = 1;
    THROW_IF_FAILED(WHvSetPartitionProperty(m_partition.get(), WHvPartitionPropertyCodeExtendedVmExits, &property, sizeof(property)));

    property = {};
    property.ExceptionExitBitmap = (1ull << WHvX64ExceptionTypeDebugTrapOrFault) | (1ull << WHvX64ExceptionTypeBreakpointTrap) | (1 << WHvX64ExceptionTypePageFault);
    THROW_IF_FAILED(WHvSetPartitionProperty(m_partition.get(), WHvPartitionPropertyCodeExceptionExitBitmap, &property, sizeof(property)));

    // Setup the partition and create the virtual processor.
    THROW_IF_FAILED(WHvSetupPartition(m_partition.get()));

    // Allocate and map the address space of the partition with a single allocation. When possible,
    // multiple allocations and mappings should be coalesced as they require additional tracking
    // structures. The permissions of the individual pages are enforced by the allocation, the
    // mapping, and the guest's page table. In this sample the mapping is done with full
    // permissions so the permissions are determined by the allocation (host's page table) and the
    // guest's page table.
    const size_t fcram_size_bytes = 0x0800'0000; // 128 MiB
    const size_t vram_size_bytes = 0x0060'0000; // 6 MiB
    const size_t dspmem_size_bytes = 0x0008'0000; // 512 KiB
    const uint64_t fcram_start_paddr = 0x2000'0000;
    const uint64_t vram_start_paddr = 0x1800'0000;
    const uint64_t dspmem_start_paddr = 0x1ff0'0000;

    m_fcram_ptr = MyPartitionThingy::AllocateForGuestUsage(fcram_size_bytes);
    m_vram_ptr = MyPartitionThingy::AllocateForGuestUsage(vram_size_bytes);
    m_dspmem_ptr = MyPartitionThingy::AllocateForGuestUsage(dspmem_size_bytes);
    m_fcram_host = MyPartitionThingy::PrepareForHostUsage<uint8_t>(m_fcram_ptr, 0, fcram_size_bytes, PAGE_READWRITE);
    m_vram_host = MyPartitionThingy::PrepareForHostUsage<uint8_t>(m_vram_ptr, 0, fcram_size_bytes, PAGE_READWRITE);
    m_dspmem_host = MyPartitionThingy::PrepareForHostUsage<uint8_t>(m_dspmem_ptr, 0, fcram_size_bytes, PAGE_READWRITE);
    m_fcram_guest = m_partition.MapToGuestPhysical(m_fcram_ptr, 0, fcram_start_paddr, fcram_size_bytes, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    m_vram_guest = m_partition.MapToGuestPhysical(m_vram_ptr, 0, vram_size_bytes, vram_size_bytes, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    m_dspmem_guest = m_partition.MapToGuestPhysical(m_dspmem_ptr, 0, dspmem_start_paddr, dspmem_size_bytes, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);

    const size_t page_count = (
        1 // [0] PML4
        + 1 // [1] PDP
        + 1 // [2] PD ctx and stack (PDP off 4)
        + 1 // [3] PT ctx and stack
        + 1 // [4] page vcpu arm ctx
        + 1 // [5] page vcpu x86 stack
        + 4 // [7-10] PD base 30 bits (PDP off 0-3)
        + 1 // [6] PD code (PDP off 5)
        + 8 // [11-18] PT code (PDP off 5)
        /* page base 30 bits allocated per process <- pointed to in PTs allocated per process <- pointed to in PD [7-10] */
        /* page code allocated per process <- pointed to in PT [11-18] */
    );
    m_base_pagetable_gdt_ptr = MyPartitionThingy::AllocateForGuestUsage((1 + 1 + NUM_CORES * page_count) * MyPageThingy::PAGE_SIZE);
    m_gdt_page = MyPartitionThingy::PrepareForHostUsage<uint64_t>(m_base_pagetable_gdt_ptr, 0, MyPageThingy::PAGE_SIZE, PAGE_READWRITE);
    m_gdt_guest = m_partition.MapToGuestPhysical(m_base_pagetable_gdt_ptr, 0, gdt_start_paddr, MyPageThingy::PAGE_SIZE, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    m_sync_page = MyPartitionThingy::PrepareForHostUsage<uint32_t>(m_base_pagetable_gdt_ptr, MyPageThingy::PAGE_SIZE, MyPageThingy::PAGE_SIZE, PAGE_READWRITE);
    m_sync_guest = m_partition.MapToGuestPhysical(m_base_pagetable_gdt_ptr, MyPageThingy::PAGE_SIZE, gdt_start_paddr + MyPageThingy::PAGE_SIZE, MyPageThingy::PAGE_SIZE, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);

    m_gdt_page[gdtNullEntryIndex] = gdtNullEntryValue;
    m_gdt_page[gdtCodeSegmentEntryIndex] = gdtCodeSegmentEntryValue;
    m_gdt_page[gdtDataSegmentEntryIndex] = gdtDataSegmentEntryValue;

    for(int core_index = 0; core_index < NUM_CORES; ++core_index)
    {
        auto& core = m_virtual_cores[core_index].emplace(*this, core_index);
        const size_t page_offset = (1 + 1 + core_index * page_count) * MyPageThingy::PAGE_SIZE;
        core.pagetable_start_paddr = pagetable_start_paddr + ((uint64_t)(core_index) << 32);
        core.base_pml4_page = MyPartitionThingy::PrepareForHostUsage<MyPageThingy>(m_base_pagetable_gdt_ptr, page_offset, page_count * MyPageThingy::PAGE_SIZE, PAGE_READWRITE);
        core.base_pagetable_guest = m_partition.MapToGuestPhysical(m_base_pagetable_gdt_ptr, page_offset, core.pagetable_start_paddr, page_count * MyPageThingy::PAGE_SIZE, WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);

        MyPageThingy& pageTables_PML4 = core.base_pml4_page[0];
        pageTables_PML4.clear();
        pageTables_PML4.set_entry(0, MyPageThingy::make_entry(core.pagetable_start_paddr, 1, {.present = true, .allow_write = true}));

        MyPageThingy& pageTables_PDP = core.base_pml4_page[1];
        pageTables_PDP.clear();
        // vaddr in 0x0xxx'xxxx, 0x1xxx'xxxx, 0x2xxx'xxxx, 0x3xxx'xxxx -> these indices will get rewritten a lot for context switching
        // for now, cleared so nothing can access there
        // every process will have its own PDs and PTs allocated for itself, to simplify this
        pageTables_PDP.set_entry(0, MyPageThingy::make_entry(core.pagetable_start_paddr, 7, {.present = true, .allow_write = true}));
        core.base_pml4_page[7].clear();
        pageTables_PDP.set_entry(1, MyPageThingy::make_entry(core.pagetable_start_paddr, 8, {.present = true, .allow_write = true}));
        core.base_pml4_page[8].clear();
        pageTables_PDP.set_entry(2, MyPageThingy::make_entry(core.pagetable_start_paddr, 9, {.present = true, .allow_write = true}));
        core.base_pml4_page[9].clear();
        pageTables_PDP.set_entry(3, MyPageThingy::make_entry(core.pagetable_start_paddr, 10, {.present = true, .allow_write = true}));
        core.base_pml4_page[10].clear();

        // vaddr in 0x1'0xxx'xxxx
        pageTables_PDP.set_entry(4, MyPageThingy::make_entry(core.pagetable_start_paddr, 2, {.present = true, .allow_write = true}));
        // vaddr in 0x1'4xxx'xxxx -> code for the process
        pageTables_PDP.set_entry(5, MyPageThingy::make_entry(core.pagetable_start_paddr, 6, {.present = true, .allow_write = true}));
    
        MyPageThingy& pageTables_PDP_PD_4 = core.base_pml4_page[2];
        pageTables_PDP_PD_4.clear();
        // vaddr in 0x1'000x'xxxx
        pageTables_PDP_PD_4.set_entry(0, MyPageThingy::make_entry(core.pagetable_start_paddr, 3, {.present = true, .allow_write = true}));

        MyPageThingy& pageTables_PDP_PD_4_PT_0 = core.base_pml4_page[3];
        pageTables_PDP_PD_4_PT_0.clear();
        // vaddr in 0x1'0000'0xxx -> vcpu arm context page
        pageTables_PDP_PD_4_PT_0.set_entry(0, MyPageThingy::make_entry(core.pagetable_start_paddr, 4, {.present = true, .allow_write = true}));
        // vaddr in 0x1'0000'1xxx -> vcpu stack page
        pageTables_PDP_PD_4_PT_0.set_entry(1, MyPageThingy::make_entry(core.pagetable_start_paddr, 5, {.present = true, .allow_write = true}));
        // vaddr in 0x1'0000'2xxx -> common sync page
        pageTables_PDP_PD_4_PT_0.set_entry(2, MyPageThingy::make_entry(gdt_start_paddr, 1, {.present = true, .allow_write = true}));

        core.vcpu_arm_context = (arm_cpu_ctx*)&core.base_pml4_page[4];
        core.vcpu_stack = (unsigned char*)&core.base_pml4_page[5];
        core.vcpu_arm_context_guest_vaddr = 0x1'0000'0000ull;
        core.vcpu_stack_guest_vaddr = 0x1'0000'1000ull;
        core.vcpu_code_guest_vaddr = 0x1'4000'0000ull;

        MyPageThingy& pageTables_PDP_PD_5 = core.base_pml4_page[6];
        pageTables_PDP_PD_5.clear();
        // vaddr in 0x1'400x'xxxx, 0x1'402x'xxxx, 0x1'404x'xxxx, 0x1'406x'xxxx, 0x1'408x'xxxx, 0x1'40Ax'xxxx, 0x1'40Cx'xxxx, 0x1'40Ex'xxxx
        // the PTs for these PDs are preallocated and only need to be modified to point to the code pages allocated per-process
        auto set_PDP_PD_5_PTs = [&](const int pd_5_index, const int page_offset) {
            pageTables_PDP_PD_5.set_entry(pd_5_index, MyPageThingy::make_entry(core.pagetable_start_paddr, page_offset, {.present = true, .allow_write = true}));
            MyPageThingy& pageTables_PDP_PD_5_PT_x = core.base_pml4_page[page_offset];
            pageTables_PDP_PD_5_PT_x.clear();
        };
        for(int idx = 0, poff = 11; idx < 8; ++idx, ++poff)
            set_PDP_PD_5_PTs(idx, poff);
    }

    // TODO: MULTIPROCESS WITH SEPARATE RAM VADDRS (can just replace PML4 index 0 PDP index 0 entry)
    // TODO: MULTIPROCESS WITH SEPARATE CODE VADDRS (can just replace PML4 index 1 PDP index 0 PD index 2 entry)
    // TODO: MULTIPROCESS WITH SEPARATE CODE VADDRS THAT CHECK ANOTHER VADDR FOR BASE EXECUTABILITY (can just replace PML4 index 1 PDP index 0 PD index 2 entry)
}

} // namespace WHvSample

// Entry point for sample
int main(int argc, char **argv)
try
{
    test::MyKernelThingy sys;
    auto init_process_pid = sys.load_process("initprocess.bin");
    sys.start_process_on_core(init_process_pid, 0);
    while(!sys.requested_exit())
    {
        sys.run_cores();
    }
}
catch (std::exception& e)
{
    fprintf(stderr, "exception: %s\n", e.what());
    return EXIT_FAILURE;
}

