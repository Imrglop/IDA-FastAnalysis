
#include <chrono>
#include <dlfcn.h>
#include <filesystem>
#include <future>
#include <safetyhook.hpp>
#include <unordered_set>
#include <libhat.hpp>

#include "ref_scanner.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

struct FastAnalysisPlugin final : plugmod_t {
    inline static FastAnalysisPlugin* SINGLETON{};

    FastAnalysisPlugin() {
        get_proc_module();
        msg("filepath is is %s\n", std::filesystem::current_path().string().c_str());

        if (!m_mod) {
            msg("FastAnalysis is not supported for this target!\n");
            return;
        }

        init_hooks();
    }

    ~FastAnalysisPlugin() override {
        if (m_initialized_hooks)
            deinit_hooks();
    }

    bool run(size_t arg) override {
        // TODO: settings menu

        if (m_initialized_hooks)
            info("FastAnalysis is active\n");
        else
            info("FastAnalysis is not active\n");

        return true;
    }

    void get_proc_module() {
        if (inf_get_procname() == "metapc") {
#ifdef WIN32
            m_mod = hat::process::get_module("pc.dll");
#elifdef __linux__
            m_mod = hat::process::get_module("pc.so");
#endif
        }
    }

    bool init_hooks() {
        m_initialized_hooks = true;
        auto pattern = hat::compile_signature<
#ifdef WIN32
       "48 83 ec ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 44 24 38 41 b8 02 00 00 00"
#elifdef __linux__
#error Linux is not supported

        // Looks like it might be this
        "55 53 48 83 ec ? 64 48 8b 14 25 ? 00 00 00 48 89 54 ? ? ba 02"
#endif
        >();

        m_mod->for_each_segment([this](std::span<std::byte> section, hat::protection protection) {
            if (static_cast<bool>(protection & hat::protection::Execute)) {
                m_mod_text_section = section;
                return false;
            }

            return true;
        });

        hat::scan_result result = hat::find_pattern(m_mod_text_section, pattern,
            hat::scan_alignment::X16, hat::scan_hint::x86_64);

        if (!result.has_result()) {
            warning("FastAnalysis may not support this IDA version (signature result not found)\n");
            return false;
        }

        m_has_write_dref_hook = safetyhook::create_inline(result.get(), metapc_has_write_dref_hook);

        auto enable_result = m_has_write_dref_hook.enable();

        if (!enable_result.has_value()) {
            warning("Failed to enable hook, FastAnalysis will not function");
            return false;
        }

        return true;
    }

    void deinit_hooks() {
        std::unique_lock lock{m_hook_mutex};
    }

    bool get_target_text_section_bytes() {
        segment_t* segment = get_segm_by_name(".text");

        if (segment == nullptr)
            return false;

        msg("FastAnalysis: Getting %lld bytes from IDA\n", segment->size());
        m_target_text_section_bytes.resize(segment->size());

        auto start_time = std::chrono::high_resolution_clock::now();

        get_bytes(m_target_text_section_bytes.data(),
            m_target_text_section_bytes.size(),
            segment->start_ea);

        m_text_start_ea = segment->start_ea;

        auto end_time = std::chrono::high_resolution_clock::now();

        msg("FastAnalysis: Took %d ms\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
        return true;
    }

    void scan_for_refs() {
        if (m_scanned_for_refs)
            return;

        // TODO: make this a setting
        uint32_t num_threads = std::thread::hardware_concurrency();

        get_target_text_section_bytes();

        size_t section_size = m_target_text_section_bytes.size();
        size_t size_per_division = section_size / num_threads;

        auto start_time = std::chrono::high_resolution_clock::now();

        std::vector<std::future<std::unordered_set<uintptr_t>>> threads;

        std::byte* division_begin = m_target_text_section_bytes.data();

        for (int i = 0; i < num_threads; i++) {
            std::byte* division_end = division_begin + size_per_division;

            if (i != num_threads - 1) {
                // make sure we aren't cutting into the middle of an instruction
                ea_t original_ea = division_end - m_target_text_section_bytes.data() + m_text_start_ea;
                ea_t n = next_not_tail(original_ea);
                division_end += n - original_ea;
            }

            threads.emplace_back(std::async(std::launch::async, [virtual_base_addr = m_text_start_ea, division_begin, division_end] {
                return RefScanner::find_write_drefs(RefScanner::X86_64, virtual_base_addr,
                    division_begin, division_end);
            }));

            division_begin = division_end;
        }

        for (auto& thread : threads) {
            auto set = thread.get();
            m_write_drefs_to.merge(set);
        }

        auto end_time = std::chrono::high_resolution_clock::now();

        msg("FastAnalysis: finding %d write drefs took %d ms\n", m_write_drefs_to.size(),
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

        m_scanned_for_refs = true;

        // Save some memory now that we don't need the bytes anymore
        m_target_text_section_bytes.clear();
    }

    bool m_initialized_hooks = false;
    bool m_scanned_for_refs = false;

    safetyhook::InlineHook m_has_write_dref_hook{};
    std::optional<hat::process::module> m_mod;
    std::span<std::byte> m_mod_text_section;

    std::vector<std::byte> m_target_text_section_bytes;
    std::unordered_set<uintptr_t> m_write_drefs_to;
    ea_t m_text_start_ea{};

    std::mutex m_hook_mutex;

    inline static void* return_metapc_has_dref = nullptr;

    // Checks if there's a write data xref to the target address
    static int metapc_has_write_dref_hook(void*, ea_t target_addr) {
        auto plugin = SINGLETON;
        std::unique_lock lock{plugin->m_hook_mutex};

        if (!plugin->m_scanned_for_refs) {
            plugin->scan_for_refs();
        }

        return plugin->m_write_drefs_to.contains(target_addr);
    }
};

plugmod_t* idaapi init() {
    return FastAnalysisPlugin::SINGLETON = new FastAnalysisPlugin;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Speeds up IDA Auto-Analysis",
    nullptr,
    "FastAnalysis",
    nullptr
};