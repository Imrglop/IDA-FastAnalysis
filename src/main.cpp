
#include <chrono>
#ifdef __linux__
#include <dlfcn.h>
#elifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif
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
        bool is_arm = false;

        if (inf_get_procname() == "metapc") {
#ifdef WIN32
#ifdef IDA_8
            m_proc_mod = hat::process::get_module("pc64.dll");
#else
            m_proc_mod = hat::process::get_module("pc.dll");
#endif
#elifdef __linux__
            m_proc_mod = hat::process::get_module("pc.so");
#endif
        } else if (inf_get_procname() == "ARM") {
            is_arm = true;

            // the function we need to hook for ARM is just in ida.dll, weirdly enough
#ifndef IDA_8
            m_proc_mod = hat::process::get_module("ida.dll");
#endif
        }

#ifdef WIN32
#ifndef IDA_8
        m_ida_mod = hat::process::get_module("ida.dll");
#else
        m_ida_mod = hat::process::get_module("ida64.dll");
#endif
#elifdef __linux__
        m_ida_mod = hat::process::get_module("ida.so");
#endif

        if (!m_proc_mod || !m_ida_mod) {
            msg("FastAnalysis is not supported for this target: %s\n", inf_get_procname().c_str());
            return;
        }

        m_proc_mod->for_each_segment([this](std::span<std::byte> section, hat::protection protection) {
           if (static_cast<bool>(protection & hat::protection::Execute)) {
               m_proc_mod_text_section = section;
               return false;
           }

           return true;
        });

        bool result;
        if (is_arm)
            result = init_arm_hooks();
        else
            result = init_metapc_hooks();

        auto get_bytes_addr =
#ifdef WIN32
            reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(m_ida_mod->address()), "get_bytes"));
#endif

        if (get_bytes_addr)
            m_get_bytes_hook = safetyhook::create_inline(get_bytes_addr, get_bytes_hook);

        if (result)
            m_active = true;
    }

    ~FastAnalysisPlugin() override = default;

    bool run(size_t arg) override {
        // TODO: settings menu

        if (m_active)
            info("FastAnalysis is active\n");
        else
            info("FastAnalysis is not active\n");

        return true;
    }

    bool init_arm_hooks() {
        auto pattern = hat::compile_signature<"48 83 ec ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 44 24 38 48 8b d1 41 b8 02">();

        hat::scan_result result = hat::find_pattern(m_proc_mod_text_section, pattern,
            hat::scan_alignment::X16, hat::scan_hint::x86_64);

        if (!result.has_result()) {
            warning("FastAnalysis may not support this IDA version (signature result not found)\n");
            return false;
        }

        m_arm_has_write_dref_hook = safetyhook::create_inline(result.get(), arm_has_write_dref_hook);

        auto enable_result = m_arm_has_write_dref_hook.enable();

        if (!enable_result.has_value()) {
            warning("Failed to enable hook, FastAnalysis will not function");
            return false;
        }

        return true;
    }

    bool init_metapc_hooks() {
        auto pattern = hat::compile_signature<
#ifdef WIN32
#ifdef IDA_8
       "40 53 48 83 EC ? 48 8b 05 ? ? ? ? 48 33 C4 48 89 44 24 38"
#else
       "48 83 ec ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 44 24 38 41 b8 02 00 00 00"
#endif
#elifdef __linux__
#error Linux is not supported

        // Looks like it might be this
        "55 53 48 83 ec ? 64 48 8b 14 25 ? 00 00 00 48 89 54 ? ? ba 02"
#endif
        >();

        hat::scan_result result = hat::find_pattern(m_proc_mod_text_section, pattern,
            hat::scan_alignment::X16, hat::scan_hint::x86_64);

        if (!result.has_result()) {
            warning("FastAnalysis may not support this IDA version (signature result not found)\n");
            return false;
        }

        m_metapc_has_write_dref_hook = safetyhook::create_inline(result.get(), metapc_has_write_dref_hook);

        auto enable_result = m_metapc_has_write_dref_hook.enable();

        if (!enable_result.has_value()) {
            warning("Failed to enable hook, FastAnalysis will not function");
            return false;
        }

        return true;
    }

    static bool get_section_bytes(const char* name, std::vector<std::byte>& bytes, ea_t& start_ea) {
        segment_t* segment = get_segm_by_name(name);

        if (segment == nullptr)
            return false;

        auto min_ea = segment->start_ea;
        auto binary_size = segment->size();

        bytes = {};
        bytes.resize(binary_size);

        msg("FastAnalysis: Getting %lld bytes from IDA (%s)\n", binary_size, name);
        auto start_time = std::chrono::high_resolution_clock::now();
        ssize_t res = get_bytes(bytes.data(),
            static_cast<ssize_t>(binary_size),
            min_ea);
        auto end_time = std::chrono::high_resolution_clock::now();
        msg("FastAnalysis: Took %d ms\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

        //assert(res == binary_size);

        start_ea = segment->start_ea;

        return true;
    }

    bool get_target_sections_bytes() {
        // TODO: instead, get all sections with executable code and have an option to search the entire binary regardless of whether or not a "text" section is present

        if (!get_section_bytes(".text", m_target_text_section_bytes, m_text_start_ea)) {
            if (!get_section_bytes("__text", m_target_text_section_bytes, m_text_start_ea)) {
                msg("FastAnalysis may not support this target: no .text section or equivalent found.\n");
                return false;
            }
        }

        get_section_bytes(".rdata", m_target_rdata_section_bytes, m_rdata_start_ea);
        get_section_bytes(".data", m_target_data_section_bytes, m_data_start_ea);

        return true;
    }

    void scan_for_refs(bool is_arm) {
        if (m_scanned_for_refs)
            return;


        if (!get_target_sections_bytes()) {
            msg("FastAnalysis: Failed to get target text section bytes\n");
            m_active = false;
            return;
        }


        size_t section_size = m_target_text_section_bytes.size();

        uint32_t num_threads = std::thread::hardware_concurrency();
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

            threads.emplace_back(std::async(std::launch::async, [=, text_start = m_text_start_ea] {
                return RefScanner::find_write_drefs(is_arm ? RefScanner::AARCH64 : RefScanner::X86_64, text_start + i * size_per_division,
                    division_begin, division_end);
            }));

            division_begin = division_end;
        }

        for (auto& thread : threads) {
            auto set = thread.get();
            m_write_drefs_to.merge(set);
        }

        auto end_time = std::chrono::high_resolution_clock::now();

        msg("FastAnalysis (%s): finding %d write drefs took %d ms\n", is_arm ? "arm64" : "x86-64", m_write_drefs_to.size(),
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

        m_scanned_for_refs = true;

        // Save some memory now that we don't need the bytes anymore
        m_target_text_section_bytes.clear();
    }

    bool m_active = false;
    bool m_scanned_for_refs = false;

    safetyhook::InlineHook m_get_bytes_hook{};
    safetyhook::InlineHook m_metapc_has_write_dref_hook{};
    safetyhook::InlineHook m_arm_has_write_dref_hook{};
    std::optional<hat::process::module> m_proc_mod;
    std::optional<hat::process::module> m_ida_mod;
    std::span<std::byte> m_proc_mod_text_section;
    std::span<std::byte> m_ida_mod_text_section;

    std::vector<std::byte> m_target_text_section_bytes;
    std::vector<std::byte> m_target_rdata_section_bytes;
    std::vector<std::byte> m_target_data_section_bytes;
    std::unordered_set<uintptr_t> m_write_drefs_to;
    ea_t m_text_start_ea{};
    ea_t m_data_start_ea{};
    ea_t m_rdata_start_ea{};

    // TODO: Also hook a function to prevent the user from patching the binary while analysis is happening, so this stays valid
    static ssize_t get_bytes_hook(void *buf, ssize_t size, ea_t ea, int gmb_flags, void *mask) {
        auto plugin = SINGLETON;

        // filter out types of calls not used (often) in analysis
        if ((gmb_flags & GMB_WAITBOX) || mask) {
            return plugin->m_get_bytes_hook.call<ssize_t>(buf, size, ea, gmb_flags, mask);
        }

        // check if both bounds are in .rdata section
        if (ea >= plugin->m_rdata_start_ea && ea + size < plugin->m_rdata_start_ea + plugin->m_target_rdata_section_bytes.size()) {
            // return a slice of m_all_bytes
            auto offs = ea - plugin->m_rdata_start_ea;

            if (size == 8) // allow compiler to optimize the memcpy away
                memcpy(buf, plugin->m_target_rdata_section_bytes.data() + offs, 8);
            else if (size == 16)
                memcpy(buf, plugin->m_target_rdata_section_bytes.data() + offs, 16);
            else
                memcpy(buf, plugin->m_target_rdata_section_bytes.data() + offs, size);

            return size;
        }

        if (ea >= plugin->m_data_start_ea && ea < plugin->m_data_start_ea + plugin->m_target_data_section_bytes.size()) {
            // return a slice of m_all_bytes
            auto offs = ea - plugin->m_data_start_ea;

            if (size == 8) // allow compiler to optimize the memcpy away
                memcpy(buf, plugin->m_target_data_section_bytes.data() + offs, 8);
            else if (size == 16)
                memcpy(buf, plugin->m_target_data_section_bytes.data() + offs, 16);
            else
                memcpy(buf, plugin->m_target_data_section_bytes.data() + offs, size);

            return size;
        }

        return plugin->m_get_bytes_hook.call<ssize_t>(buf, size, ea, gmb_flags, mask);
    }

    // Checks if there's a write data xref to the target address
    static bool metapc_has_write_dref_hook(void* unknown, ea_t target_addr) {
        auto plugin = SINGLETON;
        if (!plugin->m_active) {
            return plugin->m_metapc_has_write_dref_hook.call<bool>(unknown, target_addr);
        }

        if (!plugin->m_scanned_for_refs) {
            plugin->scan_for_refs(false);
        }

        return plugin->m_write_drefs_to.contains(target_addr);
    }

    static bool arm_has_write_dref_hook(ea_t target_addr) {
        auto plugin = SINGLETON;
        if (!plugin->m_active) {
            return plugin->m_arm_has_write_dref_hook.call<bool>(target_addr);
        }

        if (!plugin->m_scanned_for_refs) {
            plugin->scan_for_refs(true);
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
