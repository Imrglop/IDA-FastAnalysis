#pragma once

#ifdef __APPLE__

#include <dobby.h>

#include <cstdint>

class dobby_hook final {
public:
    dobby_hook() = default;
    dobby_hook(const dobby_hook&) = delete;
    dobby_hook& operator=(const dobby_hook&) = delete;

    ~dobby_hook() {
        uninstall();
    }

    bool install(void* target, void* replacement) {
        if (m_installed || target == nullptr || replacement == nullptr)
            return false;

        m_target = target;
        m_original = nullptr;
        m_status = DobbyHook(m_target, replacement, &m_original);
        if (m_status != 0 || m_original == nullptr) {
            if (m_status == 0)
                DobbyDestroy(m_target);
            m_target = nullptr;
            m_original = nullptr;
            return false;
        }

        m_installed = true;
        return true;
    }

    void uninstall() {
        if (!m_installed)
            return;

        m_status = DobbyDestroy(m_target);
        if (m_status == 0) {
            m_target = nullptr;
            m_original = nullptr;
            m_installed = false;
        }
    }

    template <typename Function>
    [[nodiscard]] Function original() const {
        return reinterpret_cast<Function>(reinterpret_cast<std::uintptr_t>(m_original));
    }

    [[nodiscard]] int status() const {
        return m_status;
    }

private:
    void* m_target{};
    void* m_original{};
    int m_status{-1};
    bool m_installed{};
};

#endif
