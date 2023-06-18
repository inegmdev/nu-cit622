#pragma once
#include <string>
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"
#include "spdlog/fmt/bundled/xchar.h"

class Logger {
private:
	std::shared_ptr<spdlog::logger> m_logger;
	std::string m_log_file_name;
public:
	Logger();
	void init();
    void deinit();
#if 0
	template<typename... Args>
	void write(fmt::format_string<Args...> fmt, Args &&... args) {
		m_logger->info(fmt, std::forward<Args>(args)...);
	}

    template<typename... Args>
    void write(fmt::wformat_string<Args...> fmt, Args &&... args) {
        std::wstring formattedString = fmt::format(fmt, std::forward<Args>(args)...);
        m_logger->info("{}", formattedString);
    }
#else
    template<typename... Args>
    void write(fmt::format_string<Args...> fmt, Args&&... args) {
        m_logger->info(fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void write(fmt::wstring_view fmt, Args&&... args) {
        std::wstring formattedString = fmt::format(fmt, std::forward<Args>(args)...);
        std::string convertedString(formattedString.begin(), formattedString.end());
        m_logger->info(convertedString);
    }
#endif
};
