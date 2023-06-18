#pragma once

#define LOG_ERROR     0b1
#define LOG_WARNING   0b10
#define LOG_INFO      0b100
#define LOG_DEBUG     0b1000

#define LOGGING_VERBOSITY (LOG_INFO | LOG_WARNING | LOG_ERROR)

#if (LOGGING_VERBOSITY & LOG_DEBUG)
#define DBG(...) std::cout << "[DEBUG]   " << __VA_ARGS__
#define DBG_LN(...) std::cout << "[DEBUG]   " << __VA_ARGS__ << std::endl;
#else
#define DBG(...)
#define DBG_LN(...)
#endif

#if (LOGGING_VERBOSITY & LOG_INFO)
#define INFO(...) std::cout << "[INFO]    " << __VA_ARGS__
#define INFO_LN(...) std::cout << "[INFO]    " << __VA_ARGS__ << std::endl;
#else
#define INFO(...)
#define INFO_LN(...)
#endif

#if (LOGGING_VERBOSITY & LOG_WARNING)
#define WARN(...) std::cout << "[WARNING] " << __VA_ARGS__
#define WARN_LN(...) std::cout << "[WARNING] " << __VA_ARGS__ << std::endl;
#else
#define WARN(...)
#define WARN_LN(...)
#endif

#if (LOGGING_VERBOSITY & LOG_ERROR)
#define ERR(...) std::cerr << "[ERROR]   " << __VA_ARGS__
#define ERR_LN(...) std::cerr << "[ERROR]   " << __VA_ARGS__ << std::endl;
#else
#define ERR(...)
#define ERR_LN(...)
#endif
