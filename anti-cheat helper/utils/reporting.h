#pragma once

#include <string>
#include <iostream>

namespace utils {

	void report_hook(const std::wstring& module, const std::wstring& type, uintptr_t offset, uintptr_t target);;

	void report_exec_region(uintptr_t address, size_t size, const std::string& perms, const std::string& hex_snippet);

} // namespace utils
