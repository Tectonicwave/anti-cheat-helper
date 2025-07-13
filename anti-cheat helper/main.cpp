#include <iostream>
#include <conio.h>
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <array>
#include <map>

#include "Vac3/vac3_emulation.h"
#include "Vac3/hook_detector.h"
#include "utils/module_utils.h"

class HandleGuard {
public:
	explicit HandleGuard(HANDLE handle = nullptr) noexcept : handle_(handle) {}
	~HandleGuard() noexcept {
		if (handle_ && handle_ != INVALID_HANDLE_VALUE)
			CloseHandle(handle_);
	}
	HandleGuard(const HandleGuard&) = delete;
	HandleGuard& operator=(const HandleGuard&) = delete;
	HandleGuard(HandleGuard&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
	HandleGuard& operator=(HandleGuard&& other) noexcept {
		if (this != &other) {
			if (handle_ && handle_ != INVALID_HANDLE_VALUE)
				CloseHandle(handle_);
			handle_ = other.handle_;
			other.handle_ = nullptr;
		}
		return *this;
	}

	HANDLE get() const noexcept { return handle_; }
	explicit operator bool() const noexcept { return handle_ && handle_ != INVALID_HANDLE_VALUE; }

private:
	HANDLE handle_;
};

namespace {

	constexpr wchar_t target_process_name[] = L"cs2.exe";

	[[nodiscard]] DWORD wait_for_process(std::wstring_view process_name) noexcept {
		std::wcout << L"Waiting for process " << process_name << L" ...\n";

		DWORD pid = 0;
		while ((pid = utils::get_process_id_by_name(process_name.data())) == 0) {
			Sleep(1000);
		}

		std::wcout << L"Found PID: " << pid << L"\n";
		return pid;
	}

	void wait_for_keypress(std::wstring_view message = L"Press any key to exit...") noexcept {
		std::wcout << message << L'\n';
		_getch();
	}

} // namespace

int guarded_main() noexcept {
	const DWORD pid = wait_for_process(target_process_name);

	std::wstring exe_path;
	if (!utils::get_process_exe_path(pid, exe_path)) {
		std::wcerr << L"[ERROR] Failed to get executable path\n";
		wait_for_keypress();
		return 1;
	}
	std::wcout << L"Executable path: " << exe_path << L'\n';

	std::map<std::wstring, vac3::section_info_t> snapshots;
	std::map<std::wstring, uintptr_t> module_bases;

	// Open process handle once for module enumeration
	HandleGuard process_handle{ OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
	if (!process_handle) {
		std::wcerr << L"[ERROR] Failed to open process handle (error: " << GetLastError() << L")\n";
		wait_for_keypress();
		return 1;
	}

	std::vector<HMODULE> modules;
	if (!utils::enum_process_modules(pid, modules)) {
		std::wcerr << L"[ERROR] Failed to enumerate modules\n";
		wait_for_keypress();
		return 1;
	}

	for (const auto mod : modules) {
		wchar_t mod_name[MAX_PATH]{};
		if (!GetModuleBaseNameW(process_handle.get(), mod, mod_name, MAX_PATH))
			continue;

		const std::wstring module_name{ mod_name };
		if (!utils::is_game_module(module_name))
			continue;

		wchar_t mod_path[MAX_PATH]{};
		if (!GetModuleFileNameExW(process_handle.get(), mod, mod_path, MAX_PATH)) {
			std::wcerr << L"[WARN] Failed to get module path for " << module_name << L'\n';
			continue;
		}

		const uintptr_t module_base = reinterpret_cast<uintptr_t>(mod);

		vac3::section_info_t sec_info{};
		if (!vac3::load_text_section_snapshot(mod_path, sec_info, module_base)) {
			std::wcerr << L"[WARN] Failed to load snapshot for " << module_name << L'\n';
			continue;
		}

		module_bases[module_name] = module_base;
		snapshots[module_name] = std::move(sec_info);

		std::wcout << L"[INFO] Snapshot loaded and relocations applied for " << module_name << L'\n';

		if (_wcsicmp(module_name.c_str(), L"tier0.dll") == 0) {
			constexpr std::array whitelist_offsets{
				0x1B4116u, 0x1B4117u, 0x1B4118u, 0x1B4119u,
				0x1B41B7u, 0x1B41B8u, 0x1B41B9u, 0x1B41BAu
			};
			for (const auto off : whitelist_offsets)
				utils::add_whitelist_offset(off);
		}
	}

	std::wcout << L"Monitoring for hooks. Press 'q' or ESC to quit.\n";

	while (true) {
		bool found_hooks = false;

		std::vector<uintptr_t> mod_starts;
		std::vector<uintptr_t> mod_ends;
		std::vector<std::wstring> mod_names;

		utils::get_module_ranges(pid, mod_starts, mod_ends, mod_names);

		for (const auto& [module_name, section] : snapshots) {
			const auto base = module_bases.at(module_name);
			const auto hooks = vac3::check_for_hooks(pid, section, base, mod_starts, mod_ends);

			if (!hooks.empty()) {
				found_hooks = true;
				std::wcout << L"[ALERT] Hooks detected in module: " << module_name << L'\n';

				for (const auto& hook : hooks) {
					std::wcout << L"  [" << hook.type << L"] at offset 0x" << std::hex << hook.offset
						<< L" jumping to 0x" << hook.target << std::dec << L'\n';
				}
			}
		}

		vac_emulation::run_vac_like_scanner(pid);

		if (found_hooks) {
			std::wcout << L"\nAll suspicious hooks have been listed above.\n";
			wait_for_keypress();
			return 0;
		}

		if (_kbhit()) {
			const int key = _getch();
			if (key == 'q' || key == 27) {
				std::wcout << L"Exiting...\n";
				break;
			}
		}

		Sleep(1000);
	}

	wait_for_keypress();

	return 0;
}

int main() noexcept {
	int ret = 0;
	__try {
		ret = guarded_main();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		const DWORD code = GetExceptionCode();
		std::wcerr << L"[FATAL] Exception code: 0x" << std::hex << code << L'\n';
		wait_for_keypress();
		return 1;
	}
	return ret;
}