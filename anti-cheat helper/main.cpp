#include <iostream>
#include <conio.h>
#include <map>
#include "hook_checker.h"

#define _WIN32_WINNT 0x0601  // Or higher (0x0A00 for Win10, etc)
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

extern "C" int guarded_main();

int main() {
	int ret = 0;
	__try {
		ret = guarded_main();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DWORD code = GetExceptionCode();
		std::wcerr << L"[FATAL] Exception code: 0x" << std::hex << code << L"\n";
		std::wcerr << L"Press any key to exit...\n";
		_getch();
		return 1;
	}
	return ret;
}

std::vector<uintptr_t> mod_starts;
std::vector<uintptr_t> mod_ends;

int guarded_main() {
	const wchar_t* process_name = L"cs2.exe";
	DWORD pid = 0;

	std::wcout << L"Waiting for process " << process_name << L"...\n";
	while ((pid = hook_checker::get_process_id_by_name(process_name)) == 0)
		Sleep(1000);

	std::wcout << L"Found PID: " << pid << L"\n";

	std::wstring exe_path;
	if (!hook_checker::get_process_exe_path(pid, exe_path)) {
		std::wcerr << L"[ERROR] Failed to get executable path\n";
		std::wcout << L"Press any key to exit...\n";
		_getch();
		return 1;
	}

	std::wcout << L"Executable path: " << exe_path << L"\n";

	std::map<std::wstring, hook_checker::section_info> snapshots;
	std::map<std::wstring, uintptr_t> module_bases;

	HMODULE h_mods[1024];
	DWORD cb_needed = 0;

	HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!h_process) {
		std::wcerr << L"[ERROR] Failed to open process handle, error: " << GetLastError() << L"\n";
		std::wcout << L"Press any key to exit...\n";
		_getch();
		return 1;
	}

	if (!EnumProcessModules(h_process, h_mods, sizeof(h_mods), &cb_needed)) {
		std::wcerr << L"[ERROR] Failed to enumerate modules, error: " << GetLastError() << L"\n";
		CloseHandle(h_process);
		std::wcout << L"Press any key to exit...\n";
		_getch();
		return 1;
	}

	size_t module_count = cb_needed / sizeof(HMODULE);

	for (size_t i = 0; i < module_count; ++i) {
		wchar_t mod_name[MAX_PATH] = {};
		if (GetModuleBaseNameW(h_process, h_mods[i], mod_name, MAX_PATH)) {
			std::wstring module_name(mod_name);
			if (hook_checker::is_game_module(module_name)) {
				wchar_t mod_path[MAX_PATH] = {};
				if (GetModuleFileNameExW(h_process, h_mods[i], mod_path, MAX_PATH)) {
					std::wstring module_path(mod_path);
					hook_checker::section_info sec_info{};

					uintptr_t module_base = reinterpret_cast<uintptr_t>(h_mods[i]);

					// Pass module_base so relocations get applied inside the function
					if (hook_checker::load_text_section_snapshot(module_path, sec_info, module_base)) {
						module_bases[module_name] = module_base;
						snapshots[module_name] = sec_info;
						std::wcout << L"[INFO] Snapshot loaded and relocations applied for " << module_name << L"\n";

						// ADD WHITELIST PATCHES FOR KNOWN LEGIT MODIFICATIONS
						if (_wcsicmp(module_name.c_str(), L"tier0.dll") == 0) {
							hook_checker::add_whitelist_offset(0x1B4116, L"tier0 legit patch");
							hook_checker::add_whitelist_offset(0x1B4117, L"tier0 legit patch");
							hook_checker::add_whitelist_offset(0x1B4118, L"tier0 legit patch");
							hook_checker::add_whitelist_offset(0x1B4119, L"tier0 legit patch");
							hook_checker::add_whitelist_offset(0x1B41B7, L"tier0 legit patch");
							hook_checker::add_whitelist_offset(0x1B41B8, L"tier0 legit patch");
							hook_checker::add_whitelist_offset(0x1B41B9, L"tier0 legit patch");
							hook_checker::add_whitelist_offset(0x1B41BA, L"tier0 legit patch");
						}
					}
					else {
						std::wcerr << L"[WARN] Failed to load snapshot for " << module_name << L"\n";
					}
				}
				else {
					std::wcerr << L"[WARN] Failed to get module path for " << module_name << L"\n";
				}
			}
		}
	}

	CloseHandle(h_process);

	std::wcout << L"Monitoring for hooks. Press 'q' or ESC to quit.\n";

	while (true) {
		bool found_hooks = false;

		// build mod_starts and mod_ends every iteration in case modules change
		mod_starts.clear();
		mod_ends.clear();

		HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!h_process) {
			std::wcerr << L"[ERROR] Failed to open process handle\n";
			break;
		}

		for (size_t i = 0; i < module_count; ++i) {
			MODULEINFO modinfo{};
			if (GetModuleInformation(h_process, h_mods[i], &modinfo, sizeof(modinfo))) {
				mod_starts.push_back(reinterpret_cast<uintptr_t>(modinfo.lpBaseOfDll));
				mod_ends.push_back(reinterpret_cast<uintptr_t>(modinfo.lpBaseOfDll) + modinfo.SizeOfImage);
			}
		}
		CloseHandle(h_process);

		for (const auto& entry : snapshots) {
			const std::wstring& module_name = entry.first;
			const hook_checker::section_info& section = entry.second;

			uintptr_t base = module_bases[module_name];
			auto hooks = hook_checker::check_for_hooks(pid, section, base, mod_starts, mod_ends);

			if (!hooks.empty()) {
				found_hooks = true;
				std::wcout << L"[ALERT] Hooks detected in module: " << module_name << L"\n";

				for (const auto& hook : hooks) {
					std::wcout << L"  [" << hook.type << L"] at offset 0x" << std::hex << hook.offset
						<< L" jumping to 0x" << hook.target << std::dec << L"\n";
				}
			}
		}

		if (found_hooks) {
			std::wcout << L"\nAll suspicious hooks have been listed above.\n";
			std::wcout << L"Press any key to exit...\n";
			_getch();
			return 0;
		}

		if (_kbhit()) {
			int key = _getch();
			if (key == 'q' || key == 27) {
				std::wcout << L"Exiting...\n";
				break;
			}
		}

		Sleep(1000);
	}

	std::wcout << L"Press any key to exit...\n";
	_getch();

	return 0;
}