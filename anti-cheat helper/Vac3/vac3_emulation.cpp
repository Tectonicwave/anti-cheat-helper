#include "vac3_emulation.h"
#include "../utils/module_utils.h"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <sstream>

#undef min

namespace vac_emulation {

	// Helper: get loaded modules as vector of module_range_t
	static std::vector<module_range_t> get_loaded_modules(DWORD pid) {
		std::vector<module_range_t> modules;

		std::vector<uintptr_t> starts;
		std::vector<uintptr_t> ends;
		std::vector<std::wstring> names;
		utils::get_module_ranges(pid, starts, ends, names);

		size_t count = std::min({ starts.size(), ends.size(), names.size() });
		for (size_t i = 0; i < count; ++i) {
			modules.push_back(module_range_t{ starts[i], ends[i], names[i] });
		}

		return modules;
	}

	// Helper: is address in any module range
	static bool is_address_in_modules(uintptr_t addr, const std::vector<module_range_t>& modules) {
		for (const auto& mod : modules) {
			if (addr >= mod.base && addr < mod.end)
				return true;
		}
		return false;
	}

	// Helper: is address in trusted module ranges (uses utils::is_trusted_module)
	static bool is_address_in_trusted_module(uintptr_t addr, const std::vector<module_range_t>& modules) {
		for (const auto& mod : modules) {
			if (addr >= mod.base && addr < mod.end) {
				if (utils::is_trusted_module(mod.name))
					return true;
			}
		}
		return false;
	}

	// Helper: check if region base is inside any loaded module
	static bool region_in_module_list(HANDLE hProc, void* addr, const std::vector<module_range_t>& modules) {
		return is_address_in_modules(reinterpret_cast<uintptr_t>(addr), modules);
	}

	// Helper: partial PE header check for suspicious memory regions
	static bool is_pe_header(const uint8_t* data, size_t size) {
		if (size < sizeof(IMAGE_DOS_HEADER))
			return false;
		if (data[0] != 'M' || data[1] != 'Z')
			return false;

		auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
		if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000 || dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size)
			return false;

		auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + dos->e_lfanew);
		return nt->Signature == IMAGE_NT_SIGNATURE;
	}

	//caches
	static std::unordered_set<uintptr_t> g_reported_regions;
	static std::unordered_set<uintptr_t> g_reported_thread_starts;

	// Heuristic to skip known system/private executable memory regions, have do this for now 
	static const std::set<uintptr_t> known_safe_exec_regions = {
		0x7ffbfbe70000, // .NET Core or CLR JIT region
		0x7ffc43840000, // App-specific loader 
		0x7ffc482e0000  // Another trusted loader blob
	};

	bool is_known_safe_exec_region(uintptr_t addr) {
		return known_safe_exec_regions.find(addr) != known_safe_exec_regions.end();
	}

	// Scan suspicious executable regions (manual maps, RWX, etc) with whitelist caches
	inline void scan_suspicious_exec_regions(HANDLE hProc, const std::vector<module_range_t>& modules) {
		SYSTEM_INFO sysInfo;
		GetSystemInfo(&sysInfo);
		uint8_t* addr = (uint8_t*)sysInfo.lpMinimumApplicationAddress;
		uint8_t* max = (uint8_t*)sysInfo.lpMaximumApplicationAddress;

		MEMORY_BASIC_INFORMATION mbi;

		while (addr < max) {
			if (!VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi))) break;

			bool is_exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

			if (mbi.State == MEM_COMMIT && is_exec && mbi.Type == MEM_PRIVATE) {
				uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);

				// added safe location for now yes lazy who cares
				if (is_known_safe_exec_region(baseAddr)) {
					addr += mbi.RegionSize;
					continue;
				}

				// Deduplication: only report once per base address
				if (g_reported_regions.find(baseAddr) == g_reported_regions.end()) {
					// Skip if region belongs to loaded modules
					if (!region_in_module_list(hProc, mbi.BaseAddress, modules)) {
						// Skip if inside trusted module ranges
						if (!is_address_in_trusted_module(baseAddr, modules)) {
							std::vector<uint8_t> buffer(mbi.RegionSize);
							SIZE_T bytesRead;
							if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
								bool has_pe = is_pe_header(buffer.data(), bytesRead);

								bool has_code_pattern = false;
								for (size_t i = 0; i + 5 < bytesRead; i++) {
									if ((buffer[i] == 0x55 && buffer[i + 1] == 0x8B) || // push ebp; mov ebp, esp
										((buffer[i] == 0x40 || buffer[i] == 0x48) && buffer[i + 1] == 0x89)) { // mov with REX prefix
										has_code_pattern = true;
										break;
									}
								}

								if (has_pe || has_code_pattern) {
									std::wstringstream ws;
									ws << L"[VAC3-LIKE] Suspicious exec region @ 0x" << std::hex << baseAddr
										<< L" Size: " << std::dec << mbi.RegionSize / 1024 << L" KB ";

									if (has_pe) ws << L"[Partial PE Header] ";
									else if (has_code_pattern) ws << L"[Code pattern] ";

									if (mbi.Protect & PAGE_EXECUTE_READWRITE) ws << L"[RWX] ";
									else if (mbi.Protect & PAGE_EXECUTE_READ) ws << L"[RX] ";

									std::wcout << ws.str() << L"\n";

									size_t snippet_len = std::min<size_t>(32, bytesRead);
									std::wcout << L"  Hex dump snippet: ";
									for (size_t j = 0; j < snippet_len; j++) {
										std::wcout << std::hex << (int)buffer[j] << L" ";
									}
									std::wcout << std::dec << L"\n";

									g_reported_regions.insert(baseAddr);
								}
							}
						}
					}
				}
			}
			addr += mbi.RegionSize;
		}
	}

	//Scan threads for suspicious thread start addresses outside modules with deduplication and whitelist
	void scan_suspicious_threads(DWORD pid, HANDLE hProc, const std::vector<module_range_t>& modules) {
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snap == INVALID_HANDLE_VALUE)
			return;

		THREADENTRY32 te{};
		te.dwSize = sizeof(te);

		if (Thread32First(snap, &te)) {
			do {
				if (te.th32OwnerProcessID != pid)
					continue;

				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
				if (hThread) {
					void* start = nullptr;

					using NtQueryInformationThread_t = NTSTATUS(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
					static NtQueryInformationThread_t NtQueryInformationThread = nullptr;

					if (!NtQueryInformationThread)
						NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
							GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread"));

					if (NtQueryInformationThread) {
						NtQueryInformationThread(hThread, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr);

						uintptr_t start_addr = reinterpret_cast<uintptr_t>(start);

						if (!is_address_in_modules(start_addr, modules) && !is_address_in_trusted_module(start_addr, modules)) {
							if (g_reported_thread_starts.find(start_addr) == g_reported_thread_starts.end()) {
								g_reported_thread_starts.insert(start_addr);

								MEMORY_BASIC_INFORMATION mbi{};
								if (VirtualQueryEx(hProc, start, &mbi, sizeof(mbi))) {
									std::wcout << L"[VAC3-LIKE] Suspicious thread (TID " << te.th32ThreadID << L") entry at 0x"
										<< std::hex << start_addr << L" in region 0x" << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << std::dec << L"\n";
								}
								else {
									std::wcout << L"[VAC3-LIKE] Suspicious thread (TID " << te.th32ThreadID << L") entry at 0x"
										<< std::hex << start_addr << L" (region query failed)" << std::dec << L"\n";
								}
							}
						}
					}
					CloseHandle(hThread);
				}
			} while (Thread32Next(snap, &te));
		}

		CloseHandle(snap);
	}

	// Run the VAC3-like scanner on target process
	void run_vac_like_scanner(DWORD target_pid) {
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
		if (!hProc) {
			std::wcerr << L"[ERROR] Failed to open target process\n";
			return;
		}

		auto modules = get_loaded_modules(target_pid);

		scan_suspicious_exec_regions(hProc, modules);
		scan_suspicious_threads(target_pid, hProc, modules);

		CloseHandle(hProc);
	}

} // namespace vac_emulation
