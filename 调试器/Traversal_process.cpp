#include "Traversal_process.h"
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <vector>
#include <algorithm>

//判断目标进程位数：优先 IsWow64Process2（不受宿主位数影响），失败再退回 IsWow64Process。
//注意：Win32 宿主自身处于 WOW64，IsWow64Process 会把其他 32 位进程也报成 TRUE，
//所以回退路径只标注 x86/x64，无法区分时显示 "?"。
static const char* ProcessArch(HANDLE hProcess)
{
	typedef BOOL(WINAPI* PFN_IsWow64Process2)(HANDLE, USHORT*, USHORT*);
	static PFN_IsWow64Process2 pIsWow64Process2 =
		(PFN_IsWow64Process2)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
	if (pIsWow64Process2 != nullptr)
	{
		USHORT machine = 0, nativeMachine = 0;
		if (pIsWow64Process2(hProcess, &machine, &nativeMachine))
		{
			//非 WOW64 进程的 ProcessMachine 为 IMAGE_FILE_MACHINE_UNKNOWN，
			//此时该进程就是宿主原生位数（nativeMachine）
			if (machine == IMAGE_FILE_MACHINE_UNKNOWN)
				machine = nativeMachine;
			if (machine == IMAGE_FILE_MACHINE_I386)
				return "x86";
			if (machine == IMAGE_FILE_MACHINE_AMD64)
				return "x64";
			if (machine == IMAGE_FILE_MACHINE_ARM64)
				return "ARM64";
			return "?";
		}
	}
	BOOL bWow64 = FALSE;
	if (IsWow64Process(hProcess, &bWow64))
		return bWow64 ? "x86" : "x64";
	return "?";
}

//分页等待：按任意键继续，按 q 结束列举（单键读取，避免与 scanf 残留换行互相干扰）
static bool PageWait()
{
	printf("--- 按任意键继续，q 结束列举 ---");
	int ch = _getch();
	printf("\n");
	return (ch == 'q' || ch == 'Q');
}

//枚举当前进程（最多 200 条），打印 PID、位数与进程名，分页显示后由用户输入 PID 选择
DWORD Traversal_process::SelectProcess()
{
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("进程枚举失败（错误码 %lu）\n", GetLastError());
		return 0;
	}
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);

	const int kMaxList = 200;
	const int kPageSize = 20;
	printf("可附加进程（PID    位数  进程名）：\n");
	int shown = 0;
	//可查询的（能标出位数的）排在前面，方便优先选择可附加的进程
	struct Item { DWORD pid; const char* arch; WCHAR name[MAX_PATH]; bool archKnown; bool sameArch; };
	std::vector<Item> list;
	if (Process32First(hProcessSnapshot, &pe))
	{
		do
		{
			if (pe.th32ProcessID == 0 || list.size() >= (size_t)kMaxList)
				continue;
			HANDLE hTarget = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
			const char* szArch = hTarget ? ProcessArch(hTarget) : "?";
			if (hTarget)
				CloseHandle(hTarget);
			Item it = { pe.th32ProcessID, szArch };
			wcsncpy_s(it.name, pe.szExeFile, _TRUNCATE);
			it.archKnown = (szArch[0] != '?');
#ifdef _WIN64
			it.sameArch = (strcmp(szArch, "x64") == 0);
#else
			it.sameArch = (strcmp(szArch, "x86") == 0);
#endif
			list.push_back(it);
		} while (Process32Next(hProcessSnapshot, &pe));
	}
	CloseHandle(hProcessSnapshot);
	std::sort(list.begin(), list.end(), [](const Item& a, const Item& b) {
		if (a.sameArch != b.sameArch)
			return a.sameArch;          // 与本程序同一位数的排最前
		if (a.archKnown != b.archKnown)
			return a.archKnown;         // 已知位数的其次
		return a.pid < b.pid;
		});
	{
		bool quit = false;
		for (size_t i = 0; i < list.size(); i++)
		{
			printf("  %5lu  %-5s %ls\n", list[i].pid, list[i].arch, list[i].name);
			++shown;
			if (shown % kPageSize == 0)
			{
				if (PageWait())
				{
					quit = true;
					break;
				}
			}
		}
		if (quit)
		{
			printf("共列出 %d 条（上限 %d，已按 q 提前结束）\n", shown, kMaxList);
			return 0;
		}
	}
	printf("共列出 %d 条（上限 %d）\n", shown, kMaxList);
#ifdef _WIN64
	printf("注意：本程序为 x64，只能附加 x64 进程（x86 进程请使用 Win32 版本）。\n");
#else
	printf("注意：本程序为 Win32，只能附加 x86 进程（x64 进程请使用 x64 版本）。\n");
#endif

	char text[32] = { 0 };
	printf("请输入要附加的 PID：");
	scanf_s("%31s", text, (UINT)sizeof(text));
	char* end = nullptr;
	DWORD pid = (DWORD)strtoul(text, &end, 10);
	if (end == text || *end != '\0' || pid == 0)
	{
		printf("PID 格式错误：%s\n", text);
		return 0;
	}
	return pid;
}
