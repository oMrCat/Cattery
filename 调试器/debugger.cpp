#include "debugger.h"
#include"breakpoint.h"
#include"capstone.h"
#include"Plugin_Dll.h"
#include <conio.h>

// In x64 the CONTEXT struct only has 64-bit registers (Rax/Rip...).
// These map a 32-bit register name to the low 32 bits of its 64-bit register,
// which keeps the original 32-bit semantics. No whole-register aliasing (Eip->Rip).
#ifdef _WIN64
#define EAX_OF(c) ((DWORD)((c).Rax))
#define EBX_OF(c) ((DWORD)((c).Rbx))
#define ECX_OF(c) ((DWORD)((c).Rcx))
#define EDX_OF(c) ((DWORD)((c).Rdx))
#define ESI_OF(c) ((DWORD)((c).Rsi))
#define EDI_OF(c) ((DWORD)((c).Rdi))
#define ESP_OF(c) ((DWORD)((c).Rsp))
#define EBP_OF(c) ((DWORD)((c).Rbp))
#define EIP_OF(c) ((DWORD)((c).Rip))
//x64 下取完整 64 位指令指针，供断点地址使用（不能用 EIP_OF 截断）
#define IP_OF(c) ((ULONG_PTR)((c).Rip))
#else
#define EAX_OF(c) ((c).Eax)
#define EBX_OF(c) ((c).Ebx)
#define ECX_OF(c) ((c).Ecx)
#define EDX_OF(c) ((c).Edx)
#define ESI_OF(c) ((c).Esi)
#define EDI_OF(c) ((c).Edi)
#define ESP_OF(c) ((c).Esp)
#define EBP_OF(c) ((c).Ebp)
#define EIP_OF(c) ((c).Eip)
#define IP_OF(c) ((ULONG_PTR)((c).Eip))
#endif

vector<MODULEENTRY32>Mo;
vector<char*>ExMoNa;
vector<ULONG_PTR>ExMoAddr;
extern PreviousbpInfo bpInfo;
extern LPVOID addr;
LPVOID g_dWMemAddr;
extern int type;
int flag = 0;
int nflag = 1;
int rflag = 0;
int nIsGo = 0;

char n_Name[30] = { 0 };
ULONG_PTR n_Value = 0;
ULONG_PTR n_addr = 0;

ULONG_PTR r_addr = 0;
char r_Name[30] = { 0 };
ULONG_PTR r_Value = 0;
bool debugger::open(LPCSTR szPath)
{
	STARTUPINFOA si
	{
		sizeof(si)
	};
	PROCESS_INFORMATION pi;
	BOOL bResult = CreateProcessA(szPath,
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi
	);
	if (!bResult)
	{
		printf("进程创建失败（路径：%s，错误码 %lu）\n", szPath, GetLastError());
		return false;
	}
	Capstone::Init();
	return true;
}


LPVOID oep;
void debugger::run()
{
	while (WaitForDebugEvent(&debugEvent, -1))
	{
		openHandles();
		switch (debugEvent.dwDebugEventCode)//判断事件代码
		{
			//由异常引发的调试事件
		case EXCEPTION_DEBUG_EVENT:
			if (nflag == 1)
			{
				nflag = 0;
				Plugin_Dll::LoadDll(debugEvent.dwProcessId);
			}
			OnDispatchException();
			break;
			//进程创建的调试事件
		case CREATE_PROCESS_DEBUG_EVENT:
			//给程序入口点下断点
			::oep = debugEvent.u.CreateProcessInfo.lpStartAddress;
			break;
		default:
			break;
		}
		//被调试的程序继续运行
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, deContinueStatus);
		closeHandles();
	}
}

void debugger::openHandles()
{
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, debugEvent.dwProcessId);
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
}

void debugger::closeHandles()
{
	CloseHandle(hProcess);
	CloseHandle(hThread);
}



void debugger::OnDispatchException()
{
	//判断是由哪个断点引发的异常，会得到一个序号对应内核层的IDT的回调函数
	auto exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	//下断的地址
	auto exceptionAddr = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	//断点的类型
	auto exceptionType = debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
	//设置断点的内存地址
	auto dwMemAddr = debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];
	//由哪一类引发的异常
	switch (exceptionCode)
	{
	case EXCEPTION_BREAKPOINT://由int3引发的普通断点
		if (isSystemPoint)
		{
			//对OEP设置int3断点(只设置一次)，所以一次之后要进行撤销int3断点
			Breakpoint::SetInt3BreakPoint(hProcess, oep);
			isSystemPoint = FALSE;
		}
		Breakpoint::FixInt3BreakPoint(hProcess, exceptionAddr, hThread);
		if (rflag == 3)
		{
			goto y;
		}
		break;
		//单步以及硬件会走下面这个逻辑
	case EXCEPTION_SINGLE_STEP://由硬件断点引发的异常
		if (bpInfo.PreviousIsBp == 1)
		{
			if (bpInfo.whichbp == 0)
			{
				Breakpoint::SetInt3BreakPoint(hProcess, bpInfo.previousAddr);
			}
			else if (bpInfo.whichbp == 1)
			{
				Breakpoint::SetHwBreakPoint(hThread, bpInfo.previousAddr, bpInfo.type, bpInfo.len);
			}
			else if (bpInfo.whichbp == 2)
			{
				Breakpoint::SetMmBreakpoint(hProcess, addr, type);
			}
			bpInfo.PreviousIsBp = 0;
			return;
		}
		else if (bpInfo.PreviousIsBp == 0)
		{
			//硬件断点命中：Dr6 的 B0–B3 会置位。先清 Dr7 的 L 位并挂 TF 单步跨过，
			//再进入命令循环；这样用户 g 之后才会重新启用断点，不会立刻重复命中。
			CONTEXT hwContext = { 0 };
			hwContext.ContextFlags = CONTEXT_ALL;
			GetThreadContext(hThread, &hwContext);
			if ((hwContext.Dr6 & 0xF) != 0)
			{
				Breakpoint::FixHwBreakpoint(hThread, hProcess, exceptionAddr);
				goto x;
			}
			if (flag == 1)
			{
				flag = 0;
				goto x;
			}
			else if (flag == 2 || rflag == 3)
			{
				goto y;
			}
			else if (rflag == 10)
			{
				rflag = 0;
				return;
			}
		}
		break;
	case EXCEPTION_ACCESS_VIOLATION://由内存断点引发的异常

		Breakpoint::FixMmBreakpoint(hProcess, hThread, (LPVOID)dwMemAddr, (int)exceptionType);

		if (nIsGo == 0)
		{
			return;
		}
		if ((LPVOID)dwMemAddr == g_dWMemAddr)
		{
			nIsGo = 0;
		}
		break;
	}
	//将出现异常的地址打印出来
x:Capstone::DisAsm(hProcess, exceptionAddr, 10);

y:GetInput();

}

bool debugger::Open(DWORD dwPid)
{
	Capstone::Init();
	return DebugActiveProcess(dwPid);
}

void debugger::GetDebugSymbol()
{
	//初始化符号
	SymInitialize(hProcess, NULL, TRUE);
	//加载模块符号文件
	SymLoadModule64(
		hProcess,
		debugEvent.u.LoadDll.hFile,//模块文件句柄
		NULL,
		NULL,
		(DWORD64)(ULONG_PTR)debugEvent.u.LoadDll.lpBaseOfDll,
		0
	);
}
//通过名称获取地址
SIZE_T debugger::GetSymAddress(HANDLE hProcess, const char* pszName)
{
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//根据名字查询符号信息，输出到pSymbol中
	if (!SymFromName(hProcess, pszName, pSymbol))
	{
		return 0;
	}
	return (SIZE_T)pSymbol->Address;//返回函数地址
}

//通过地址获取名称
BOOL debugger::GetSymName(HANDLE hProcess, SIZE_T nAddress, CString& strName)
{
	DWORD64 dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//根据地址获取符号信息
	if (!SymFromAddr(hProcess, nAddress, &dwDisplacement, pSymbol))
	{
		return FALSE;
	}
	strName = pSymbol->Name;
	return TRUE;
}

SIZE_T debugger::FindApiAddress(HANDLE hProcess, const char* pszName)
{
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//根据名字查询符号信息，输出到pSymbol中
	if (!SymFromName(hProcess, pszName, pSymbol))
	{
		return 0;
	}
	return (SIZE_T)pSymbol->Address;//返回函数地址
}

void debugger::ModuleAPI(DWORD PID)
{
	Mo.clear();
	ExMoNa.clear();
	ExMoAddr.clear();
	setlocale(LC_ALL, "chs");

	//定义一些变量
	HANDLE hProcessSnapshot = 0;
	MODULEENTRY32 me = {};
	me.dwSize = sizeof(MODULEENTRY32);
	//创建模块快照
	hProcessSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,//创建的是模块快照
		PID              //进程ID，只有在创建模块，堆快照的时候，指定进程
	);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		return;
	}
	//获取第一个进程的信息，如果获取成功，就可以继续往后获取
	BOOL bSuccess = Module32First(
		hProcessSnapshot,//快照的句柄
		&me              //第一个进程的信息
	);
	//循环遍历，所有的进程信息
	if (bSuccess == TRUE)
	{
		do {
			Mo.push_back(me);
		} while (Module32Next(hProcessSnapshot, &me));
	}
	CloseHandle(hProcessSnapshot);
	printf("开始解析：\n");
	for (size_t i = 0; i < Mo.size(); i++)
	{
		USES_CONVERSION;
		//首先先将宽字符转成多字节
		char* buffer = W2A(Mo[i].szExePath);
		// 先读取文件到内存
		char* buff = read_file(buffer);
		// 判断是否是有效的PE文件
		if (is_pe_file(buff) == true)
		{
			// 开始解析
			// get_optional_header_information(buff);
			veExport(buff);
		}
	}
}

//导出/导入表列举的分页状态：定义在此供 ExportImport 与本文件后半段的打印循环共用
static const int kPageSize = 200;
static int g_pageLines = 0;
static bool g_pageStop = false;
//最近一次打印的 PE 头，分页时重绘，避免被后续输出冲掉
static char g_peHeader[256] = { 0 };

void debugger::ExportImport(DWORD PID)
{

	Mo.clear();
	setlocale(LC_ALL, "chs");

	//定义一些变量
	HANDLE hProcessSnapshot = 0;
	MODULEENTRY32 me = {};
	me.dwSize = sizeof(MODULEENTRY32);
	//创建模块快照
	hProcessSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,//创建的是模块快照
		PID              //进程ID，只有在创建模块，堆快照的时候，指定进程
	);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		return;
	}
	//获取第一个进程的信息，如果获取成功，就可以继续往后获取
	BOOL bSuccess = Module32First(
		hProcessSnapshot,//快照的句柄
		&me              //第一个进程的信息
	);
	//循环遍历，所有的进程信息
	if (bSuccess == TRUE)
	{
		do {
			Mo.push_back(me);
		} while (Module32Next(hProcessSnapshot, &me));
	}
	CloseHandle(hProcessSnapshot);
	//开始导出/导入表列举：重置分页状态，避免上一轮的退出标记影响本轮
	g_pageLines = 0;
	g_pageStop = false;
	for (size_t i = 0; i < Mo.size(); i++)
	{
		USES_CONVERSION;
		//首先先将宽字符转成多字节
		char* buffer = W2A(Mo[i].szExePath);
		// 先读取文件到内存
		char* buff = read_file(buffer);
		// 判断是否是有效的PE文件
		if (is_pe_file(buff) == true)
		{
			if (g_pageStop)
			{
				printf("已退出列举（q）\n");
				return;
			}
			printf("导出表信息：\n");
			// 开始解析
			// get_optional_header_information(buff);
			get_export_information(buff);
			if (!g_pageStop)
			{
				printf("导入表信息：\n");
				get_import_information(buff);
			}
		}
	}
}

char* debugger::read_file(const char* path)
{
	// 打开文件,获取文件大小
	HANDLE file_handle = CreateFileA(path, GENERIC_READ,
		FILE_SHARE_READ, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	// 读取内容
	// 先获取文件大小 ，申请空间保存内容
	DWORD file_size = GetFileSize(file_handle, NULL);
	char* buff = new char[file_size];

	// 读取文件内容
	DWORD real_read_size = 0;
	ReadFile(file_handle, buff, file_size, &real_read_size, NULL);

	// 关闭文件
	CloseHandle(file_handle);
	return buff;
}

// PE32 / PE32+ layout helpers.
// The parsed file may be PE32 or PE32+, so its layout must be selected by the
// file's own OptionalHeader.Magic, never by the architecture of this build.
static PIMAGE_NT_HEADERS32 PeNt32(char* buff)
{
	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)buff;
	return (PIMAGE_NT_HEADERS32)(buff + dos_head->e_lfanew);
}

static PIMAGE_NT_HEADERS64 PeNt64(char* buff)
{
	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)buff;
	return (PIMAGE_NT_HEADERS64)(buff + dos_head->e_lfanew);
}

static bool PeIs64(char* buff)
{
	return PeNt32(buff)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

static DWORD PeDataDirectoryRva(char* buff, int index)
{
	if (PeIs64(buff))
		return PeNt64(buff)->OptionalHeader.DataDirectory[index].VirtualAddress;
	return PeNt32(buff)->OptionalHeader.DataDirectory[index].VirtualAddress;
}

static PIMAGE_SECTION_HEADER PeFirstSection(char* buff)
{
	if (PeIs64(buff))
		return IMAGE_FIRST_SECTION(PeNt64(buff));
	return IMAGE_FIRST_SECTION(PeNt32(buff));
}

static ULONG_PTR PeImageBase(char* buff)
{
	if (PeIs64(buff))
		return (ULONG_PTR)PeNt64(buff)->OptionalHeader.ImageBase;
	return (ULONG_PTR)PeNt32(buff)->OptionalHeader.ImageBase;
}

bool debugger::is_pe_file(char* buff)
{
	// pe 文件解析的过程中，最常用的就是 类型转换
	// 先判断前两个字节是不是 0x5A4D
	PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)buff;
	if (dos_head->e_magic == IMAGE_DOS_SIGNATURE)
	{
		// 再判断 elfanew 指向的是不是 0x00004550
		PIMAGE_NT_HEADERS32 nt_head = PeNt32(buff);
		if (nt_head->Signature == IMAGE_NT_SIGNATURE)
		{
			return true;
		}
	}
	return false;
}

DWORD debugger::rva_to_foa(char* buff, DWORD rva)
{
	// 区段的数量
	DWORD section_count = PeNt32(buff)->FileHeader.NumberOfSections;
	// 获取到区段头表（位置由文件自身的 PE32/PE32+ 布局决定）
	PIMAGE_SECTION_HEADER section_head = PeFirstSection(buff);
	for (DWORD i = 0; i < section_count; i++)
	{
		// 如果 rva 在本区段，就计算段内偏移
		// 加上文件中的偏移,
		// 为什么用 内存的起始地址 + 文件大小，
		// 因为部分数据，在文件中没有，用内存大小计算这个范围，
		// 可能出现问题
		if (rva >= section_head->VirtualAddress &&
			rva <= section_head->VirtualAddress +
			section_head->SizeOfRawData
			)
		{
			// 根据公式计算 FOA 
			// RVA - 区段起始地址 = FOA - 区段文件起始地址
			DWORD foa = rva - section_head->VirtualAddress
				+ section_head->PointerToRawData;
			return foa;
		}
		section_head++;
	}
	return 0;
}

//导出/导入表列举的分页控制：每 kPageSize 行暂停，避免一次输出上万行
//把控制台缓冲区冲掉（PE 头是模块列举的关键信息，不能被冲掉）
static void PageBreak()
{
	if (++g_pageLines < kPageSize)
		return;
	g_pageLines = 0;
	//重绘当前模块 PE 头，避免翻页后关键信息被冲掉
	printf("%s\n", g_peHeader);
	printf("--- 按任意键继续 / q 退出 ---");
	//用 _getch 单键读取，避免与 scanf 残留换行互相干扰
	int ch = _getch();
	printf("\n");
	if (ch == 'q' || ch == 'Q')
		g_pageStop = true;
}

//行计数 + 用户是否已按 q 退出列举
static bool PageTick()
{
	PageBreak();
	return g_pageStop;
}

void debugger::get_export_information(char* buff)
{
	//输出 PE 头关键信息，便于在界面上确认该模块是 PE32 还是 PE32+（x64）
	sprintf_s(g_peHeader, sizeof(g_peHeader), "PE 头：%s  ImageBase=%p  SizeOfImage=0x%08X",
		PeIs64(buff) ? "PE32+" : "PE32",
		(PVOID)PeImageBase(buff),
		PeIs64(buff) ? PeNt64(buff)->OptionalHeader.SizeOfImage : PeNt32(buff)->OptionalHeader.SizeOfImage);
	printf("%s\n", g_peHeader);

	// 导出表在数据目录表的第 0 项
	DWORD export_rva = PeDataDirectoryRva(buff, 0);
	DWORD export_foa = rva_to_foa(buff, export_rva);

	// 获取到导出表的数据
	PIMAGE_EXPORT_DIRECTORY export_table =
		(PIMAGE_EXPORT_DIRECTORY)(buff + export_foa);

	// 解析内容
	DWORD name_foa = rva_to_foa(buff, export_table->Name);
	PCHAR name = (PCHAR)(buff + name_foa);
	printf("导出模块的名称：%s\n", name);

	// 获取到序号的基址
	DWORD base = export_table->Base;
	// 获取到两张表的数量
	DWORD address_count = export_table->NumberOfFunctions;
	DWORD name_count = export_table->NumberOfNames;
	// 遍历三张表，获取数据，如果哪张表没有内容了代表遍历完成？
	// 【地址表】，名称表，名称序号表
	// 得到函数地址表
	DWORD func_table_rva = export_table->AddressOfFunctions;
	DWORD func_table_foa = rva_to_foa(buff, func_table_rva);
	PDWORD func_table = PDWORD(buff + func_table_foa);
	// 得到函数名称表
	DWORD name_table_rva = export_table->AddressOfNames;
	DWORD name_table_foa = rva_to_foa(buff, name_table_rva);
	PDWORD name_table = PDWORD(buff + name_table_foa);
	// 得到名称序号表// 我们可以自己实现 GetProcAddress 这个函数
	DWORD ordinal_table_rva = export_table->AddressOfNameOrdinals;
	DWORD ordinal_table_foa = rva_to_foa(buff, ordinal_table_rva);
	PWORD ordinal_table = PWORD(buff + ordinal_table_foa);

	// 开始遍历,因为地址表中的内容多，所以用他遍历
	for (DWORD i = 0; i < address_count; i++)
	{
		if (func_table[i] == 0)
		{
			// 如果地址表的内容为 0 就是无效函数
			continue;
		}
		// 判断函数是否在名称表中，如果在就是名称导出，否则就是序号导出
		// 标志位，如果为假，就说明不在名称表中
		bool is_find = false;
		for (DWORD j = 0; j < name_count; j++)
		{
			// i 是从 0 开始遍历，序号表也就不需要加 base 了
			// 如果地址表的索引和名称序号表的内容一致，就说明名称导出
			// printf("%d %d\n", i, ordinal_table[j]);
			if (i == (DWORD)ordinal_table[j])
			{
				is_find = true;
				PCHAR fun_name =
					(PCHAR)(buff + rva_to_foa(buff, name_table[j]));
				printf("函数地址: %08X  函数名称: %s  名称序号: %d \n",
					func_table[i], fun_name, ordinal_table[j] + base);
				if (PageTick()) return;
				break;
			}
		}
		if (is_find == false)
		{
			printf("函数地址: %08X  函数名称: NULL  函数序号 %d \n",
				func_table[i], i + base);
			if (PageTick()) return;
		}

	}
}

void debugger::get_import_information(char* buff)
{


	// 导入表在数据目录表的第 1 项
	DWORD import_rva = PeDataDirectoryRva(buff, 1);
	DWORD import_foa = rva_to_foa(buff, import_rva);

	// 获取到导入表的数据
	PIMAGE_IMPORT_DESCRIPTOR import_table =
		(PIMAGE_IMPORT_DESCRIPTOR)(buff + import_foa);

	// 0x8464 == 0x00008464 -> 最高位就是0了 0x80000000 -> 10000000000000...
	// 导入表是以 全0 结构为结尾
	while (import_table->Name != 0)
	{
		// 先获取到导入模块的名称
		DWORD name_foa = rva_to_foa(buff, import_table->Name);
		PCHAR name = (PCHAR)(buff + name_foa);
		printf("%s \n", name);
		if (PageTick()) return;
		// 获取到导入地址表 IMAGE_THUNK_DATA
		// Thunk 的宽度由文件自身的 PE32/PE32+ 决定，不能由本程序的目标架构决定
		DWORD iat_foa = rva_to_foa(buff, import_table->FirstThunk);
		if (PeIs64(buff))
		{
			PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(buff + iat_foa);
			while (iat->u1.AddressOfData != 0)
			{
				if (!IMAGE_SNAP_BY_ORDINAL64(iat->u1.Ordinal))
				{
					// 否则就是名称导入
					DWORD name_table_foa =
						rva_to_foa(buff, (DWORD)iat->u1.AddressOfData);
					PIMAGE_IMPORT_BY_NAME name_table =
						(PIMAGE_IMPORT_BY_NAME)(buff + name_table_foa);

					printf("序号：%02X, 函数名 : %s \n",
						name_table->Hint,
						name_table->Name);
					if (PageTick()) return;
				}
				// 判断最高位是否为1，如果为1就是序号导入
				else
				{
					printf("导入序号为 %02x \n",
						(DWORD)(iat->u1.Ordinal & 0x7FFFFFFF));
					if (PageTick()) return;
				}
				iat++;
			}
		}
		else
		{
			PIMAGE_THUNK_DATA32 iat = (PIMAGE_THUNK_DATA32)(buff + iat_foa);
			while (iat->u1.AddressOfData != 0)
			{
				if (!IMAGE_SNAP_BY_ORDINAL32(iat->u1.Ordinal))
				{
					// 否则就是名称导入
					DWORD name_table_foa =
						rva_to_foa(buff, iat->u1.AddressOfData);
					PIMAGE_IMPORT_BY_NAME name_table =
						(PIMAGE_IMPORT_BY_NAME)(buff + name_table_foa);

					printf("序号：%02X, 函数名 : %s \n",
						name_table->Hint,
						name_table->Name);
					if (PageTick()) return;
				}
				// 判断最高位是否为1，如果为1就是序号导入
				else
				{
					printf("导入序号为 %02x \n",
						iat->u1.Ordinal & 0x7FFFFFFF);
					if (PageTick()) return;
				}
				iat++;
			}
		}
		import_table++;
	}
}

void debugger::veExport(char* buff)
{

	// 导出表在数据目录表的第 0 项
	DWORD export_rva = PeDataDirectoryRva(buff, 0);
	DWORD export_foa = rva_to_foa(buff, export_rva);

	// 获取到导出表的数据
	PIMAGE_EXPORT_DIRECTORY export_table =
		(PIMAGE_EXPORT_DIRECTORY)(buff + export_foa);

	// 解析内容
	DWORD name_foa = rva_to_foa(buff, export_table->Name);
	PCHAR name = (PCHAR)(buff + name_foa);
	//printf("导出模块的名称：%s\n", name);

	// 获取到序号的基址
	DWORD base = export_table->Base;
	// 获取到两张表的数量
	DWORD address_count = export_table->NumberOfFunctions;
	DWORD name_count = export_table->NumberOfNames;
	// 遍历三张表，获取数据，如果哪张表没有内容了代表遍历完成？
	// 【地址表】，名称表，名称序号表
	// 得到函数地址表
	DWORD func_table_rva = export_table->AddressOfFunctions;
	DWORD func_table_foa = rva_to_foa(buff, func_table_rva);
	PDWORD func_table = PDWORD(buff + func_table_foa);
	// 得到函数名称表
	DWORD name_table_rva = export_table->AddressOfNames;
	DWORD name_table_foa = rva_to_foa(buff, name_table_rva);
	PDWORD name_table = PDWORD(buff + name_table_foa);
	// 得到名称序号表// 我们可以自己实现 GetProcAddress 这个函数
	DWORD ordinal_table_rva = export_table->AddressOfNameOrdinals;
	DWORD ordinal_table_foa = rva_to_foa(buff, ordinal_table_rva);
	PWORD ordinal_table = PWORD(buff + ordinal_table_foa);

	// 开始遍历,因为地址表中的内容多，所以用他遍历
	for (DWORD i = 0; i < address_count; i++)
	{
		if (func_table[i] == 0)
		{
			// 如果地址表的内容为 0 就是无效函数
			continue;
		}
		// 判断函数是否在名称表中，如果在就是名称导出，否则就是序号导出
		// 标志位，如果为假，就说明不在名称表中
		bool is_find = false;
		for (DWORD j = 0; j < name_count; j++)
		{
			// i 是从 0 开始遍历，序号表也就不需要加 base 了
			// 如果地址表的索引和名称序号表的内容一致，就说明名称导出
			// printf("%d %d\n", i, ordinal_table[j]);
			if (i == (DWORD)ordinal_table[j])
			{
				is_find = true;
				PCHAR fun_name =
					(PCHAR)(buff + rva_to_foa(buff, name_table[j]));
				/*printf("函数地址: %p  函数名称: %s  \n",
					func_table[i], fun_name);*/
				ExMoNa.push_back(fun_name);
				ULONG_PTR e_Addr = foa_to_va(buff, func_table[i]);
				//printf("%x", e_Addr);
				ExMoAddr.push_back(e_Addr);
				break;
			}
		}
	}
}

//按寄存器名读取当前值：x64 下 rax…r15 按全宽取值，eax 等仍取低 32 位（Win32 只有 eax…eip）
static bool ReadRegisterByName(CONTEXT& ct, const char* szName, ULONG_PTR& value)
{
#ifdef _WIN64
	if (!_stricmp(szName, "rax")) { value = (ULONG_PTR)ct.Rax; return true; }
	if (!_stricmp(szName, "rbx")) { value = (ULONG_PTR)ct.Rbx; return true; }
	if (!_stricmp(szName, "rcx")) { value = (ULONG_PTR)ct.Rcx; return true; }
	if (!_stricmp(szName, "rdx")) { value = (ULONG_PTR)ct.Rdx; return true; }
	if (!_stricmp(szName, "rsi")) { value = (ULONG_PTR)ct.Rsi; return true; }
	if (!_stricmp(szName, "rdi")) { value = (ULONG_PTR)ct.Rdi; return true; }
	if (!_stricmp(szName, "rsp")) { value = (ULONG_PTR)ct.Rsp; return true; }
	if (!_stricmp(szName, "rbp")) { value = (ULONG_PTR)ct.Rbp; return true; }
	if (!_stricmp(szName, "rip")) { value = (ULONG_PTR)ct.Rip; return true; }
	if (!_stricmp(szName, "r8")) { value = (ULONG_PTR)ct.R8; return true; }
	if (!_stricmp(szName, "r9")) { value = (ULONG_PTR)ct.R9; return true; }
	if (!_stricmp(szName, "r10")) { value = (ULONG_PTR)ct.R10; return true; }
	if (!_stricmp(szName, "r11")) { value = (ULONG_PTR)ct.R11; return true; }
	if (!_stricmp(szName, "r12")) { value = (ULONG_PTR)ct.R12; return true; }
	if (!_stricmp(szName, "r13")) { value = (ULONG_PTR)ct.R13; return true; }
	if (!_stricmp(szName, "r14")) { value = (ULONG_PTR)ct.R14; return true; }
	if (!_stricmp(szName, "r15")) { value = (ULONG_PTR)ct.R15; return true; }
#endif
	if (!_stricmp(szName, "eax")) { value = (ULONG_PTR)EAX_OF(ct); return true; }
	if (!_stricmp(szName, "ebx")) { value = (ULONG_PTR)EBX_OF(ct); return true; }
	if (!_stricmp(szName, "ecx")) { value = (ULONG_PTR)ECX_OF(ct); return true; }
	if (!_stricmp(szName, "edx")) { value = (ULONG_PTR)EDX_OF(ct); return true; }
	if (!_stricmp(szName, "esi")) { value = (ULONG_PTR)ESI_OF(ct); return true; }
	if (!_stricmp(szName, "edi")) { value = (ULONG_PTR)EDI_OF(ct); return true; }
	if (!_stricmp(szName, "esp")) { value = (ULONG_PTR)ESP_OF(ct); return true; }
	if (!_stricmp(szName, "ebp")) { value = (ULONG_PTR)EBP_OF(ct); return true; }
	if (!_stricmp(szName, "eip")) { value = (ULONG_PTR)EIP_OF(ct); return true; }
	return false;
}

bool debugger::RegisterBreakpoint(HANDLE hThread, const char* szName, ULONG_PTR nValue, ULONG_PTR& addr)
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	ULONG_PTR current = 0;
	if (ReadRegisterByName(context, szName, current) && current == nValue)
	{
		addr = IP_OF(context);
		flag = 0;
		return TRUE;
	}
	//单步步入到下一行
	context.EFlags = 0x00000100;
	//将陷阱标志还原
	SetThreadContext(hThread, &context);
	flag = 2;
	bpInfo.PreviousIsBp = 0;
	return FALSE;
}

bool debugger::ConditionalBreakpoint(HANDLE hThread, const char* szName, ULONG_PTR nValue)
{
	CONTEXT co = { 0 };
	co.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &co);
	ULONG_PTR current = 0;
	if (ReadRegisterByName(co, szName, current) && current == nValue)
	{
		return TRUE;
	}
	rflag = 3;
	bpInfo.PreviousIsBp = 0;
	return FALSE;
}

ULONG_PTR debugger::foa_to_va(char* buff, DWORD dwFOA)
{
	PIMAGE_SECTION_HEADER pSection = NULL;
	DWORD NumberOfSectinsCount = 0;
	ULONG_PTR dwImageBase = 0;

	pSection = PeFirstSection(buff);

	dwImageBase = PeImageBase(buff);
	NumberOfSectinsCount = PeNt32(buff)->FileHeader.NumberOfSections;
	for (DWORD each = 0; each < NumberOfSectinsCount; each++)
	{
		DWORD PointerRawStart = pSection[each].PointerToRawData;                                // 文件偏移开始位置
		DWORD PointerRawEnds = pSection[each].PointerToRawData + pSection[each].SizeOfRawData;  // 文件偏移结束位置

		if (dwFOA >= PointerRawStart && dwFOA <= PointerRawEnds)
		{
			DWORD RVA = pSection[each].VirtualAddress + (dwFOA - pSection[each].PointerToRawData);  // 计算出RVA
			ULONG_PTR VA = (ULONG_PTR)RVA + dwImageBase;                                             // 计算出VA
			return VA;
		}
	}
	return -1;
}


//char* debugger::WideCharToMultiByte(const wchar_t* wideChar)
//{
//	// 1. 首先指定接收转换结果的指针
//	char* multiByte;
//	// 2. 然后第一次调用函数，获取存储转换结果所需缓冲区的大小
//	int len = (int)WideCharToMultiByte(CP_ACP, NULL,
//		wideChar,	// 要被转换的宽字符字符串
//		-1,			// 要转换的长度，设为-1表示转换整串
//		NULL,		// 第一次调用，接收缓冲区设置为NULL
//		NULL,		// 接收缓冲区的大小，设为NULL表示让函数返回需要的大小
//		NULL, NULL);
//	// 3. 根据返回的结果创建合适大小的缓冲区
//	multiByte = new char[len];
//	// 4. 第二次调用函数，进行真正的转换
//	WideCharToMultiByte(CP_ACP,
//		NULL,
//		wideChar,	// 要被转换的宽字符字符串
//		-1,			// 要转换的长度，设为-1表示转换整串
//		multiByte,	// 第二次调用，设为接收转换结果的缓冲区指针
//		len,		// 设定接收缓冲区大小
//		NULL, NULL);
//	return multiByte;
//}


//读取一个十六进制地址（支持 0x 前缀与纯十六进制，x64 下保留完整 64 位）
static bool PromptHex64(const char* szTip, ULONG_PTR& value)
{
	char text[64] = { 0 };
	printf("%s", szTip);
	if (scanf_s("%63s", text, (UINT)sizeof(text)) != 1)
	{
		printf("\n");
		return false;
	}
	printf("\n");
	unsigned __int64 v = 0;
	if (!ParseHex64(text, v))
	{
		printf("地址格式错误：%s（示例：00007FF60BFE1270 或 0x7FF60BFE1270）\n", text);
		return false;
	}
	value = (ULONG_PTR)v;
	return true;
}

//读取一个数值：0x 开头按十六进制，否则按十进制
static bool PromptNumber64(const char* szTip, ULONG_PTR& value)
{
	char text[64] = { 0 };
	printf("%s", szTip);
	if (scanf_s("%63s", text, (UINT)sizeof(text)) != 1)
	{
		printf("\n");
		return false;
	}
	printf("\n");
	const char* p = text;
	int base = 10;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
	{
		p += 2;
		base = 16;
	}
	errno = 0;
	char* end = nullptr;
	unsigned __int64 v = _strtoui64(p, &end, base);
	if (errno == ERANGE || end == p || *end != '\0')
	{
		printf("数值格式错误：%s（示例：10 或 0x1F）\n", text);
		return false;
	}
	value = (ULONG_PTR)v;
	return true;
}

void debugger::GetInput()
{
	char szCmd[0x10] = { 0 };

	while (1)
	{
		if (flag == 2 || rflag == 3)
		{
			if (flag == 2)
			{

				strcpy_s(szCmd, 0x10, "cp");
			}
			else if (rflag == 3)
			{
				strcpy_s(szCmd, 0x10, "rp");
			}
		}
		else
		{
			// stdin 结束（EOF）/读取出错时退出命令循环：
			// 否则 szCmd 跨迭代保留旧值，"bp" 等等待参数的命令会无限重放提示刷屏
			if (scanf_s("%s", szCmd, (unsigned)sizeof(szCmd)) != 1)
			{
				break;
			}
		}
		//go
		if (!_stricmp(szCmd, "g"))
		{
			if (rflag != 1)
			{
				break;

			}
			else
			{
				rflag = 3;
				//break;
			}
		}
		else if (!_stricmp(szCmd, "t"))//单步步入
		{
			flag = 1;
			//设置一个单步步入断点 
			Breakpoint::SetTfBreakPoint(hThread);
			bpInfo.PreviousIsBp = 0;
			break;
		}
		else if (!_stricmp(szCmd, "bp"))//int3的输入逻辑
		{
			//x64 地址是 64 位，必须按 ULONG_PTR 解析，否则高位被截断导致断点不命中
			ULONG_PTR addr = 0;
			if (PromptHex64("请输入地址：", addr))
				Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)addr);
		}
		else if (!_stricmp(szCmd, "ba"))//硬件断点
		{
			//原理:由cpu所提供的这个Dr系列寄存器做多可以设置4个硬件断点
			//断点的位置由Dr0-Dr3去保存,相应的Dr7中的Ln表示对应的断点是否
			//有效,Dr7中还提供RW\LEN标志位,用于设置断点的类型以及读写长度
			//RW:0(执行断点,他的这个len也必须为0), 1(写) 3(读)
			//LEN:0(1字节), 1(2字节), 2(8字节), 3(4字节)
			//硬件读写断点是一个陷阱式异常,会断在下一条指令
			ULONG_PTR addr = 0;
			if (PromptHex64("请输入地址：", addr))
			{
				int type = 0;
				int len = 0, l = 1;
				printf("请输入类型：");
				scanf_s("%x", &type);
				printf("\n");
				printf("请输入大小：");
				scanf_s("%x", &len);
				printf("\n");
				if (len == 1)
					l = 2;
				else if (len == 2)
					l = 8;
				else if (len == 3)
					l = 4;
				//执行断点(类型0)必须使用 1 字节长度(LEN=0)，否则 CPU 行为未定义
				if (type == 0)
					l = 0;
				Breakpoint::SetHwBreakPoint(hThread, (LPVOID)addr, type, l);
			}
		}
		else if (!_stricmp(szCmd, "bd"))//删除硬件断点（清除 Dr0-Dr3）
		{
			Breakpoint::ClearHwBreakpoints(hThread);
		}
		else if (!_stricmp(szCmd, "bm"))//内存断点
		{
			//0读取异常  1写入异常 8执行异常
			ULONG_PTR addr = 0;
			if (PromptHex64("请输入地址：", addr))
			{
				int type = 0;
				printf("请输入类型：");
				scanf_s("%d", &type);
				printf("\n");
				g_dWMemAddr = (LPVOID)addr;
				Breakpoint::SetMmBreakpoint(hProcess, (LPVOID)addr, type);
			}
		}
		else if (!_stricmp(szCmd, "e"))//寄存器
		{
			Capstone::nRegister(hThread);
		}
		else if (!_stricmp(szCmd, "s"))//堆栈
		{
			DWORD Count = 0;
			printf("请输入显示个数：");
			scanf_s("%d", &Count);
			printf("\n");
			Capstone::Stack(hProcess, hThread, Count);
		}
		else if (!_stricmp(szCmd, "m"))//内存
		{
			ULONG_PTR addr = 0;
			if (PromptHex64("请输入地址：", addr))
			{
				DWORD Count = 0;
				printf("请输入显示个数：");
				scanf_s("%d", &Count);
				printf("\n");
				Capstone::nMemory(hProcess, (LPCVOID)addr, Count);
			}
		}
		else if (!_stricmp(szCmd, "mo"))//模块
		{
			Capstone::GetModules(debugEvent.dwProcessId);
		}
		else if (!_stricmp(szCmd, "ee"))//修改寄存器
		{
			char nReg[20] = { 0 };
			printf("请输入寄存器名称：");
			scanf_s("%s", nReg, 20);
			printf("\n");
			ULONG_PTR dwValue = 0;
			if (PromptNumber64("请输入值：", dwValue))
				Capstone::AlternRegister(hThread, nReg, dwValue);
		}
		else if (!_stricmp(szCmd, "em"))//修改内存
		{
			ULONG_PTR addr = 0;
			if (PromptHex64("请输入地址：", addr))
			{
				// 接收值后只写入最低的一个字节，避免写满 4 字节溢出 1 字节缓冲区
				ULONG_PTR dwValue = 0;
				if (PromptNumber64("请输入值：", dwValue))
				{
					BYTE byteValue = (BYTE)(dwValue & 0xFF);
					int Count = 1;
					Capstone::AlternMemory(hProcess, (LPVOID)addr, &byteValue, Count);
				}
			}
		}
		else if (!_stricmp(szCmd, "ea"))//修改汇编代码
		{
			Capstone::AlterDisAsm(hProcess);
		}
		else if (!_stricmp(szCmd, "p"))//单步步过
		{
			flag = 1;
			Capstone::SetStepFlag(hProcess, hThread);
			bpInfo.PreviousIsBp = 0;
			break;
		}
		else if (!_stricmp(szCmd, "ei"))//解析被调试程序任意模块的导出表和导入表
		{
			ExportImport(debugEvent.dwProcessId);
		}
		else if (!_stricmp(szCmd, "rp"))//条件断点
		{
			if (rflag != 3)
			{
				if (!PromptHex64("请输入地址：", r_addr))
					continue;
				printf("请输入寄存器名称：");
				scanf_s("%s", r_Name, 30);
				printf("\n");
				if (!PromptNumber64("请输入值：", r_Value))
					continue;
				//显示读到的寄存器值（x64 下为完整 64 位），便于确认比较基准
				{
					CONTEXT ct = { 0 };
					ct.ContextFlags = CONTEXT_ALL;
					GetThreadContext(hThread, &ct);
					ULONG_PTR cur = 0;
					if (ReadRegisterByName(ct, r_Name, cur))
						printf("当前 %s = %p（目标 %p）\n", r_Name, (PVOID)cur, (PVOID)r_Value);
					else
						printf("不支持的寄存器名：%s（x64 可用 rax…r15 或 eax…eip）\n", r_Name);
				}
			}
			if (nflag == 0)
			{
				nflag = 3;
				Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)(ULONG_PTR)r_addr);
			}
			if (ConditionalBreakpoint(hThread, r_Name, r_Value))
			{
				rflag = 1;
				Capstone::DisAsm(hProcess, (LPVOID)(ULONG_PTR)r_addr, 10);
				flag = 1;
				//设置一个单步步入断点 
				Breakpoint::SetTfBreakPoint(hThread);
				bpInfo.PreviousIsBp = 0;
				break;
			}
			else
			{
				break;
			}
		}
		else if (!_stricmp(szCmd, "cp"))//寄存器断点
		{
			if (flag != 2)
			{
				printf("请输入寄存器名称：");
				scanf_s("%s", n_Name, 30);
				printf("\n");
				if (!PromptNumber64("请输入值：", n_Value))
					continue;
				//显示读到的寄存器值（x64 下为完整 64 位），便于确认比较基准
				CONTEXT ct = { 0 };
				ct.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hThread, &ct);
				ULONG_PTR cur = 0;
				if (ReadRegisterByName(ct, n_Name, cur))
					printf("当前 %s = %p（目标 %p）\n", n_Name, (PVOID)cur, (PVOID)n_Value);
				else
					printf("不支持的寄存器名：%s（x64 可用 rax…r15 或 eax…eip）\n", n_Name);
			}

			if (RegisterBreakpoint(hThread, n_Name, n_Value, n_addr))
			{
				Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)(ULONG_PTR)n_addr);
				//Capstone::DisAsm(hProcess, (LPVOID)r_addr, 10);
			}
			if (flag != 0)
			{
				break;
			}
		}
		else if (!_stricmp(szCmd, "api"))//API断点
		{
			char nName[30] = { 0 };
			ModuleAPI(debugEvent.dwProcessId);
			printf("请输入函数名：");
			scanf_s("%s", nName, 30);
			for (size_t i = 0; i < ExMoNa.size(); i++)
			{
				if (strcmp(nName, ExMoNa[i]) == 0)
				{

					Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)ExMoAddr[i]);
					break;
				}
			}
		}
		else if (!_stricmp(szCmd, "crp"))//取消条件断点
		{
			rflag = 10;
			Breakpoint::Deletepoint(hProcess, (LPVOID)(ULONG_PTR)r_addr, hThread);
			
		}
	}
}