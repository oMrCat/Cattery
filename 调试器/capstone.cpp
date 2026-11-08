#include "capstone.h"
csh Capstone::Handle = { 0 };
cs_opt_mem Capstone::OptMem = { 0 };

//初始化反汇编引擎
void Capstone::Init()
{
	//配置堆空间的回调函数
	OptMem.free = free;
	OptMem.calloc = calloc;
	OptMem.malloc = malloc;
	OptMem.realloc = realloc;
	OptMem.vsnprintf = (cs_vsnprintf_t)vsprintf_s;

	//注册堆空间管理组函数
	cs_option(NULL, CS_OPT_MEM, (size_t)&OptMem);
	// 打开一个句柄
#ifdef _WIN64
	cs_open(CS_ARCH_X86, CS_MODE_64, &Capstone::Handle);
#else
	cs_open(CS_ARCH_X86, CS_MODE_32, &Capstone::Handle);
#endif
}
// 反汇编指定条数的语句
void Capstone::DisAsm(HANDLE Handle, LPVOID Addr, DWORD Count)
{
	// 用来读取指令位置内存的缓冲区信息
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[Count * 16]{ 0 };

	// 读取指定长度的内存空间

	//call  rep
	SIZE_T dwWrite = 0;
	ReadProcessMemory(Handle, (LPVOID)Addr, buff, Count * 16, &dwWrite);
	size_t count = cs_disasm(Capstone::Handle, (uint8_t*)buff, Count * 16, (uint64_t)Addr, 0, &ins);
	for (DWORD i = 0; i < Count; ++i)
	{
		// 地址列按架构宽度输出：x64 用 16 位十六进制，避免把 64 位地址截成 32 位
#ifdef _WIN64
		printf("%016I64X\t", (unsigned __int64)ins[i].address);
#else
		printf("%08X\t", (UINT)ins[i].address);
#endif
		for (uint16_t j = 0; j < 16; ++j)
		{
			if (j < ins[i].size)
				printf("%02X", ins[i].bytes[j]);
			else
				printf("  ");
		}
		// 输出对应的反汇编
		printf("\t%s %s\n", ins[i].mnemonic, ins[i].op_str);
	}

	printf("\n");
	// 释放动态分配的空间
	delete[] buff;
	cs_free(ins, count);
}

void Capstone::nRegister(HANDLE hThread)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
#ifdef _WIN64
	printf("RAX:%016I64X\n", ct.Rax);
	printf("RBX:%016I64X\n", ct.Rbx);
	printf("RCX:%016I64X\n", ct.Rcx);
	printf("RDX:%016I64X\n", ct.Rdx);
	printf("RDI:%016I64X\n", ct.Rdi);
	printf("RSI:%016I64X\n", ct.Rsi);
	printf("RSP:%016I64X\n", ct.Rsp);
	printf("RBP:%016I64X\n", ct.Rbp);
	printf("RIP:%016I64X\n", ct.Rip);
	printf("R8 :%016I64X\n", ct.R8);
	printf("R9 :%016I64X\n", ct.R9);
	printf("R10:%016I64X\n", ct.R10);
	printf("R11:%016I64X\n", ct.R11);
	printf("R12:%016I64X\n", ct.R12);
	printf("R13:%016I64X\n", ct.R13);
	printf("R14:%016I64X\n", ct.R14);
	printf("R15:%016I64X\n", ct.R15);
	printf("EFlags:%08X\n", ct.EFlags);
#else
	printf("EAX:%08X\n", ct.Eax);
	printf("EBX:%08X\n", ct.Ebx);
	printf("ECX:%08X\n", ct.Ecx);
	printf("EDX:%08X\n", ct.Edx);
	printf("EDI:%08X\n", ct.Edi);
	printf("ESI:%08X\n", ct.Esi);
	printf("ESP:%08X\n", ct.Esp);
	printf("EBP:%08X\n", ct.Ebp);
	printf("EIP:%08X\n", ct.Eip);
	printf("EFlags:%08X\n", ct.EFlags);
#endif
}

void Capstone::Stack(HANDLE hProcess, HANDLE hThread, DWORD Count)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
	BYTE buff[512];
	SIZE_T dwRead = 0;
#ifdef _WIN64
	ReadProcessMemory(hProcess, (LPCVOID)ct.Rsp, buff, 512, &dwRead);
	for (DWORD i = 0; i < Count; i++)
	{
		// x64: each stack slot is 8 bytes (pointer width)
		printf("%016I64X\n", ((ULONG_PTR*)buff)[i]);
	}
#else
	ReadProcessMemory(hProcess, (LPCVOID)ct.Esp, buff, 512, &dwRead);
	for (DWORD i = 0; i < Count; i++)
	{
		printf("%08x\n", ((DWORD*)buff)[i]);
	}
#endif
}

void Capstone::nMemory(HANDLE hProcess, LPCVOID addr, DWORD Count)
{
	BYTE buff[512];
	SIZE_T dwRead = 0;
	ReadProcessMemory(hProcess, addr, buff, 512, &dwRead);
	if (Count < 16)
	{
		printf("%p:", (PVOID)addr);
		for (DWORD i = 0; i < Count; i++)
		{
			printf("%02x ", buff[i]);
		}
	}
	else
	{
		DWORD i = 0;
		int n = 0;
		if (Count % 16 == 0)
		{

			n = Count / 16;
		}
		else if (Count % 16 != 0)
		{
			n = Count / 16 + 1;
		}
		for (int j = 0; j < n; j++)
		{
			printf("%p:", (PVOID)((ULONG_PTR)addr + (16 * (size_t)j)));
			for (; i < Count; i++)
			{
				if (i % (16 * (j + 1)) == 0 && i != 0)
				{
					printf("\n");
					break;
				}
				printf("%02x ", buff[i]);
			}
		}
	}
	printf("\n\t");

}

void Capstone::GetModules(DWORD PID)
{
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
		return ;
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
			// 同时输出模块基址与大小：x64 下 modBaseAddr 本身就是 64 位指针，%p 会打印完整地址
			printf("%S  base=%p  size=0x%08X  path=%S\n", me.szModule, (PVOID)me.modBaseAddr, me.modBaseSize, me.szExePath);
		} while (Module32Next(hProcessSnapshot, &me));
	}
	CloseHandle(hProcessSnapshot);
}


void Capstone::AlternRegister(HANDLE hThread, const char* Reg, ULONG_PTR dwValue)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
#ifdef _WIN64
	// x64：支持 RAX/R8…R15 等 64 位寄存器整体写入；EAX/EIP 等只覆盖低 32 位，保持原 32 位语义。
	ULONG_PTR* reg = nullptr;
	bool low32 = false;
	if (!_stricmp(Reg, "RAX")) reg = &ct.Rax;
	else if (!_stricmp(Reg, "RBX")) reg = &ct.Rbx;
	else if (!_stricmp(Reg, "RCX")) reg = &ct.Rcx;
	else if (!_stricmp(Reg, "RDX")) reg = &ct.Rdx;
	else if (!_stricmp(Reg, "RDI")) reg = &ct.Rdi;
	else if (!_stricmp(Reg, "RSI")) reg = &ct.Rsi;
	else if (!_stricmp(Reg, "RSP")) reg = &ct.Rsp;
	else if (!_stricmp(Reg, "RBP")) reg = &ct.Rbp;
	else if (!_stricmp(Reg, "RIP")) reg = &ct.Rip;
	else if (!_stricmp(Reg, "R8")) reg = &ct.R8;
	else if (!_stricmp(Reg, "R9")) reg = &ct.R9;
	else if (!_stricmp(Reg, "R10")) reg = &ct.R10;
	else if (!_stricmp(Reg, "R11")) reg = &ct.R11;
	else if (!_stricmp(Reg, "R12")) reg = &ct.R12;
	else if (!_stricmp(Reg, "R13")) reg = &ct.R13;
	else if (!_stricmp(Reg, "R14")) reg = &ct.R14;
	else if (!_stricmp(Reg, "R15")) reg = &ct.R15;
	else if (!_stricmp(Reg, "EAX")) { reg = &ct.Rax; low32 = true; }
	else if (!_stricmp(Reg, "EBX")) { reg = &ct.Rbx; low32 = true; }
	else if (!_stricmp(Reg, "ECX")) { reg = &ct.Rcx; low32 = true; }
	else if (!_stricmp(Reg, "EDX")) { reg = &ct.Rdx; low32 = true; }
	else if (!_stricmp(Reg, "EDI")) { reg = &ct.Rdi; low32 = true; }
	else if (!_stricmp(Reg, "ESI")) { reg = &ct.Rsi; low32 = true; }
	else if (!_stricmp(Reg, "ESP")) { reg = &ct.Rsp; low32 = true; }
	else if (!_stricmp(Reg, "EBP")) { reg = &ct.Rbp; low32 = true; }
	else if (!_stricmp(Reg, "EIP")) { reg = &ct.Rip; low32 = true; }
	if (reg != nullptr)
	{
		if (low32)
			*reg = (*reg & ~(ULONG_PTR)0xFFFFFFFF) | (dwValue & 0xFFFFFFFF);
		else
			*reg = dwValue;
	}
	else
	{
		printf("未知寄存器：%s（可用 RAX-R15 / EAX-EIP）\n", Reg);
	}
#else
	if (strcmp(Reg, "EAX") == 0)
	{
		ct.Eax = dwValue;
	}
	else if (strcmp(Reg, "EBX") == 0)
	{
		ct.Ebx = dwValue;
	}
	else if (strcmp(Reg, "ECX") == 0)
	{
		ct.Ecx = dwValue;
	}
	else if (strcmp(Reg, "EDX") == 0)
	{
		ct.Edx = dwValue;
	}
	else if (strcmp(Reg, "EDI") == 0)
	{
		ct.Edi = dwValue;
	}
	else if (strcmp(Reg, "ESI") == 0)
	{
		ct.Esi = dwValue;
	}
	else if (strcmp(Reg, "EIP") == 0)
	{
		ct.Eip = dwValue;
	}
#endif

	SetThreadContext(hThread, &ct);
}

void Capstone::AlternMemory(HANDLE hProcess, LPVOID addr, const BYTE* buff, int Count)
{
	SIZE_T dwRead = 0;
	WriteProcessMemory(hProcess, addr, buff, Count, &dwRead);
}

void Capstone::AlterDisAsm(HANDLE hProcess)
{
	// 创建一个对象，用于操作汇编引擎.
	XEDPARSE xed = { 0 };
	// 关键：告诉 XEDParse 使用 64 位编码模式，否则 mov rax,rbx 这类指令会被当成 32 位而编码失败
#ifdef _WIN64
	xed.x64 = true;
#else
	xed.x64 = false;
#endif
	printf("请输入汇编指令的起始地址（十六进制，可带 0x）：\n");
	char addrText[64] = { 0 };
	if (scanf_s("%63s", addrText, (UINT)sizeof(addrText)) != 1)
	{
		printf("未读取到地址，已取消。\n");
		return;
	}
	// 丢弃本行剩余字符（含换行），避免后面的 gets_s 读到空行
	int ch;
	while ((ch = getchar()) != '\n' && ch != EOF) { }
	unsigned __int64 cip = 0;
	if (!ParseHex64(addrText, cip))
	{
		printf("地址格式错误：%s（示例：00007FF60BFE1270 或 0x7FF60BFE1270）\n", addrText);
		return;
	}
	xed.cip = cip;
	printf("请输入汇编指令（例如 nop / mov rax, rbx）：\n");
	if (gets_s(xed.instr, XEDPARSE_MAXBUFSIZE) == nullptr || xed.instr[0] == '\0')
	{
		printf("指令为空，已取消。\n");
		return;
	}
	// 使用 XEDParseAssemble() 函数将汇编指令转换成 OPCODE
	if (XEDPARSE_OK != XEDParseAssemble(&xed))
	{
#ifdef _WIN64
		printf("指令错误：%s（XEDParse 当前按 x64 编码，仍不支持该写法；可改用 nop 等简单指令验证）\n", xed.error);
#else
		printf("指令错误：%s\n", xed.error);
#endif
		return;
	}
	if (xed.dest_size == 0 || xed.dest_size > XEDPARSE_MAXASMSIZE)
	{
		printf("指令错误：编码结果长度非法（%u）\n", xed.dest_size);
		return;
	}

	// 代码段通常为只读，先临时放开写权限，写入后恢复
	DWORD oldProtect = 0, restoreProtect = 0;
	VirtualProtectEx(hProcess, (LPVOID)xed.cip, xed.dest_size, PAGE_EXECUTE_READWRITE, &oldProtect);
	SIZE_T dwWrite = 0;
	BOOL bWritten = WriteProcessMemory(hProcess, (LPVOID)xed.cip, xed.dest, xed.dest_size, &dwWrite);
	if (oldProtect != 0)
		VirtualProtectEx(hProcess, (LPVOID)xed.cip, xed.dest_size, oldProtect, &restoreProtect);
	if (!bWritten || dwWrite != xed.dest_size)
	{
		printf("写入失败：目标地址 %p 不可访问（err=%lu）\n", (PVOID)xed.cip, GetLastError());
		return;
	}
	printf("%p: ", (PVOID)xed.cip);
	for (DWORD i = 0; i < (DWORD)xed.dest_size; i++)
	{
		printf("%02X ", xed.dest[i]);
	}
	printf("\n写入成功。\n");
}

void Capstone::SetStepFlag(HANDLE hProcess,HANDLE hThread)
{
	CONTEXT ct = { 0 };
	ct.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ct);
#ifdef _WIN64
	ULONG_PTR Address = ct.Rip;
#else
	ULONG_PTR Address = ct.Eip;
#endif
	cs_insn* ins = nullptr;
	CHAR buff[512] = { 0 };
	SIZE_T bytesRead = 0;
	ReadProcessMemory(hProcess, (LPVOID)Address, buff, 512, &bytesRead);//必须先ReadProcessMemory到调试器中
	cs_disasm(Capstone::Handle, (uint8_t*)buff, (size_t)bytesRead, (uint64_t)Address, 0, &ins);
	//DWORD PID = GetProcessId(hProcess);
	if (!memcmp(ins->mnemonic, "call", 4) || !memcmp(ins->mnemonic, "rep", 3))
	{
		Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)(Address + ins->size));
	}
	else
	{
		Breakpoint::SetTfBreakPoint(hThread);
	}
}


int Capstone::GetInstrLen(HANDLE Handle, LPVOID Addr, DWORD Count, char* Code)
{
	// 用来读取指令位置内存的缓冲区信息
	cs_insn* ins = nullptr;
	PCHAR buff = new CHAR[Count * 16]{ 0 };
	int len = 0;
	// 读取指定长度的内存空间
	SIZE_T dwWrite = 0;
	ReadProcessMemory(Handle, (LPVOID)Addr, buff, Count * 16, &dwWrite);
	size_t count = cs_disasm(Capstone::Handle, (uint8_t*)buff, Count * 16, (uint64_t)Addr, 0, &ins);

	//for (DWORD i = 0; i < Count; ++i)
	//{
	//	printf("-----%08X\t", (UINT)ins[i].address); 
	//	for (uint16_t j = 0; j < 16; ++j)
	//	{
	//		if (j < ins[i].size)
	//			printf("%02X", ins[i].bytes[j]);
	//		else
	//			printf("  ");
	//	}
	//	// 输出对应的反汇编
	//	printf("\t%s %s\n", ins[i].mnemonic, ins[i].op_str);
	//}
	strcpy_s(Code, 10, ins[0].mnemonic);
	len = ins[0].size;
	//printf("\n");
	// 释放动态分配的空间
	delete[] buff;
	cs_free(ins, count);
	return len;
}
