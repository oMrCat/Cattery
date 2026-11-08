#include "breakpoint.h"
#include<vector>
using std::vector;
vector<bp>g_bp;
vector<bp>d_bp;
PreviousbpInfo bpInfo;
extern LPVOID oep;
//模拟DR7的结构体
typedef struct _DBG_REG7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} R7, * PR7;
void Breakpoint::SetTfBreakPoint(HANDLE hThread)
{
	//TF 陷阱标志，此标志为1时，CPU每次仅会执行1条指令，执行完之后标志位变为0
   //获取所有的寄存器的信息
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_FULL;
	//把当前线程运行所获得的寄存器信息填充到这个context当中
	GetThreadContext(hThread, &context);
	context.EFlags = 0x00000100;
	//将陷阱标志还原
	SetThreadContext(hThread, &context);
}

void Breakpoint::SetInt3BreakPoint(HANDLE hProcess, LPVOID addr)
{
	//	设置cc，但是要修复
	bp int3Bp = { 0 };
	//当前下断的地址放到int3Bp里面
	int3Bp.addr = addr;
	SIZE_T dwRead = 0;
	//读取内存,将头一个字节保存起来
	ReadProcessMemory(hProcess, addr, &int3Bp.oldBytes, 1, &dwRead);
	//写入cc
	BYTE cc = '\xcc';
	WriteProcessMemory(hProcess, addr, &cc, 1, &dwRead);
	//将断点存入vector中
	g_bp.push_back(int3Bp);
	d_bp.push_back(int3Bp);
}

void Breakpoint::FixInt3BreakPoint(HANDLE hProcess, LPVOID addr, HANDLE hThread)
{
	for (size_t i = 0; i < g_bp.size(); i++)
	{
		if (addr == g_bp[i].addr)
		{
			bpInfo.previousAddr = addr;
			SIZE_T bytes = 0;
			WriteProcessMemory(hProcess, addr, &g_bp[i].oldBytes, 1, &bytes);
			//使用线程的上下文
			CONTEXT context = { 0 };
			context.ContextFlags = CONTEXT_ALL;
			//读取寄存器
			GetThreadContext(hThread, &context);
#ifdef _WIN64
			context.Rip -= 1;
#else
			context.Eip -= 1;
#endif
			//写入寄存器
			SetThreadContext(hThread, &context);
			//oep不需设置永久断点，修复TF断点，就不会触发
			if (::oep != addr)
			{
				Breakpoint::SetTfBreakPoint(hThread);
				bpInfo.PreviousIsBp = 1;
				bpInfo.whichbp = 0;
			}
			//单步步入到下一行
			Breakpoint::SetTfBreakPoint(hThread);
			bpInfo.PreviousIsBp = 1;
			//软件int3断点
			bpInfo.whichbp = 0;
			//删除g_bp[i].addr的地址
			vector<bp>::iterator it = g_bp.begin() + i;
			g_bp.erase(it);
		}
	}
}

void Breakpoint::SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len)
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	PR7 Dr7 = (PR7)&context.Dr7;

	if (Dr7->L0 == 0)
	{
		Dr7->L0 = 1;
		Dr7->LEN0 = len;
		Dr7->RW0 = type;
		context.Dr0 = (DWORD_PTR)addr;
	}
	else if (Dr7->L1 == 0)
	{
		Dr7->L1 = 1;
		Dr7->LEN1 = len;
		Dr7->RW1 = type;
		context.Dr1 = (DWORD_PTR)addr;
	}
	else if (Dr7->L2 == 0)
	{
		Dr7->L2 = 1;
		Dr7->LEN2 = len;
		Dr7->RW2 = type;
		context.Dr2 = (DWORD_PTR)addr;
	}
	else if (Dr7->L3 == 0)
	{
		Dr7->L3 = 1;
		Dr7->LEN3 = len;
		Dr7->RW3 = type;
		context.Dr3 = (DWORD_PTR)addr;
	}
	else
	{
		printf("没有可用的硬件寄存器了!");
	}
	SetThreadContext(hThread, &context);
	bpInfo.previousAddr = (LPVOID)addr;
}

void Breakpoint::FixHwBreakpoint(HANDLE hThread, HANDLE hProcess, LPVOID addr)
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	PR7 Dr7 = (PR7)&context.Dr7;
	LPVOID addr2 = 0;
	switch (context.Dr6 & 0xF)
	{
	case 1:
	{
		Dr7->L0 = 0;
		bpInfo.type = Dr7->RW0;
		addr2 = (LPVOID)context.Dr0;
		bpInfo.len = Dr7->LEN0;
	} break;
	case 2:
	{
		Dr7->L1 = 0;
		bpInfo.type = Dr7->RW1;
		addr2 = (LPVOID)context.Dr1;
		bpInfo.len = Dr7->LEN1;
	} break;
	case 4:
	{

		Dr7->L2 = 0;
		bpInfo.type = Dr7->RW2;
		addr2 = (LPVOID)context.Dr2;
		bpInfo.len = Dr7->LEN2;
	}
	break;
	case 8:
	{
		Dr7->L3 = 0;
		bpInfo.type = Dr7->RW3;
		addr2 = (LPVOID)context.Dr3;
		bpInfo.len = Dr7->LEN3;
	}
	break;
	default:
		break;
	}
	bpInfo.PreviousIsBp = 1;
	bpInfo.whichbp = 1;
	if (bpInfo.type == 0)
	{
		bpInfo.previousAddr = addr;
	}
	else if (bpInfo.type == 1 || bpInfo.type == 3)
	{

		bpInfo.previousAddr = addr2;
	}
	//清除 Dr6 的命中位，避免后续普通单步被误判为硬件断点命中
	context.Dr6 = 0;
	SetThreadContext(hThread, &context);
	Breakpoint::SetTfBreakPoint(hThread);
}

//清除所有硬件断点（Dr0-Dr3 的使能位与 Dr6 状态）
void Breakpoint::ClearHwBreakpoints(HANDLE hThread)
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	PR7 Dr7 = (PR7)&context.Dr7;
	Dr7->L0 = 0;
	Dr7->L1 = 0;
	Dr7->L2 = 0;
	Dr7->L3 = 0;
	context.Dr6 = 0;
	SetThreadContext(hThread, &context);
	printf("已删除硬件断点（Dr0-Dr3 使能位已清除）\n");
}

DWORD dwOldProtected;
LPVOID addr;
int type;
extern LPVOID g_dWMemAddr;
extern int nIsGo;
void Breakpoint::SetMmBreakpoint(HANDLE hProcess, LPVOID addr, int type)
{
	if (type == 8)
	{
		Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)addr);
	}
	else if (type == 1)
	{
		::addr = addr;
		::type = type;
		VirtualProtectEx(hProcess, addr, 1, PAGE_EXECUTE_READ, &dwOldProtected);
	}
	else if (type == 0)
	{
		::addr = addr;
		::type = type;
		VirtualProtectEx(hProcess, addr, 1, PAGE_NOACCESS, &dwOldProtected);
	}
}

void Breakpoint::FixMmBreakpoint(HANDLE hProcess, HANDLE hThread, LPVOID addr, int type)
{
	if (type == 8)
	{
		if (g_dWMemAddr == addr)
		{
			nIsGo = 1;
		}
		VirtualProtectEx(hProcess, addr, 1, dwOldProtected, &dwOldProtected);
	}
	if (type == 0)
	{
		if (g_dWMemAddr == addr)
		{
			nIsGo = 1;
		}
		VirtualProtectEx(hProcess, addr, 1, dwOldProtected, &dwOldProtected);
	}
	if (type == 1)
	{
		if (g_dWMemAddr == addr)
		{
			nIsGo = 1;
		}
		VirtualProtectEx(hProcess, addr, 1, dwOldProtected, &dwOldProtected);
	}
	SetTfBreakPoint(hThread);
	bpInfo.PreviousIsBp = 1;
	bpInfo.whichbp = 2;
}

void Breakpoint::Deletepoint(HANDLE hProcess, LPVOID addr, HANDLE hThread)
{
	for (size_t i = 0; i < d_bp.size(); i++)
	{
		if (addr == d_bp[i].addr)
		{
			bpInfo.previousAddr = addr;
			bpInfo.PreviousIsBp = 0;
			SIZE_T bytes = 0;
			WriteProcessMemory(hProcess, addr, &d_bp[i].oldBytes, 1, &bytes);
			vector<bp>::iterator it = d_bp.begin() + i;
			d_bp.erase(it);
		}
	}
}


