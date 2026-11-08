#pragma once
#include<windows.h>
#include<TlHelp32.h>
#include<iostream> 
#include<stdlib.h>
#include<cerrno>
#include"breakpoint.h"
#include"XEDParse.h"
#include"Capstone/include/capstone.h"

// 统一解析十六进制地址/数值：兼容 0x 前缀与纯十六进制，x64 下支持完整 64 位。
// 解析失败（空串、非法字符、溢出）返回 false。
inline bool ParseHex64(const char* text, unsigned __int64& value)
{
	if (text == nullptr)
		return false;
	const char* p = text;
	while (*p == ' ' || *p == '\t')
		++p;
	if (*p == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;
	if (*p == '\0')
		return false;
	errno = 0;
	char* end = nullptr;
	unsigned __int64 v = _strtoui64(p, &end, 16);
	if (errno == ERANGE || end == p)
		return false;
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		++end;
	if (*end != '\0')
		return false;
	value = v;
	return true;
}
#ifdef _WIN64
#pragma comment(lib,"capstone_x64.lib")
#pragma comment(lib,"XEDParse_x64.lib")
#else
#pragma comment(lib,"capstone/capstone.lib")
#pragma comment(lib,"XEDParse.lib")
#endif 
#pragma comment(linker,"/NODEFAULTLIB:\"libcmtd.lib\"")

//反汇编引擎（工具类）：主要操作是通过传入的地址返回
//上面保存的代码信息
//可以对输出格式进行丰富化
class Capstone
{
private:
	//用于初始化和内存管理的句柄
	static csh Handle;
	static cs_opt_mem OptMem;

public:
	//设置为默认构造函数
	Capstone() = default;
	~Capstone() = default;

	//用于初始化的函数
	static void Init();
	static int GetInstrLen(HANDLE Handle, LPVOID Addr, DWORD Count, char* Code);
	//用于执行反汇编的函数
	static void DisAsm(HANDLE Handle, LPVOID Addr, DWORD Count);
	//用于获取寄存器信息的函数
	static void nRegister(HANDLE hThread);
	//用于获取堆栈信息的函数
	static void Stack(HANDLE hProcess, HANDLE hThread, DWORD Count);
	//用于获取内存信息的函数
	static void nMemory(HANDLE hProcess, LPCVOID addr, DWORD Count);
	//获取模块信息
	static void GetModules(DWORD PID);
	//修改寄存器数据（值按指针宽度传入，x64 下为 64 位）
	static void AlternRegister(HANDLE hThread, const char* Reg, ULONG_PTR dwValue);
	//修改内存信息数据
	static void AlternMemory(HANDLE hProcess, LPVOID addr, const BYTE* buff,int Count);
	//修改反汇编
	static void AlterDisAsm(HANDLE hProcess);
	//设置单步步过
	static void SetStepFlag(HANDLE hProcess, HANDLE hThread);
	
};