#pragma once
#include<windows.h>
#include<stdio.h>
#include<DbgHelp.h>
#include<atlstr.h>
#include<vector>
#include<atlstr.h>
#include<tlhelp32.h>
#pragma comment(lib,"Dbghelp.lib") 
using std::vector;

//保存符号信息的结构体
//typedef struct _SYMBOL_INFO {
//	ULONG SizeOfStruct;//结构体大小
//	ULONG TypeIndex;
//	ULONG64 Reserved[2];
//	ULONG Index;
//	ULONG Size;
//	ULONG ModBase;
//	ULONG Flags;
//	ULONG64 Value;
//	ULONG64 Address;//符号的地址
//	ULONG Register;
//	ULONG Scope;
//	ULONG Tag;
//	ULONG NameLen;//符号名的字节数
//	ULONG MaxNameLen;//保存符号名的空间最大字节数
//	TCHAR Name[1];//保存符号名的缓冲名
//}SYMBOL_INFO,*_PSYMBOL_INFO;

class debugger
{
public:
	//被调试程序继续运行
	DWORD deContinueStatus = DBG_CONTINUE;
	//结构体，用来接受调试系统发送过来的异常
	DEBUG_EVENT debugEvent;
	//打开目标程序；创建失败返回 false
	bool open(LPCSTR szPath);
	void run();
	//打开句柄
	void openHandles();
	//关闭句柄
	void closeHandles();
	//定义进程句柄
	HANDLE hProcess;
	//定义线程句柄
	HANDLE hThread;
	//获取OEP
	//LPVOID oep;
	//定义一个标志位，用来设置一次性的断点（系统断点）
	BOOL isSystemPoint = TRUE;
	//获取用户输入的一个函数
	void GetInput();
	//定义一个分发异常的函数，处理异常事件，修复断点
	void OnDispatchException();
	//附加程序
	bool Open(DWORD dwPid);
	//获取调试符号
	void GetDebugSymbol();
	//通过名称获取地址
	SIZE_T GetSymAddress(HANDLE hProcess, const char* pszName);
	//通过地址获取名称
	BOOL GetSymName(HANDLE hProcess, SIZE_T nAddress, CString& strName);
	//获取一个符号对应的地址方法
	SIZE_T FindApiAddress(HANDLE hProcess, const char* pszName);
	//遍历所有模块的导出表
	void ModuleAPI(DWORD PID);
	//遍历所有模块的任意模块的导出表和导入表
	void ExportImport(DWORD PID);
	// 读取文件，返回值是读取到的缓冲区
	char* read_file(const char* path);
	// 判断文件是不是 PE 文件
	bool is_pe_file(char* buff);
	// RVA 转换成 FOA 
	DWORD rva_to_foa(char* buff, DWORD rva);
	// 解析导出表
	void get_export_information(char* buff);
	// 解析导入表
	void get_import_information(char* buff);
	// 导出表函数存储动态数组
	void veExport(char* buff);
	//宽字符转多字节
	//char* WideCharToMultiByte(const wchar_t* wideChar);
	//寄存器断点（addr 按指针宽度返回，x64 下为 64 位地址）
	bool RegisterBreakpoint(HANDLE hThread, const char* szName, ULONG_PTR nValue, ULONG_PTR& addr);
	//条件断点
	bool ConditionalBreakpoint(HANDLE hThread,const char*szName, ULONG_PTR nValue);
	//foa转va
	ULONG_PTR foa_to_va(char* buff, DWORD dwFOA);
};