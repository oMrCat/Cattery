#pragma once
#include<windows.h>
//定义一个用来保存cc的结构体
typedef struct _bp
{
	//断点的类型
	int type;
	//下断指令的地址
	LPVOID addr;
	//原本的内容
	BYTE oldBytes;
}bp;

struct PreviousbpInfo {
	//标志TF
	int PreviousIsBp = 0;
	//判断TF之前是什么类型的断点
	int whichbp = -1;
	//上一步断点的地址
	LPVOID previousAddr;
	int type;
	int len;
};


class Breakpoint
{
public:
	//Tf是Eflag标志寄存器中的一个标志位，是用来设置单步断点的
	static void SetTfBreakPoint(HANDLE hThread);
	//用来int3断点,要使用到被调试的进程，需要使用写入内存writeprocessmemory
	static void SetInt3BreakPoint(HANDLE hProcess, LPVOID addr);
	//修复（将写入的cc删除）
	static void FixInt3BreakPoint(HANDLE hProcess, LPVOID addr, HANDLE hThread);
	//设置硬件断点
	static void SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len);
	//修复硬件断点
	static void FixHwBreakpoint(HANDLE hThread, HANDLE hProcess, LPVOID addr);
	//删除全部硬件断点（清除 Dr0-Dr3 使能位）
	static void ClearHwBreakpoints(HANDLE hThread);
	//设置内存断点
	static void SetMmBreakpoint(HANDLE hProcess, LPVOID addr, int type);
	//修复内存断点
	static void FixMmBreakpoint(HANDLE hProcess, HANDLE hThread, LPVOID addr, int type);
	//设置删除断点
	static void Deletepoint(HANDLE hProcess, LPVOID addr, HANDLE hThread);
};