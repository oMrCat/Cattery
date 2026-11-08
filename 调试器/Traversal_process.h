#pragma once
#include<windows.h>
#include<TlHelp32.h>

class Traversal_process
{
public:
	//枚举当前进程并打印 PID + 进程名，由用户输入 PID 选择；返回 0 表示未选择
	DWORD SelectProcess();
};
