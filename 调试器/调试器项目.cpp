#include<stdio.h>
#include"debugger.h"
#include"Plugin_Dll.h"
#include"Traversal_process.h"

int main()
{
	//Plugin_Dll nPlugin;
#ifndef _WIN64
	// Win32 版本依赖 32 位 XEDParse.dll：缺失时加载器会让进程静默退出，
	// 这里提前显式检查并给出明确提示（工程已将该 DLL 配置为延迟加载）
	if (LoadLibraryA("XEDParse.dll") == NULL)
	{
		printf("启动失败：缺少 XEDParse.dll（32 位）。请把 32 位 XEDParse.dll 放到程序同目录后重试。\n");
		MessageBoxA(NULL, "缺少 XEDParse.dll（32 位）。\n请把 32 位 XEDParse.dll 放到程序同目录后重试。", "调试器启动失败", MB_ICONERROR);
		return -1;
	}
#endif
	debugger debug;
	Traversal_process Processid;
	int choice = 0;
	printf("1.打开程序，2.附加程序");
	scanf_s("%d", &choice);
	if (choice == 1)
	{
		char szPath[MAX_PATH] = "111.exe";
		char szInput[MAX_PATH] = { 0 };
		int ch;
		//吃掉 scanf 残留的换行，避免下面的 gets_s 读到空行
		while ((ch = getchar()) != '\n' && ch != EOF) {}
		printf("请输入要打开的程序路径（直接回车默认 111.exe）：");
		gets_s(szInput, MAX_PATH);
		//只有输入非空时才覆盖默认路径，回车保持默认值
		if (szInput[0] != '\0')
			strcpy_s(szPath, MAX_PATH, szInput);
		if (!debug.open(szPath))
			return -1;
		//nPlugin.LoadDll(debug.debugEvent.dwProcessId);
		debug.run();
	}
	else if (choice == 2)
	{
		DWORD Pid = Processid.SelectProcess();
		if (Pid != 0 && debug.Open(Pid) != 0)
		{
			debug.run();
		}
		else
		{
			printf("调试器不能附加到活动程序\n");
		}
	}

	return 0;
}
