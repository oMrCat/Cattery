#include "Plugin_Dll.h"
vector<CString>FileName;

void Plugin_Dll::EnumFile()
{
	//vector<CString>& filenames
	CString fn;
	WIN32_FIND_DATA  wfd = {};
	setlocale(LC_ALL, "CHS"); // 设置字符编码格式
	//找到第一个文件
	TCHAR szDirtoryPath[MAX_PATH] = { 0 };
	_stprintf_s(szDirtoryPath, _T("%s\\%s"), PATH, _T("*"));
	HANDLE hFindFile = FindFirstFile(szDirtoryPath, &wfd);
	if (hFindFile != INVALID_HANDLE_VALUE) 
	{
		do {
			fn.Format(L"%s", wfd.cFileName);
			FileName.push_back(fn);
		} while (FindNextFile(hFindFile, &wfd));
	}
}

void Plugin_Dll::LoadDll(int dwPid)
{
	typedef int (*FUN)(int dwPid);
	FUN g_pFun = nullptr;
	EnumFile();
	char* str;
	char* str_last;
	CString nPath;
	CString n;
	n.Format(L"\\");
	USES_CONVERSION;
	for (size_t i = 0; i < FileName.size(); i++)
	{
		str = W2A(FileName[i]);
		if (strcmp(str, ".") == 0 || strcmp(str, "..") == 0)
		{
			continue;
		}
		nPath.Format(L"%s", PATH + n + FileName[i]);
		str = W2A(nPath);
		str_last=FileNameLast(str);
		if (strcmp(str_last,"dll")==0)
		{
			//1. 载入dll文件 得到模块句柄
			HMODULE nhModule = LoadLibrary(nPath);
			//2. 搜索dll中的函数
			g_pFun = (FUN)GetProcAddress(nhModule, "Fun");
			//3. 调用它
			g_pFun(dwPid);
			//4. 释放dll
			FreeLibrary(nhModule);

		}
	}
}

char* Plugin_Dll::FileNameLast(const char* path)
{
	// 返回值要交给调用方使用，缓冲区必须是静态存储期，不能返回局部变量地址
	static char filenameLast[100] = { 0 };
	char* tmp = nullptr;
	tmp = (char*)strrchr(path, '.');
	if (tmp == NULL)
	{
		return 0;
	}
	strcpy_s(filenameLast, tmp + 1);//filenameLast就是后缀
	return filenameLast;
}
