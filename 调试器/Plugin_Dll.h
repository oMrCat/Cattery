#pragma once
#include<windows.h>
#include<atlstr.h>
#include<locale.h>
#include<vector>
#include<string>
#define PATH  L"C:\\Users\\MrCat\\source\\repos\\调试器项目\\plugin"
using std::vector;
using std::string;
class Plugin_Dll
{
public:
	//遍历文件名
	static void EnumFile();
	//加载动态链接库
	static void LoadDll(int dwPid);
	//获取后缀名
	static char* FileNameLast(const char* path);
};

