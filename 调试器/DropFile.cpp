// DropFile.cpp: 实现文件
//

#include "pch.h"
#include "DropFile.h"
#include "afxdialogex.h"


// DropFile 对话框

IMPLEMENT_DYNAMIC(DropFile, CDialogEx)

DropFile::DropFile(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

DropFile::~DropFile()
{
}

void DropFile::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(DropFile, CDialogEx)
END_MESSAGE_MAP()


// DropFile 消息处理程序
