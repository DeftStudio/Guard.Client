
// NewVerifyDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "include/verify.h"
#include "NewVerify.h"
#include "NewVerifyDlg.h"
#include "afxdialogex.h"
#include "include/string.hpp"
#include "include/FileHelp.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CNewVerifyDlg 对话框
std::string inipath;
std::wstring winipath;

CNewVerifyDlg::CNewVerifyDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_NEWVERIFY_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNewVerifyDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CNewVerifyDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CNewVerifyDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CNewVerifyDlg::OnBnClickedCancel)
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CNewVerifyDlg 消息处理程序

BOOL CNewVerifyDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标


	// TODO: 在此添加额外的初始化代码
	inipath = g_filehelp.GetProgramDir() + "\\config.ini";
	winipath = string2wstring(inipath);
	// 检查文件是否存在
	if (!PathFileExists(winipath.c_str())) {
		// 文件不存在，创建并写入默认配置
		WritePrivateProfileString(_T("Config"), _T("Key"), _T(""), winipath.c_str());
	}
	// 读取配置文件内容
	CString key1Value, key2Value;
	TCHAR buffer[256] = { 0 };
	TCHAR buffer2[256] = { 0 };

	// 是否记住了密码
	GetPrivateProfileString(_T("Config"), _T("记住密码"), _T(""), buffer2, 256, winipath.c_str());
	if (wcscmp(buffer2, L"1") == 0)
	{
		CButton* pCheckBox = (CButton*)GetDlgItem(IDC_CHECK2);  // 获取复选框指针
		if (pCheckBox)
			pCheckBox->SetCheck(BST_CHECKED);
		// 读取 Key1
		GetPrivateProfileString(_T("Config"), _T("Key"), _T(""), buffer, 256, winipath.c_str());
		key1Value = buffer;
		if (key1Value.GetLength() > 1)
		{
			GetDlgItem(IDC_EDIT1)->SetWindowText(key1Value);
		}
	}
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CNewVerifyDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CNewVerifyDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CNewVerifyDlg::OnBnClickedOk()
{
	CString str;
	std::string g_Card;
	GetDlgItem(IDC_EDIT1)->GetWindowText(str);
	if (str.GetLength() < 1)
	{
		MessageBox(_T("非法的卡密长度"));
		return;
	}
	std::wstring WCard = str.GetBuffer();
	g_Card = wstring2string(WCard);
	if (!g_Verify.Login(g_Card))
	{
		MessageBox(_T("登录错误"));
		return;
	}
	if (!g_Verify.GetVerify())
	{
		MessageBox(_T("非法的登录"));
		return;
	}
	CButton* pCheckBox = (CButton*)GetDlgItem(IDC_CHECK2);  // 获取复选框指针
	if (pCheckBox) {
		int checkState = pCheckBox->GetCheck();  // 获取复选框状态
		if (checkState == BST_CHECKED) {
			// 检查文件是否存在
			if (PathFileExists(winipath.c_str())) {
				// 文件存在，创建并写入配置
				WritePrivateProfileString(_T("Config"), _T("Key"), WCard.c_str(), winipath.c_str());
			}
		}
		WritePrivateProfileString(_T("Config"), _T("记住密码"), std::to_wstring(checkState).c_str(), winipath.c_str());
	}
	MessageBox(_T("登录成功"));
	return;
}

void CNewVerifyDlg::OnBnClickedCancel()
{
	CString str;
	std::string g_Card;
	GetDlgItem(IDC_EDIT1)->GetWindowText(str);
	if (str.GetLength() < 1)
	{
		MessageBox(_T("非法的卡密长度"));
		return;
	}
	std::wstring WCard = str.GetBuffer();
	g_Card = wstring2string(WCard);
	if (!g_Verify.Stripping_Equipment(g_Card))
	{
		MessageBox(_T("解绑设备失败"));
		return;
	}
	if (!g_Verify.GetVerify())
	{
		MessageBox(_T("非法的登录"));
		return;
	}
	return;
}
BOOL CNewVerifyDlg::DestroyWindow()
{
	exit(0);
}
void CNewVerifyDlg::OnClose()
{
	exit(0);
}