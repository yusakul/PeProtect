
// PeProtectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "PeProtect.h"
#include "PeProtectDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CPeProtectDlg 对话框



CPeProtectDlg::CPeProtectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_PEPROTECT_DIALOG, pParent)
	, m_Browse_FilePath(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPeProtectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, m_MfcEditBrowse);
	DDX_Text(pDX, IDC_MFCEDITBROWSE1, m_Browse_FilePath);
}

BEGIN_MESSAGE_MAP(CPeProtectDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON_PACK, &CPeProtectDlg::OnBnClickedButtonPack)
END_MESSAGE_MAP()


// CPeProtectDlg 消息处理程序

BOOL CPeProtectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	//调用ChangeWindowMessageFilter函数，放行WM_DROPFILES消息和WM_COPYGLOBALDATA消息，以解决Win7系统中文件拖放失效的问题
	DragAcceptFiles(TRUE);
	ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
	ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);       // 0x0049 == WM_COPYGLOBALDATA

	if (!(m_hModule = LoadLibraryA("..\\Debug\\Pack.dll")))
	{
		MessageBox(L"加载Pack.dll失败");
		TerminateProcess(NULL, 0);
	}
	else
	{
		m_PackFunc = (Pack)GetProcAddress(m_hModule, "Pack");
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPeProtectDlg::OnPaint()
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
HCURSOR CPeProtectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CPeProtectDlg::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	CDialogEx::OnDropFiles(hDropInfo);

	//拖动单个文件的时候
	TCHAR szPath[MAX_PATH] = {};
	//获取拖拽文件的路径
	DragQueryFile(hDropInfo, 0, szPath, MAX_PATH);
	m_Browse_FilePath = szPath;
	//将路径添加到文件框中
	m_MfcEditBrowse.SetWindowText(m_Browse_FilePath);
	//UpdateData(FALSE);
	//拖放结束后，释放内存
	DragFinish(hDropInfo);
	UpdateData(TRUE);
	//MessageBox(m_Browse_FilePath, L"Tip", 0);
}


void CPeProtectDlg::OnBnClickedButtonPack()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(true);
	m_bIsCompression = 0;				//是否压缩
	m_bIsEncryption = 0;				//是否加密
	
	char *szPath = new char[255];
	WideCharToMultiByte(CP_ACP, 0, m_Browse_FilePath.GetBuffer(), -1, szPath, 255, NULL, FALSE);

	UpdateData(TRUE);

	if (m_PackFunc(szPath))
	{
		MessageBox(L"完成...\n", L"Tip", NULL);
	}
	delete[] szPath;
}
