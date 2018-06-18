
// PeProtectDlg.h : 头文件
//

#pragma once
#include "afxeditbrowsectrl.h"

typedef bool(*Pack)(PCHAR pPath);

// CPeProtectDlg 对话框
class CPeProtectDlg : public CDialogEx
{
// 构造
public:
	CPeProtectDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PEPROTECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CMFCEditBrowseCtrl m_MfcEditBrowse;
	CString m_Browse_FilePath;
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnBnClickedButtonPack();


private:
	HMODULE m_hModule;
	Pack	m_PackFunc;
public:
	// 压缩
	BOOL m_bIsCompression;
	BOOL m_bIsEncryption;
};
