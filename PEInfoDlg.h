#pragma once


// CPEInfoDlg dialog

class CPEInfoDlg : public CDialog
{
	DECLARE_DYNAMIC(CPEInfoDlg)

public:
	CPEInfoDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CPEInfoDlg();

	void HideAllControl();

// Dialog Data
	enum { IDD = IDD_INFO_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	afx_msg void OnNMDblclkDirDataListServer(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMDblclkITListServer(NMHDR *pNMHDR, LRESULT *pResult);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonDir();
};
