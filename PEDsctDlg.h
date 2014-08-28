// PEDsctDlg.h : 头文件
//

#pragma once
#include "PEInfoDlg.h"


// CPEDsctDlg 对话框
class CPEDsctDlg : public CDialog
{
// 构造
public:
	CPEDsctDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_PEDSCT_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

public:
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: 判断是否是PE文件
	 */
	BOOL IsPEFile(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: 获取PE文件DOS头
	 */
	PIMAGE_DOS_HEADER GetDosHeader(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: 获取NT文件头
	 */
	PIMAGE_NT_HEADERS GetNtHeader(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: 获取NT文件头中的 PE文件头结构
	 */
	PIMAGE_FILE_HEADER GetFileHeader(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: 获取NT文件头中的 可选文件头结构
	 */
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	DWORD GetPhysicalAddress(DWORD dwRVA);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: 打印DOS文件头
	 */
	void ShowDosHeaderInfo();
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowFileHeaderInfo();
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowOptionHeaderInfo();	
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowDirectoryInfo();
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowSectionTable();
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowImportTable();
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowThunkData(PIMAGE_IMPORT_DESCRIPTOR pID);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowExportTable();
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: NULL
	 */
	void ShowRelocTable();
private:
	CPEInfoDlg m_DlgPEInfo;		// PE信息对话框
	LPVOID m_pMappingMemory;	// PE内存映射
	CString m_strFilePath;		// PE文件路径
	CString m_strFileName;		// PE文件名称

// 实现
protected:
	HICON m_hIcon;
	CMenu m_cMenu;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnOpenFile();
	afx_msg void OnCloseFile();
};
