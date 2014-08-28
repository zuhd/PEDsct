// PEDsctDlg.h : ͷ�ļ�
//

#pragma once
#include "PEInfoDlg.h"


// CPEDsctDlg �Ի���
class CPEDsctDlg : public CDialog
{
// ����
public:
	CPEDsctDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_PEDSCT_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��

public:
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: �ж��Ƿ���PE�ļ�
	 */
	BOOL IsPEFile(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: ��ȡPE�ļ�DOSͷ
	 */
	PIMAGE_DOS_HEADER GetDosHeader(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: ��ȡNT�ļ�ͷ
	 */
	PIMAGE_NT_HEADERS GetNtHeader(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: ��ȡNT�ļ�ͷ�е� PE�ļ�ͷ�ṹ
	 */
	PIMAGE_FILE_HEADER GetFileHeader(LPVOID pImageBase);
	/*
	 *	@Param: NULL
	 *	@Return: NULL
	 *	@Description: ��ȡNT�ļ�ͷ�е� ��ѡ�ļ�ͷ�ṹ
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
	 *	@Description: ��ӡDOS�ļ�ͷ
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
	CPEInfoDlg m_DlgPEInfo;		// PE��Ϣ�Ի���
	LPVOID m_pMappingMemory;	// PE�ڴ�ӳ��
	CString m_strFilePath;		// PE�ļ�·��
	CString m_strFileName;		// PE�ļ�����

// ʵ��
protected:
	HICON m_hIcon;
	CMenu m_cMenu;

	// ���ɵ���Ϣӳ�亯��
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
