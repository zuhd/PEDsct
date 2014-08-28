// PEInfoDlg.cpp : implementation file
//

#include "stdafx.h"
#include "PEDsct.h"
#include "PEInfoDlg.h"
#include "PEDsctDlg.h"


// CPEInfoDlg dialog

IMPLEMENT_DYNAMIC(CPEInfoDlg, CDialog)
CPEInfoDlg::CPEInfoDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPEInfoDlg::IDD, pParent)
{
}

CPEInfoDlg::~CPEInfoDlg()
{
}

void CPEInfoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CPEInfoDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON_DIR, OnBnClickedButtonDir)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_DIRDATA, OnNMDblclkDirDataListServer)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_IDESC, OnNMDblclkITListServer)
END_MESSAGE_MAP()


void CPEInfoDlg::HideAllControl()
{
	GetDlgItem(IDC_EDIT_INFO)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_LIST_DIRDATA)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_LIST_IDESC)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_LIST_ITHUNK)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_LIST_EDIR)->ShowWindow(SW_HIDE);
	GetDlgItem(IDC_LIST_ST)->ShowWindow(SW_HIDE);
}
// CPEInfoDlg message handlers

void CPEInfoDlg::OnBnClickedButtonDir()
{
	HideAllControl();
	GetDlgItem(IDC_LIST_DIRDATA)->ShowWindow(SW_SHOW);
	g_pPEDsctDlg->ShowDirectoryInfo();
	// TODO: Add your control notification handler code here
}

void CPEInfoDlg::OnNMDblclkDirDataListServer(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: Add your control notification handler code here
	*pResult = 0;
	int nSelect = -1;
	CListCtrl* pList = static_cast<CListCtrl*>(GetDlgItem(IDC_LIST_DIRDATA));
	nSelect = pList->GetNextItem(nSelect, LVNI_ALL | LVNI_SELECTED);
	switch(nSelect)
	{
	case 0:
		{
			HideAllControl();
			GetDlgItem(IDC_EDIT_INFO)->ShowWindow(SW_SHOW);
			GetDlgItem(IDC_LIST_EDIR)->ShowWindow(SW_SHOW);
			g_pPEDsctDlg->ShowExportTable();
		}
		break;
	case 1:
		{
			HideAllControl();
			GetDlgItem(IDC_LIST_IDESC)->ShowWindow(SW_SHOW);
			GetDlgItem(IDC_LIST_ITHUNK)->ShowWindow(SW_SHOW);
			g_pPEDsctDlg->ShowImportTable();
		}
		break;
	case 2:
		break;
	}	
}

void CPEInfoDlg::OnNMDblclkITListServer(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: Add your control notification handler code here
	*pResult = 0;
	int nSelect = -1;
	CListCtrl* pList = static_cast<CListCtrl*>(GetDlgItem(IDC_LIST_IDESC));
	nSelect = pList->GetNextItem(nSelect, LVNI_ALL | LVNI_SELECTED);
	if (nSelect >= 0)
	{
		PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)(pList->GetItemData(nSelect));
		if (pID != NULL)
		{
			g_pPEDsctDlg->ShowThunkData(pID);
		}
	}	
}
