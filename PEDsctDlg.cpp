// PEDsctDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "PEDsct.h"
#include "PEDsctDlg.h"
#include ".\pedsctdlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CPEDsctDlg* g_pPEDsctDlg = NULL;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CPEDsctDlg 对话框



CPEDsctDlg::CPEDsctDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPEDsctDlg::IDD, pParent),m_pMappingMemory(NULL)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPEDsctDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CPEDsctDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_WM_LBUTTONDOWN()	
	ON_COMMAND(ID_OPEN_FILE, OnOpenFile)
	ON_COMMAND(ID_CLOSE_FILE, OnCloseFile)
END_MESSAGE_MAP()


// CPEDsctDlg 消息处理程序

BOOL CPEDsctDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将\“关于...\”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码	
	m_DlgPEInfo.Create(IDD_INFO_DIALOG, this);		
	m_DlgPEInfo.GetDlgItem(IDC_BUTTON_DIR)->ShowWindow(SW_HIDE);
	CListCtrl* pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_ST));
	pList->MoveWindow(15,15,255,260);
	pList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	pList->InsertColumn(0, _T("Name"), LVCFMT_CENTER, 40);
	pList->InsertColumn(1, _T("VOffset"), LVCFMT_CENTER, 40);
	pList->InsertColumn(2, _T("VSize"), LVCFMT_CENTER, 40);
	pList->InsertColumn(3, _T("ROffset"), LVCFMT_CENTER, 40);
	pList->InsertColumn(4, _T("RSize"), LVCFMT_CENTER, 40);
	pList->InsertColumn(5, _T("Flags"), LVCFMT_CENTER, 40);	
	pList->ShowWindow(SW_HIDE);

	pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_DIRDATA));
	pList->MoveWindow(15,15,255,260);
	pList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	pList->InsertColumn(0, _T("Name"), LVCFMT_CENTER, 40);
	pList->InsertColumn(1, _T("RVA"), LVCFMT_CENTER, 80);
	pList->InsertColumn(2, _T("Size"), LVCFMT_CENTER, 80);
	pList->ShowWindow(SW_HIDE);

	pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_IDESC));
	pList->MoveWindow(15,15,255,130);
	pList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	pList->InsertColumn(0, _T("DllName"), LVCFMT_CENTER, 40);
	pList->InsertColumn(1, _T("OFThunk"), LVCFMT_CENTER, 40);
	pList->InsertColumn(2, _T("TimeDateStamp"), LVCFMT_CENTER, 40);
	pList->InsertColumn(3, _T("ForwaderChain"), LVCFMT_CENTER, 40);
	pList->InsertColumn(4, _T("Name"), LVCFMT_CENTER, 40);
	pList->InsertColumn(5, _T("FirstThunk"), LVCFMT_CENTER, 40);	
	pList->ShowWindow(SW_HIDE);

	pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_ITHUNK));
	pList->MoveWindow(15,145,255,130);
	pList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	pList->InsertColumn(0, _T("ThunkRVA"), LVCFMT_CENTER, 80);	
	pList->InsertColumn(1, _T("Hint"), LVCFMT_CENTER, 80);
	pList->InsertColumn(2, _T("APIName"), LVCFMT_CENTER, 80);
	pList->ShowWindow(SW_HIDE);

	pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_EDIR));
	pList->MoveWindow(15,145,255,130);
	pList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	pList->InsertColumn(0, _T("Ordinal"), LVCFMT_CENTER, 80);
	pList->InsertColumn(1, _T("RVA"), LVCFMT_CENTER, 80);
	pList->InsertColumn(2, _T("Name"), LVCFMT_CENTER, 80);
	pList->ShowWindow(SW_HIDE);
	g_pPEDsctDlg = this;

	return TRUE;  // 除非设置了控件的焦点，否则返回 TRUE
}

void CPEDsctDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CPEDsctDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作矩形中居中
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
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标显示。
HCURSOR CPEDsctDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL CPEDsctDlg::IsPEFile(LPVOID pImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (pImageBase == NULL)
	{
		return FALSE;
	}

	pDH = (PIMAGE_DOS_HEADER)pImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;          
}

PIMAGE_DOS_HEADER CPEDsctDlg::GetDosHeader(LPVOID pImageBase)
{
	return (PIMAGE_DOS_HEADER)pImageBase;
}

PIMAGE_NT_HEADERS CPEDsctDlg::GetNtHeader(LPVOID pImageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	if (pImageBase == NULL)
	{
		return FALSE;
	}

	pDH = (PIMAGE_DOS_HEADER)pImageBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	return pNtH;
}

PIMAGE_FILE_HEADER CPEDsctDlg::GetFileHeader(LPVOID pImageBase)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pImageBase);
	if (pNtHeader != NULL)
	{
		return &pNtHeader->FileHeader;
	}
	return NULL;
}

PIMAGE_OPTIONAL_HEADER CPEDsctDlg::GetOptionalHeader(LPVOID pImageBase)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pImageBase);
	if (pNtHeader != NULL)
	{
		return &pNtHeader->OptionalHeader;
	}
	return NULL;
}

DWORD CPEDsctDlg::GetPhysicalAddress(DWORD dwRVA)
{
	if (dwRVA == 0)
	{
		return dwRVA;
	}
	
	PIMAGE_FILE_HEADER pFH = GetFileHeader(m_pMappingMemory);
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(m_pMappingMemory);
	if (pFH == NULL ||
		pOH == NULL)
	{
		AfxMessageBox("映射地址失败！");
		return 0;
	}

	// Section Table紧跟在OptionHeader之后
	PIMAGE_SECTION_HEADER pSH = (PIMAGE_SECTION_HEADER)((DWORD)pOH + (DWORD)pFH->SizeOfOptionalHeader);
	if (pSH != NULL)
	{
		// 获取区块的数量
		WORD wNumberOfSecion = pFH->NumberOfSections;
		for (WORD i = 0; i < wNumberOfSecion; i++)
		{
			if (dwRVA >= pSH[i].VirtualAddress &&
				dwRVA <= (pSH[i].VirtualAddress + pSH[i].Misc.VirtualSize))
			{
				return (pSH[i].PointerToRawData + dwRVA - pSH[i].VirtualAddress);
			}			
		}
	}
	return 0;
}

void CPEDsctDlg::ShowDosHeaderInfo()
{
	m_DlgPEInfo.GetDlgItem(IDC_BUTTON_DIR)->ShowWindow(SW_HIDE);
	char szBuffer[1024] = {0};
	PIMAGE_DOS_HEADER pDH = GetDosHeader(m_pMappingMemory);
	if (pDH != NULL)
	{
		sprintf(szBuffer,
			"----------------------------------------------------\r\n"
			"e_magic:     0x%04lX\r\n"
			"ne_cblp:     0x%04lX\r\n"
			"e_cp:        0x%04lX\r\n"
			"e_crlc:      0x%04lX\r\n"
			"e_cparhdr:   0x%04lX\r\n"
			"e_minalloc:  0x%04lX\r\n"
			"e_maxalloc:  0x%04lX\r\n"
			"e_ss:        0x%04lX\r\n"
			"e_sp:        0x%04lX\r\n"
			"e_csum:      0x%04lX\r\n"
			"e_ip:        0x%04lX\r\n"
			"e_cs:        0x%04lX\r\n"
			"e_lfarlc:    0x%04lX\r\n"
			"e_ovno:      0x%04lX\r\n"
			"e_res:       0x%04lX\r\n"
			"e_oemid:     0x%04lX\r\n"
			"e_oeminfo:   0x%04lX\r\n"
			"e_res2:      0x%04lX\r\n"
			"e_lfanew:    0x%04lX\r\n",
			pDH->e_magic,
			pDH->e_cblp,
			pDH->e_cp,
			pDH->e_crlc,
			pDH->e_cparhdr,
			pDH->e_minalloc,
			pDH->e_maxalloc,
			pDH->e_ss,
			pDH->e_sp,
			pDH->e_csum,
			pDH->e_ip,
			pDH->e_cs,
			pDH->e_lfarlc,
			pDH->e_ovno,
			pDH->e_res,
			pDH->e_oemid,
			pDH->e_oeminfo,
			pDH->e_res2,
			pDH->e_lfanew);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->SetWindowText(szBuffer);
	}
}

void CPEDsctDlg::ShowFileHeaderInfo()
{
	m_DlgPEInfo.GetDlgItem(IDC_BUTTON_DIR)->ShowWindow(SW_HIDE);
	char szBuffer[1024] = {0};
	PIMAGE_FILE_HEADER pFH = GetFileHeader(m_pMappingMemory);
	if (pFH != NULL)
	{
		sprintf(szBuffer, 
			"------------------------------------------\r\n"
			"Machine:              0x%04lX\r\n"
			"NumberOfSections:     0x%04lX\r\n"
			"TimeDateStamp:        0x%04lX\r\n"
			"PointerToSymbolTable: 0x%04lX\r\n"
			"NumberOfSymbols:      0x%04lX\r\n"
			"SizeOfOptionalHeader: 0x%04lX\r\n"
			"Characteristics:      0x%04lX\r\n",
			pFH->Machine,
			pFH->NumberOfSections,
			pFH->TimeDateStamp,
			pFH->PointerToSymbolTable,
			pFH->NumberOfSymbols,
			pFH->SizeOfOptionalHeader,
			pFH->Characteristics);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->SetWindowText(szBuffer);
	}

}

void CPEDsctDlg::ShowOptionHeaderInfo()
{
	m_DlgPEInfo.GetDlgItem(IDC_BUTTON_DIR)->ShowWindow(SW_SHOW);
	char szBuffer[2048] = {0};
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(m_pMappingMemory);
	if (pOH != NULL)
	{
		sprintf(szBuffer, 
			"------------------------------------------\r\n"
			"Magic:                   0x%04lX\r\n"
			"MajorLinkerVersion:      0x%04lX\r\n"
			"MinorLinkerVersion:      0x%04lX\r\n"
			"SizeOfCode:              0x%04lX\r\n"
			"SizeOfInitializedData:   0x%04lX\r\n"
			"SizeOfUninitializedData: 0x%04lX\r\n"
			"AddressOfEntryPoint:     0x%04lX\r\n"
			"BaseOfCode:              0x%04lX\r\n"
			"BaseOfData:              0x%04lX\r\n"
			"ImageBase:               0x%04lX\r\n"
			"SectionAlignment:        0x%04lX\r\n"
			"FileAlignment:           0x%04lX\r\n"
			"MajorOSVersion:          0x%04lX\r\n"
			"MinorOSVersion:          0x%04lX\r\n"
			"MajorImageVersion:       0x%04lX\r\n"
			"MinorImageVersion:       0x%04lX\r\n"
			"MajorSubsystemVersion:   0x%04lX\r\n"
			"MinorSubsystemVersion:   0x%04lX\r\n"
			"Win32VersionValue:       0x%04lX\r\n"
			"SizeOfImage:             0x%04lX\r\n"
			"SizeOfHeaders:           0x%04lX\r\n"
			"Checksum:                0x%04lX\r\n"
			"Subsystem:               0x%04lX\r\n"
			"DllCharacteristics:      0x%04lX\r\n"
			"SizeOfStackReserve:      0x%04lX\r\n"
			"SizeOfStackCommit:       0x%04lX\r\n"
			"SizeOfHeapReserve:       0x%04lX\r\n"
			"SizeOfHeapCommit:        0x%04lX\r\n"
			"LoaderFlags:             0x%04lX\r\n"
			"NumberOfRvaAndSizes:     0x%04lX\r\n",
			pOH->Magic,
			pOH->MajorLinkerVersion,
			pOH->MinorLinkerVersion,
			pOH->SizeOfCode,
			pOH->SizeOfInitializedData,
			pOH->SizeOfUninitializedData,
			pOH->AddressOfEntryPoint,
			pOH->BaseOfCode,
			pOH->BaseOfData,
			pOH->ImageBase,
			pOH->SectionAlignment,
			pOH->FileAlignment,
			pOH->MajorOperatingSystemVersion,
			pOH->MinorOperatingSystemVersion,
			pOH->MajorImageVersion,
			pOH->MinorImageVersion,
			pOH->MajorSubsystemVersion,
			pOH->MinorSubsystemVersion,
			pOH->Win32VersionValue,
			pOH->SizeOfImage,
			pOH->SizeOfHeaders,
			pOH->CheckSum,
			pOH->Subsystem,
			pOH->DllCharacteristics,
			pOH->SizeOfStackReserve,
			pOH->SizeOfStackCommit,
			pOH->SizeOfHeapReserve,
			pOH->SizeOfHeapCommit,
			pOH->LoaderFlags,
			pOH->NumberOfRvaAndSizes
			);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->SetWindowText(szBuffer);
	}
}

void CPEDsctDlg::ShowDirectoryInfo()
{
	char szBuffer[256] = {0};
	CString strName[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
			_T("ExportTable: "),
			_T("ImportTable: "),
			_T("Resource:    "),
			_T("Exception:   "),
			_T("Security:    "),
			_T("Relocation:  "),
			_T("Debug:       "),
			_T("Copyright:   "),
			_T("Globalptr:   "),
			_T("TlsTable:    "),
			_T("LoadConfig:  "),
			_T("BoundImport: "),
			_T("IAT:         "),
			_T("DelayImport: "),
			_T("COM:         "),
			_T("Reserved:    ")
	};
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(m_pMappingMemory);
	if (pOH != NULL)
	{
		CListCtrl* pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_DIRDATA));
		pList->DeleteAllItems();
		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			CString str;
			pList->InsertItem(i, NULL);
			pList->SetItemText(i, 0, strName[i]);		
			str.Format("0x%08lX", pOH->DataDirectory[i].VirtualAddress);
			pList->SetItemText(i, 1, str);
			str.Format("0x%08lX", pOH->DataDirectory[i].Size);
			pList->SetItemText(i, 2, str);			
			pList->SetItemData(i, (DWORD_PTR)&pOH->DataDirectory[i]);
			pList->SetRedraw();
		}
	}	
}

void CPEDsctDlg::ShowSectionTable()
{
	PIMAGE_FILE_HEADER pFH = GetFileHeader(m_pMappingMemory);
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(m_pMappingMemory);
	if (pFH == NULL ||
		pOH == NULL)
	{
		AfxMessageBox("映射地址失败！");
		return;
	}

	// Section Table紧跟在OptionHeader之后
	PIMAGE_SECTION_HEADER pSH = (PIMAGE_SECTION_HEADER)((DWORD)pOH + (DWORD)pFH->SizeOfOptionalHeader);
	if (pSH != NULL)
	{
		// 获取区块的数量
		WORD wNumberOfSecion = pFH->NumberOfSections;
		CListCtrl* pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_ST));
		pList->DeleteAllItems();
		for (WORD i = 0; i < wNumberOfSecion; i++)
		{
			CString str;
			pList->InsertItem(i, NULL);
			str = pSH[i].Name;
			pList->SetItemText(i, 0, str);
			str.Format("0x%04lX", pSH[i].VirtualAddress);
			pList->SetItemText(i, 1, str);
			str.Format("0x%04lX", pSH[i].Misc.VirtualSize);
			pList->SetItemText(i, 2, str);
			str.Format("0x%04lX", pSH[i].PointerToRawData);
			pList->SetItemText(i, 3, str);
			str.Format("0x%04lX", pSH[i].SizeOfRawData);
			pList->SetItemText(i, 4, str);
			str.Format("0x%04lX", pSH[i].Characteristics);
			pList->SetItemText(i, 5, str);
			pList->SetItemData(i, (DWORD_PTR)&pSH[i]);
			pList->SetRedraw();
		}
	}
}

void CPEDsctDlg::ShowImportTable()
{
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(m_pMappingMemory);
	if (pOH == NULL)
	{
		AfxMessageBox("映射地址失败！");
		return;
	}

	DWORD dwRVA = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD dwRawA = GetPhysicalAddress(dwRVA);
	if (dwRawA == 0)
	{
		AfxMessageBox("获取物理地址失败！");
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)m_pMappingMemory + dwRawA);
	CListCtrl* pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_IDESC));
	pList->DeleteAllItems();
	CListCtrl* pListTK = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_ITHUNK));
	pListTK->DeleteAllItems();
	// PID是一个连续的数组 最后一个数组所有元素值为0
	DWORD dwIndex = 0;
	while (pID[dwIndex].Name != NULL)
	{
		CString str;
		DWORD dwNameRawA = GetPhysicalAddress(pID[dwIndex].Name);
		DWORD dwOFThunkRawA = GetPhysicalAddress(pID[dwIndex].OriginalFirstThunk);
		DWORD dwFirstThunkRawA = GetPhysicalAddress(pID[dwIndex].FirstThunk);
		DWORD dwTimeDateStamp = pID[dwIndex].TimeDateStamp;
		DWORD dwForwarderChain = pID[dwIndex].ForwarderChain;
		pList->InsertItem(dwIndex, NULL);
		str = (LPCTSTR)((DWORD)m_pMappingMemory + dwNameRawA);
		pList->SetItemText(dwIndex, 0, str);
		str.Format("0x%04lX", dwOFThunkRawA);
		pList->SetItemText(dwIndex, 1, str);
		str.Format("0x%04lX", dwTimeDateStamp);
		pList->SetItemText(dwIndex, 2, str);
		str.Format("0x%04lX", dwForwarderChain);
		pList->SetItemText(dwIndex, 3, str);
		str.Format("0x%04lX", dwNameRawA);
		pList->SetItemText(dwIndex, 4, str);
		str.Format("0x%04lX", dwFirstThunkRawA);
		pList->SetItemText(dwIndex, 5, str);
		pList->SetItemData(dwIndex, (DWORD_PTR)&pID[dwIndex]);
		pList->SetRedraw();				
		dwIndex++;
	}
}

void CPEDsctDlg::ShowThunkData(PIMAGE_IMPORT_DESCRIPTOR pID)
{
	if (pID == NULL)
	{
		return;
	}
	DWORD dwOFThunkRawA = GetPhysicalAddress(pID->OriginalFirstThunk);
	DWORD dwTD = 0;
	// pTD指向的四个字节的内容为0  而不是pTD的地址为0
	PIMAGE_THUNK_DATA pTD = (PIMAGE_THUNK_DATA)((DWORD)m_pMappingMemory + dwOFThunkRawA);
	DWORD dwThunkData = 0;
	CListCtrl* pListTK = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_ITHUNK));
	pListTK->DeleteAllItems();
	while ((dwThunkData = *(DWORD*)(&pTD[dwTD])) != 0)
	{
		CString str;
		pListTK->InsertItem(dwTD, NULL);			
		str.Format("0x%04lX", dwOFThunkRawA);		
		pListTK->SetItemText(dwTD, 0, str);
		if (dwThunkData & 0x8000000)
		{
			// 根据Hint也能得到函数地址
			DWORD dwHint = dwThunkData & 0x7FFFFFFF;
			str.Format("0x%08lX", dwOFThunkRawA);	
			pListTK->SetItemText(dwTD, 1, str);
			str = _T("--");
			pListTK->SetItemText(dwTD, 2, str);
		}
		else
		{
			DWORD dwRawAddr = GetPhysicalAddress(dwThunkData & 0x7FFFFFFF);
			PIMAGE_IMPORT_BY_NAME pIN = (PIMAGE_IMPORT_BY_NAME)((DWORD)m_pMappingMemory + dwRawAddr);
			if (pIN != NULL)
			{
				WORD wHint = pIN->Hint;
				char* szName = (char*)pIN->Name;
				str.Format("0x%04lX", wHint);
				pListTK->SetItemText(dwTD, 1, str);
				str = szName;
				pListTK->SetItemText(dwTD, 2, str);
			}
		}
		pListTK->SetItemData(dwTD, (DWORD_PTR)&pTD[dwTD]);
		pListTK->SetRedraw();	
		dwTD++;
	}

}

void CPEDsctDlg::ShowExportTable()
{
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(m_pMappingMemory);
	if (pOH == NULL)
	{
		AfxMessageBox("映射地址失败！");
		return;
	}

	DWORD dwRVA = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD dwRawA = GetPhysicalAddress(dwRVA);
	if (dwRawA == 0)
	{
		AfxMessageBox("输出表为空！");
		return;
	}
	PIMAGE_EXPORT_DIRECTORY pED = (PIMAGE_EXPORT_DIRECTORY)((DWORD)m_pMappingMemory + dwRawA);
	m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->MoveWindow(15,15,255,130);
	if (pED != NULL)
	{
		char szBuffer[1024] = {0};
		DWORD dwRawName = GetPhysicalAddress(pED->Name);
		DWORD dwRawAOF = GetPhysicalAddress(pED->AddressOfFunctions);
		DWORD dwRawAON = GetPhysicalAddress(pED->AddressOfNames);
		DWORD dwRawAOO = GetPhysicalAddress(pED->AddressOfNameOrdinals);
		LPCTSTR pName = (LPCTSTR)((DWORD)m_pMappingMemory + dwRawName);
		sprintf(szBuffer, 
			"------------------------------------------\r\n"			
			"TimeDateStamp:        0x%08lX\r\n"
			"Name:                 %s\r\n"
			"Base:                 0x%08lX\r\n"
			"NumberOfFunctions:    0x%08lX\r\n"
			"NumberOfNames:        0x%08lX\r\n"
			"AddressOfFunctions:   0x%08lX\r\n"
			"AddressOfNames:       0x%08lX\r\n"
			"AddressOfOrdinals:    0x%08lX\r\n",
			pED->TimeDateStamp,
			pName,
			pED->Base,
			pED->NumberOfFunctions,
			pED->NumberOfNames,
			pED->AddressOfFunctions,
			pED->AddressOfNames,
			pED->AddressOfNameOrdinals
			);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->SetWindowText(szBuffer);
		CListCtrl* pList = static_cast<CListCtrl*>(m_DlgPEInfo.GetDlgItem(IDC_LIST_EDIR));
		pList->DeleteAllItems();
		for (int i = 0; i < pED->NumberOfNames; i++)
		{
			CString str;
			pList->InsertItem(i, NULL);
			WORD* pOrdinals = (WORD*)((DWORD)m_pMappingMemory + dwRawAOO);
			WORD wOrdinals = pOrdinals[i];
			str.Format("0x%04lX", wOrdinals);
			pList->SetItemText(i, 0, str);
			DWORD* pRVA = (DWORD*)((DWORD)m_pMappingMemory + dwRawAOF);
			DWORD dwRVA = pRVA[wOrdinals];
			str.Format("0x%08lX", dwRVA);
			pList->SetItemText(i, 1, str);
			DWORD* pName = (DWORD*)((DWORD)m_pMappingMemory + dwRawAON);
			DWORD dwRawFunName = GetPhysicalAddress(pName[i]);			
			pList->SetItemText(i, 2, (LPCTSTR)((DWORD)m_pMappingMemory + dwRawFunName));			
			pList->SetItemData(i, NULL);
			pList->SetRedraw();				
		}
	}
}

void CPEDsctDlg::ShowRelocTable()
{
	PIMAGE_OPTIONAL_HEADER pOH = GetOptionalHeader(m_pMappingMemory);
	if (pOH == NULL)
	{
		AfxMessageBox("映射地址失败！");
		return;
	}

	DWORD dwRVA = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD dwRelocSize = pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD dwRawA = GetPhysicalAddress(dwRVA);
	if (dwRawA == 0)
	{
		AfxMessageBox("获取重定位地址失败！");
		return;
	}
	PIMAGE_BASE_RELOCATION pBR = (PIMAGE_BASE_RELOCATION)((DWORD)m_pMappingMemory + dwRawA);
	if (pBR != NULL)
	{
		DWORD dwSize = 0;
		while (dwSize <= dwRelocSize)
		{
			DWORD dwRelocRVA = pBR->VirtualAddress;
			DWORD dwRelocSize = pBR->SizeOfBlock;
			DWORD dwTypeOffsetNum = (dwRelocSize - 8) / 2;
			for (int i = 0; i < dwTypeOffsetNum; i++)
			{
				WORD* pTypeOffset = (WORD*)((DWORD)pBR + 8);
				WORD wTypeOffset = pTypeOffset[i];
				WORD wRelocType = wTypeOffset >> 12;
				WORD wAddress = wTypeOffset & 0x0FFF;
			}
			dwSize += dwRelocSize;
			pBR = (PIMAGE_BASE_RELOCATION)((DWORD)pBR + dwSize);
		}
	}
}

void CPEDsctDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	// TODO: Add your message handler code here and/or call default
	CPoint pt = point;
	ClientToScreen(&pt);
	CRect crt;
	GetWindowRect(crt);	
	m_DlgPEInfo.MoveWindow(crt.right, crt.top+50, 280, 345);
	
	GetDlgItem(IDC_STATIC_IDH)->GetClientRect(&crt);
	GetDlgItem(IDC_STATIC_IDH)->ClientToScreen(&crt);	
	
	if (crt.PtInRect(pt))
	{			
		m_DlgPEInfo.ShowWindow(SW_SHOW);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ST)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_IDESC)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ITHUNK)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->ShowWindow(SW_SHOW);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->MoveWindow(15,15,255,260);
		ShowDosHeaderInfo();
	}

	GetDlgItem(IDC_STATIC_IFH)->GetClientRect(&crt);
	GetDlgItem(IDC_STATIC_IFH)->ClientToScreen(&crt);	

	if (crt.PtInRect(pt))
	{		
		m_DlgPEInfo.ShowWindow(SW_SHOW);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ST)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_IDESC)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ITHUNK)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->ShowWindow(SW_SHOW);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->MoveWindow(15,15,255,260);
		ShowFileHeaderInfo();
	}

	GetDlgItem(IDC_STATIC_IOH)->GetClientRect(&crt);
	GetDlgItem(IDC_STATIC_IOH)->ClientToScreen(&crt);	

	if (crt.PtInRect(pt))
	{			
		m_DlgPEInfo.ShowWindow(SW_SHOW);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ST)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_IDESC)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ITHUNK)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->ShowWindow(SW_SHOW);
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->MoveWindow(15,15,255,260);
		ShowOptionHeaderInfo();		
	}

	GetDlgItem(IDC_STATIC_ST)->GetClientRect(&crt);
	GetDlgItem(IDC_STATIC_ST)->ClientToScreen(&crt);	

	if (crt.PtInRect(pt))
	{				
		m_DlgPEInfo.ShowWindow(SW_SHOW);		
		m_DlgPEInfo.GetDlgItem(IDC_EDIT_INFO)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_IDESC)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ITHUNK)->ShowWindow(SW_HIDE);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ST)->ShowWindow(SW_SHOW);
		m_DlgPEInfo.GetDlgItem(IDC_LIST_ST)->MoveWindow(15,15,255,260);
		ShowSectionTable();
	}

	GetDlgItem(IDC_STATIC_SEC)->GetClientRect(&crt);
	GetDlgItem(IDC_STATIC_SEC)->ClientToScreen(&crt);	

	if (crt.PtInRect(pt))
	{				
		m_DlgPEInfo.ShowWindow(SW_SHOW);
	}
	CDialog::OnLButtonDown(nFlags, point);
}

void CPEDsctDlg::OnOpenFile()
{
	m_DlgPEInfo.ShowWindow(SW_HIDE);
	CFileDialog cFileDlg(TRUE, NULL, NULL, OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT|OFN_ALLOWMULTISELECT, "All Files (*.*)|*.*||", AfxGetMainWnd());
	if (cFileDlg.DoModal() == IDOK)
	{
		m_strFilePath = cFileDlg.GetPathName();
		m_strFileName = cFileDlg.GetFileName();

		HANDLE hFile = CreateFile(m_strFilePath, GENERIC_READ, 
			FILE_SHARE_READ || FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			AfxMessageBox("未打开目标文件");			
			return;
		}

		HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMap == NULL)
		{
			AfxMessageBox("未产生文件映射表");
			CloseHandle(hFile);
			return;
		}

		m_pMappingMemory = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
		if (m_pMappingMemory == NULL)
		{
			AfxMessageBox("未将映像映射到内存中");
			CloseHandle(hFileMap);
			CloseHandle(hFile);		
			return;
		}		

		if (!IsPEFile(m_pMappingMemory))
		{
			AfxMessageBox("不是PE文件");
			CloseHandle(hFileMap);
			CloseHandle(hFile);	
			return;
		}
		CString str = m_strFileName;
		str += " - PEDsct";
		SetWindowText(str);
		CloseHandle(hFileMap);
		CloseHandle(hFile);	
	}		
}

void CPEDsctDlg::OnCloseFile()
{
	PostQuitMessage(0);
}
