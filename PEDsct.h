// PEDsct.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error �ڰ������� PCH �Ĵ��ļ�֮ǰ������stdafx.h��
#endif

#include "resource.h"		// ������


// CPEDsctApp:
// �йش����ʵ�֣������ PEDsct.cpp
//

class CPEDsctApp : public CWinApp
{
public:
	CPEDsctApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CPEDsctApp theApp;
