#pragma once

#include "VirusTotal.h"
#include <Windows.h>
#include <MultiExtension.h>
#include <IFileSystemMonitor.h>

MCNSBEGIN

class MCVirusTotal : public IPluginInterface
{
public:
	static bool GetExtensionInfo(DLLExtensionInfo* pInfo);

	//////////////////////////////////////////////////////////////////////////
	// [ Start - MultiCommander Extension API ]
	//////////////////////////////////////////////////////////////////////////
	long PreStartInit(IMultiAppInterface* pAppInterface) override;
	long GetModuleFlags() override;
	BOOL Init(IMultiAppInterface* pAppInterface) override;
	char* Get_ModuleID()  override { return m_GuidString; }
	bool OnNotify(ZHANDLE hFrom, DWORD nNotifyMsg, WPARAM wParam = 0, LPARAM lParam = 0, void* pExtra = NULL) override;
	BOOL OnMessage(long msg, ZHANDLE hView, WPARAM wParam, LPARAM lParam) override;
	BOOL OnCustomCommand(ICustomCommand* pCustomCommand) override;
	BOOL OnClose(bool bShutDown, bool bDoNotAsk) override;
	int       DoImportData(IXData *pXData) override;
	IImportData*  Get_ImportObject() override;
	IExportData*  Get_ExportObject() override;
	//////////////////////////////////////////////////////////////////////////
	// [ End - MultiCommander Extension API ]
	//////////////////////////////////////////////////////////////////////////

private:
	BOOL Cmd_SetApiKey();
	BOOL Cmd_QueryFiles();
	void SetApiKey();
	void MCVirusTotal::QueryFilesAsync(IFileItemCollection *pFileItems);

	static char m_GuidString[34]; // why not const?
	static WORD m_ExtensionID;
	IMultiAppInterface *m_pAppInterface;
	IAppConfig *m_pConfig;
	IFileSystemMonitor *m_pFSMonitor;
	VirusTotal m_VirusTotal{ &m_pAppInterface };
	WCHAR m_ApiKey[65];
};

MCNSEND