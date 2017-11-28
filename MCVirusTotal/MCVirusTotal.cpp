#include "MCVirusTotal.h"
#include "sha1.hpp"
#include <IFilePropertiesManager.h>
#include <IFileItem.h>
#include <thread>

using namespace MCNS;

#define MCFILEPROP_VIRUSTOTAL 10
#define APPEXT_CMD_SET_APIKEY 30000
#define APPEXT_CMD_QUERY_FILE 30001

char MCVirusTotal::m_GuidString[34] = "02C71CE0F3AD4D15B231D6AF7C81B9AC";
WORD MCVirusTotal::m_ExtensionID = 0;

bool MCVirusTotal::GetExtensionInfo(DLLExtensionInfo * pInfo)
{
	if (pInfo == nullptr)
		return false;

	wcsncpy(pInfo->wsName, L"VirusTotal helper", 100);											 // Name of extension
	wcsncpy(pInfo->wsPublisher, L"espkk", 100);													 // Publishers , Author
	wcsncpy(pInfo->wsURL, L"Homepage here.................................................", 100); // URL to homepage for extension
	wcsncpy(pInfo->wsDesc, L"Description here.............................................", 160); // Short description that will be shown in Extension manager
	wcsncpy(pInfo->wsBaseName, L"MCVirusTotal", 100);												 // Base filename for config and language files
	strncpy(pInfo->strVersion, "1.0.0.0", 10);													 // Version of the extension ( use format "5.3.2.12" )
	strncpy(pInfo->strGuid, m_GuidString, 34);													 // Guid of extension
	pInfo->hIcon = LoadIcon(nullptr, IDI_ASTERISK);

	//pInfo->dwLocalizedName = 0; // TextID for localized name
	//pInfo->dwLocalizedDesc = 0; // TextID for localized description

	// EXT_ Flags
	pInfo->dwFlags = EXT_TYPE_APP |
#ifdef _UNICODE
	EXT_OS_UNICODE;
#else
	EXT_OS_ANSI;
#endif

	pInfo->dwInitOrder = 4000; // Initialization Order. Lower -> Higher. User value for 1500 >
	pInfo->dwInterfaceVersion = MULTI_INTERFACE_VERSION; // What version of MultiCommander Extension Interface this extensions is built for
	return true;
}

long MCVirusTotal::PreStartInit(IMultiAppInterface * pAppInterface)
{
	IFilePropertiesManager *pPropMan = (IFilePropertiesManager *)pAppInterface->QueryInterface(ZOBJ_PROPMANGER, 0);

	if (!pPropMan)
		return 0;

	pPropMan->Init(m_GuidString);
	FilePropData fpd;
	ZeroMemory(&fpd, sizeof(FilePropData));

	// std::wstring strCategory = pAppInterface->GetText(MAKETEXTID('p',200));
	// fpd.szCategoryName = strCategory.c_str();
	fpd.szCategoryName = L"VirusTotal helper"; // TODO: MAKETEXTID
	fpd.szDescription = nullptr;

	fpd.propType = MCFILEPROP_VIRUSTOTAL; // TODO: MAKETEXTID
	fpd.szPropName = L"VirusTotal"; // Machine name. only use Latin chars. This
									// name is not shown to user.
	fpd.szDisplayName =	L"VirusTotal"; // pAppInterface->GetText(MAKETEXTID('p',201));
	fpd.dwOptions = FILEPROP_STRING | FILEPROP_CUSTOMIZABLE;
	fpd.IdealWidth = 80;
	fpd.Align = DT_RIGHT;
	pPropMan->RegisterProperty(&fpd);

	pAppInterface->ReleaseInterface((ZHANDLE)pPropMan, ZOBJ_PROPMANGER);
	m_ExtensionID = (WORD)pAppInterface->ModuleIDStrToID(m_GuidString);

	ICommandManager *pCommandManager = pAppInterface->GetCommandManager();
	ZHANDLE hCmdSetKey = pCommandManager->RegisterCommand(APPEXT_CMD_SET_APIKEY, ZCF_ENABLE | ZCF_TARGET_ANY, L"Set API key", L"Set API key required for using VirusTotal services");
	ZHANDLE hCmdCheckHash = pCommandManager->RegisterCommand(APPEXT_CMD_QUERY_FILE, ZCF_ENABLE | ZCF_TARGET_ANY | ZCF_CMDTYPE_FILE, L"Check file by hash", L"Check file hash with VirusTotal", MAKEACCELKEY(0, FCUSTOMIZABLE)); //ZCF_CMDTYPE_FILE

	IMenuManager *pMenuManager = pAppInterface->GetMenuManager();
	if (!pMenuManager)
		return 0;

	ZHANDLE hMenuExtensions = pMenuManager->FindMenu(MAKETEXTID('m', 2006), TRUE, FALSE);
	if (hMenuExtensions == 0)
		return 0;

	ZHANDLE hMenuVirusTotal = pMenuManager->FindMenu(hMenuExtensions, L"VirusTotal", TRUE); // TODO: MAKETEXTID
	if (hMenuVirusTotal == 0)
		return 0;

	pMenuManager->AddMenuItem(hMenuVirusTotal, hCmdSetKey);
	pMenuManager->AddMenuItem(hMenuVirusTotal, hCmdCheckHash);

	return 0;
}

long MCVirusTotal::GetModuleFlags()
{
	return 0;
}

BOOL MCVirusTotal::Init(IMultiAppInterface * pAppInterface)
{
	m_pAppInterface = pAppInterface;
	m_pConfig = pAppInterface->GetAppConfig();
	m_pFSMonitor = (IFileSystemMonitor *)pAppInterface->QueryInterface(ZOBJ_FILEMONITOR, 0);

	// Load API key from config
	ZHANDLE hConfigRoot = m_pConfig->GetConfigElement(NULL, L"config");
	m_ApiKey[0] = '\0';
	m_pConfig->GetConfigValue(hConfigRoot, L"apikey", L"value", m_ApiKey, _countof(m_ApiKey));
	SetApiKey();

	return TRUE;
}

bool MCVirusTotal::OnNotify(ZHANDLE hFrom, DWORD nNotifyMsg, WPARAM wParam, LPARAM lParam, void * pExtra)
{
	return false;
}

BOOL MCVirusTotal::OnMessage(long msg, ZHANDLE hView, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case AM_CLOSE: return OnClose(false, false);
	case APPEXT_CMD_SET_APIKEY: return Cmd_SetApiKey();
	case APPEXT_CMD_QUERY_FILE: return Cmd_QueryFiles();
	}

	return FALSE;
}

BOOL MCVirusTotal::OnCustomCommand(ICustomCommand * pCustomCommand)
{
	return FALSE;
}

BOOL MCVirusTotal::OnClose(bool bShutDown, bool bDoNotAsk)
{
	// Save API key to config
	ZHANDLE hConfigRoot = m_pConfig->GetConfigElement(NULL, L"config", true);
	m_pConfig->SetConfigValue(hConfigRoot, L"apikey", L"value", m_ApiKey, true);

	return FALSE;
}

int MCVirusTotal::DoImportData(IXData * pXData)
{
	return 0;
}

IImportData * MCVirusTotal::Get_ImportObject()
{
	return nullptr;
}

IExportData * MCVirusTotal::Get_ExportObject()
{
	return nullptr;
}

void MCVirusTotal::QueryFilesAsync(IFileItemCollection *pFileItems)
{
	for (DWORD n = 0, nCount = pFileItems->Count(); n < nCount; ++n)
	{
		IFileItem *pItem = pFileItems->GetAt(n);
		if (pItem)
		{
			std::thread([&, pItem] {
				WCHAR szPath[_MC_MAXPATH_];
				pItem->Get_FullPath(szPath, _countof(szPath)); // Get full file path
				char buf[_MC_MAXPATH_];
				wcstombs(buf, szPath, _countof(buf));

				pItem->Get_Path(szPath, _countof(szPath)); // Now get folder path

				ExtraProp prop;
				ZeroMemory(&prop, sizeof(ExtraProp));
				prop.Flag = ZFXP_DISPLAYNAME;

				// Setting prop to display "Checking..."
				wcscpy(prop.szDisplayName, L"Checking...");
				pItem->SetExtraPropData(m_ExtensionID, MCFILEPROP_VIRUSTOTAL, &prop);
				m_pFSMonitor->RefreshPath(szPath);

				// Check hash
				std::wstring result = m_VirusTotal.CheckByHash(SHA1::from_file(buf).c_str());

				// Setting prop to display the result
				wcscpy(prop.szDisplayName, result.c_str());
				pItem->SetExtraPropData(m_ExtensionID, MCFILEPROP_VIRUSTOTAL, &prop);
				m_pFSMonitor->RefreshPath(szPath);
			}).detach();
		}
	}

	pFileItems->Release();
}

// Set API key for VirusTotal
void MCVirusTotal::SetApiKey()
{
	char buf[65];
	wcstombs(buf, m_ApiKey, _countof(buf));
	m_VirusTotal.SetApiKey(buf);
}

BOOL MCVirusTotal::Cmd_SetApiKey()
{
	WCHAR ApiKey[65];
	ZeroMemory(ApiKey, sizeof(ApiKey));

	bool ret = m_pAppInterface->ShowAskTextDlg(L"VirusTotal", L"API key:", m_ApiKey, nullptr, ApiKey, _countof(ApiKey) - 1);
	if (ret && ApiKey[0])
	{
		wcscpy(m_ApiKey, ApiKey);
		SetApiKey();
	}

	return TRUE;
}

// Check file command
BOOL MCVirusTotal::Cmd_QueryFiles()
{
	IFileItemCollection *pFileItems = m_pAppInterface->CreateFileItemCollection();
	m_pAppInterface->SendMessageToSource(AM_GETSELECTEDITEMS, (WPARAM)pFileItems, MF_FILES | MF_INCFOCUS);
	std::thread(&MCVirusTotal::QueryFilesAsync, this, pFileItems).detach();

	return TRUE;
}