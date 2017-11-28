#include "MCVirusTotal.h"

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD /*ul_reason_for_call*/, LPVOID /*lpReserved*/)
{
	return TRUE;
}

extern "C" PVOID APIENTRY Create(int nID)
{
	if (nID == 0)
	{
		MCNS::MCVirusTotal* pExtension = new MCNS::MCVirusTotal();
		MCNS::IPluginInterface* pInterface = static_cast<MCNS::MCVirusTotal*>(pExtension);
		return pInterface;
	}

	return nullptr;
}

extern "C" bool APIENTRY Delete(MCNS::IPluginInterface* pModule, int nID)
{
	if (pModule == nullptr)
		return false;

	if (nID == 0)
	{
		MCNS::MCVirusTotal* pExtension = dynamic_cast<MCNS::MCVirusTotal*>(pModule);
		if (pExtension)
		{
			delete pExtension;
			return true;
		}
	}

	return false;
}

extern "C" bool APIENTRY GetExtensionInfo(int nID, MCNS::DLLExtensionInfo* pInfo)
{
	if (nID == 0)
		return MCNS::MCVirusTotal::GetExtensionInfo(pInfo);

	return false;
}