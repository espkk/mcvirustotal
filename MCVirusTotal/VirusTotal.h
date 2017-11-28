#pragma once
#include <string>
#include <Windows.h>
#include <IAppInterface.h>

MCNSBEGIN;

class VirusTotal
{
public:
	VirusTotal(IMultiAppInterface **ppAppInterface) : m_ApiKey{ 0 }, m_ppAppInterface(ppAppInterface) {};

	// https://www.virustotal.com/en/user/%username%/apikey/
	void SetApiKey(const char* ApiKey);

	// Check by hash. returns "matches/total checks" or error msg.
	std::wstring CheckByHash(const char *hash);

private:
	std::string VirusTotal::FormatRequest(const char *method, const char *resource = nullptr);

	const char * const BaseURL = "https://www.virustotal.com/vtapi/v2/";
	char m_ApiKey[65];
	IMultiAppInterface **m_ppAppInterface;
};

MCNSEND;