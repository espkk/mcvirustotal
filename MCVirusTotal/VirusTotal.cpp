#include "VirusTotal.h"
#include "json.hpp"
#include <IHTTPRequest.h>

using namespace MCNS;

void VirusTotal::SetApiKey(const char *ApiKey)
{
	strcpy(m_ApiKey, ApiKey);
}

std::wstring VirusTotal::CheckByHash(const char *hash)
{
	using namespace MCNS;
	using namespace nlohmann;

	std::string request = FormatRequest("file/report", hash);
	IHTTPRequest* pRequest = (*m_ppAppInterface)->CreateHTTPRequester();
	IHTTPResponse* pResponse = pRequest->SendRequestGET(request.c_str());

	BYTE *data;
	int ret = pRequest->GetResponseCode();
	try
	{
		if (ret == 403) // api key not present/incorrect/banned/not enough permissions
			throw L"Invalid API key";
		if (ret == 204) // 4 request/sec exceeded
			throw L"Limit exceeded";

		if (ret != 200 || pResponse == nullptr)
			throw L"Unknown error";

		size_t data_len = pResponse->DataLen();
		data = new BYTE[data_len + 1];
		if (data == nullptr)
			throw L"Unknown error";

		strncpy((char*)data, (const char*)pResponse->Data(), data_len);
		data[data_len] = '\0';

		json response = json::parse(data);

		free(data);
		data = nullptr;

		int response_code = response["response_code"];
		if (response_code != 1) // 0 = not found; -2 = queued
			throw L"N/A";

		int positives = response["positives"];
		int total = response["total"];

		return std::to_wstring(positives) + L"/" + std::to_wstring(total);
	}
	catch(const WCHAR *s)
	{
		pRequest->Release();
		if(data != nullptr)
			free(data);

		return s;
	}
	catch(...) //detail::type_error e
	{
		pRequest->Release();
		if (data != nullptr)
			free(data);

		return L"Unknown error";
	}
}

std::string VirusTotal::FormatRequest(const char *method, const char *resource)
{
	std::string request = BaseURL;
	request += method;
	request += "?";
	request += "apikey=";
	request += m_ApiKey;

	if (resource)
	{
		request += "&resource=";
		request += resource;
	}
	/*if (url)
	{
		request += "?url=";
		request += url;
	}
	if (scan)
	{
		request += "?scan=";
		request += scan;
	}
	if (ip)
	{
		request += "?ip=";
		request += ip;
	}
	if (domain)
	{
		request += "?domain=";
		request += domain;
	}*/

	return request;
}