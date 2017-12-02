#include "VirusTotal.h"
#include "json.hpp"
#include <IHTTPRequest.h>
#include <memory>

using namespace MCNS;

void VirusTotal::SetApiKey(const char *ApiKey)
{
	strcpy(m_ApiKey, ApiKey);
}

class request_ptr {
public:
	request_ptr(IHTTPRequest *pRequest) : m_pRequest(pRequest) { }
	~request_ptr() { m_pRequest->Release(); }
	IHTTPRequest* operator->() { return m_pRequest; }
	IHTTPRequest& operator* () { return *m_pRequest; }
private:
	IHTTPRequest *m_pRequest;
};

std::wstring VirusTotal::CheckByHash(const char *hash)
{
	using namespace MCNS;
	using namespace nlohmann;

	std::string request = FormatRequest("file/report", hash);

	request_ptr pRequest = (*m_ppAppInterface)->CreateHTTPRequester();
	IHTTPResponse* pResponse = pRequest->SendRequestGET(request.c_str());

	int ret = pRequest->GetResponseCode();
	try
	{
		if (ret == 403) // api key not present/incorrect/banned/not enough permissions
			return L"Invalid API key";

		if (ret == 204) // 4 request/sec exceeded
			return L"Limit exceeded";

		if (ret != 200 || pResponse == nullptr)
			return L"Unknown error";

		size_t data_len = pResponse->DataLen();
		std::unique_ptr<BYTE[]> data(new BYTE[data_len + 1]);
		if (data == nullptr)
			return L"Unknown error";
		pResponse->CopyData(data.get(), data_len + 1);

		json response = json::parse(data.get());

		int response_code = response["response_code"];
		if (response_code != 1) // 0 = not found; -2 = queued
			return L"N/A";

		int positives = response["positives"];
		int total = response["total"];

		return std::to_wstring(positives) + L"/" + std::to_wstring(total);
	}
	catch(...) // json error — detail::type_error
	{
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