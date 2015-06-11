// app_taginfo.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdlib.h>
#include <string>
using namespace std;
#include <iostream>
#include <fstream>
#include <vector>


#include "../AppScanLib/AppScanLib.h"
#pragma comment(lib,"../../bin/AppScanLib.lib")

#include "../http/http.h"
#pragma comment(lib,"../../bin/http.lib")


struct PORT_SCAN
{
	arglist *list;
	int port;
	BOOL isssl;
};

std::wstring StringToWString(const std::string &str)
{
	std::wstring wstr(str.length(),L' ');
	std::copy(str.begin(), str.end(), wstr.begin());
	return wstr; 
}
std::string WStringToString(const std::wstring &wstr)
{
	std::string str(wstr.length(), ' ');
	std::copy(wstr.begin(), wstr.end(), str.begin());
	return str; 
}



void split(const std::string& s,
	const std::string& delim,
	std::vector<std::string>* ret)
{
	size_t last = 0;
	size_t index=s.find_first_of(delim,last);
	while (index!=std::string::npos)
	{
		ret->push_back(s.substr(last,index-last));
		last=index+1;
		index=s.find_first_of(delim,last);
	}
	if (index-last>0)
	{
		ret->push_back(s.substr(last,index-last));
	}
}


DWORD WINAPI HttpScanWorkProc(PVOID lpThreadParameter)
{
	PORT_SCAN *lpScanInfo = (PORT_SCAN *)lpThreadParameter;
	int port = lpScanInfo->port;
	arglist *list = lpScanInfo->list;
	wchar_t *szHost = (wchar_t *)AppGetParam(list,"host");
	DWORD dwTimeOut = AppGetTimeOut(lpScanInfo->list);
	wchar_t szUrl[1024] = {0};
	if (lpScanInfo->isssl)
	{
		wsprintf(szUrl,TEXT("https://%s:%d/"),szHost,lpScanInfo->port);
	}
	else
	{
		wsprintf(szUrl,TEXT("http://%s:%d/"),szHost,lpScanInfo->port);
	}
	//PBYTE lpBuff = new BYTE[1024];
	//ZeroMemory(lpBuff,1024);
	//PBYTE lpHeader = new BYTE[1024];
	//ZeroMemory(lpHeader,1024);
	int dwHttpState;
	char WebServerInfo[1024] = {0};
	DWORD dwServerInfoSize = sizeof(WebServerInfo);
	//BOOL bRet = HTTP_GET(szUrl,lpBuff,1023,lpHeader,1023,dwTimeOut,&dwHttpState,WebServerInfo,dwServerInfoSize);
	string buff,headbuff;
	BOOL bRet = HTTP_GET_E(WStringToString(szUrl),&buff,&headbuff,dwTimeOut,&dwHttpState,lpScanInfo->isssl);
	if (bRet)
	{
		vector<string> httphead;
		split(headbuff,"\r\n",&httphead);
		vector<string> temps;
		for (int i = 0;i < httphead.size();i++)
		{
			unsigned int index = httphead[i].find("Server:");
			if (index != string::npos)
			{

				split(httphead[i],":",&temps);
				if (temps.size() == 2)
				{
					int len = strlen(temps[1].c_str());
					if (len > 99)
					{
						len = 99;
					}
					memcpy(WebServerInfo,temps[1].c_str()+1,len);

				}
				break;
			}
		}
		wchar_t szInfo[1024] = {0};
		wsprintf(szInfo,TEXT("%s 返回状态：%d Web服务器：%s"),szUrl,dwHttpState,StringToWString(WebServerInfo).c_str());
		AppPushInfo(list,1,szInfo);
	}
	/*delete []lpBuff;
	delete []lpHeader;*/
	delete lpScanInfo;
	return 0;
}

DWORD WINAPI PortScanWorkProc(PVOID lpThreadParameter)
{
	PORT_SCAN *lpScanInfo = (PORT_SCAN *)lpThreadParameter;
	int port = lpScanInfo->port;
	arglist *list = lpScanInfo->list;
	wchar_t *szHost = (wchar_t *)AppGetParam(list,"host");
	DWORD dwTimeOut = AppGetTimeOut(lpScanInfo->list);
	BOOL bRet = AppCheckTcpPort(szHost,port,dwTimeOut);
	wchar_t info[MAX_PATH] = {0};
	if(bRet)
	{
		wsprintf(info,L"%d : %s \n",port,L"open");
		AppPushInfo(list,1,info);
		AppAddWork(list,HttpScanWorkProc,lpScanInfo);
	}
	else
	{
		delete lpScanInfo;
	}
	return 0;
}


extern "C" __declspec(dllexport) BOOL AppGetInfo(APP_INFO *lpInfo)
{
	wsprintf(lpInfo->szName,TEXT("目标信息获取"));
	wsprintf(lpInfo->szVer,TEXT("1.0"));
	wsprintf(lpInfo->szAuthorName,TEXT("YGF"));
	wsprintf(lpInfo->szDescription,TEXT("本模块用于目标信息获取。条件允许，能获取开放端口、对应的应用、WEBSERVER、操作系统\r\n参数：\r\nport=端口\r\nsslport=HTTPS端口"));
	wsprintf(lpInfo->szDefaultParam,TEXT("port=21,22,23,80,81,88,135,139,445,1080,1723,1433,3306,3389,8080\r\nsslport=443"));
	return TRUE;
}

extern "C" __declspec(dllexport) BOOL AppScan(arglist *lpList)
{	
	wchar_t szPort[1024] = {0};
	wchar_t szSSLPort[1024] = {0};
	AppGetString(lpList,TEXT("port"),szPort,1024*sizeof(wchar_t));
	AppGetString(lpList,TEXT("sslport"),szSSLPort,1024*sizeof(wchar_t));
	PLIST_STRING res = new LIST_STRING;
	ZeroMemory(res,sizeof(LIST_STRING));
	Split(szPort,TEXT(","),res);
	PLIST_STRING resssl = new LIST_STRING;
	ZeroMemory(resssl,sizeof(LIST_STRING));
	Split(szSSLPort,TEXT(","),resssl);
	PLIST_STRING item = res;
	while (TRUE)
	{
		wchar_t *szPortItem = item->szString;
		PORT_SCAN *lpScanInfo = new PORT_SCAN;
		lpScanInfo->port = _wtoi(szPortItem);
		lpScanInfo->list = lpList;
		lpScanInfo->isssl = FALSE;
		AppAddWork(lpList,PortScanWorkProc,lpScanInfo);
		if (item->next)
		{
			item = item->next;
		}
		else
		{
			break;
		}
	}
	item = resssl;
	while (TRUE)
	{
		wchar_t *szPortItem = item->szString;
		PORT_SCAN *lpScanInfo = new PORT_SCAN;
		lpScanInfo->port = _wtoi(szPortItem);
		lpScanInfo->list = lpList;
		lpScanInfo->isssl = TRUE;
		AppAddWork(lpList,PortScanWorkProc,lpScanInfo);
		if (item->next)
		{
			item = item->next;
		}
		else
		{
			break;
		}
	}
	AppWaitForWorks(lpList);
	AppFreeString(res);
	return TRUE;
}

