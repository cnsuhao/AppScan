// app_webauth.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdlib.h>
#include "../AppScanLib/AppScanLib.h"
#pragma comment(lib,"../../bin/AppScanLib.lib")
#include <Shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")
#include <string>
using namespace std;
#include <iostream>
#include <fstream>
#include <vector>

#include <WinInet.h>
#include <Urlmon.h>
#pragma comment(lib,"Urlmon.lib")
#pragma comment(lib,"WinInet.lib")

#include "../http/http.h"
#pragma comment(lib,"../../bin/http.lib")

struct USER_INFO
{
	wchar_t user[50];
	wchar_t pass[50];
};

struct PORT_SCAN
{
	arglist *list;
	int port;
	BOOL isssl;
	HANDLE hDone;
	char user[50];
	char pass[50];
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

string& replace_all(string& str,const string& old_value,const string& new_value)
{
	while (true)
	{
		string::size_type pos(0);
		if((pos = str.find(old_value)) != string::npos)
			str.replace(pos,old_value.length(),new_value);
		else break;
	}
	return str;
}

DWORD WINAPI CrackScanWorkProc(PVOID lpThreadParameter)
{
	PORT_SCAN *lpScanInfo = (PORT_SCAN *)lpThreadParameter;
	int port = lpScanInfo->port;
	arglist *list = lpScanInfo->list;
	wchar_t *szHost = (wchar_t *)AppGetParam(list,"host");
	DWORD dwTimeOut = AppGetTimeOut(lpScanInfo->list);
	wchar_t szUrl[1024] = {0};
	wchar_t szUrlPath[1024] = {0};
	if (port == 0)
	{
		wsprintf(szUrl,szHost);
	}
	else
	{
		AppGetString(list,TEXT("path"),szUrlPath,1024);
		if (lpScanInfo->isssl)
		{
			wsprintf(szUrl,TEXT("https://%s:%d%s"),szHost,lpScanInfo->port,szUrlPath);
		}
		else
		{
			wsprintf(szUrl,TEXT("http://%s:%d%s"),szHost,lpScanInfo->port,szUrlPath);
		}
	}
	/*PBYTE lpBuff = new BYTE[1024];
	ZeroMemory(lpBuff,1024);
	PBYTE lpHeader = new BYTE[1024];
	ZeroMemory(lpHeader,1024);*/
	int dwHttpState;
	char WebServerInfo[1024] = {0};
	char WebAuthInfo[1024] = {0};
	DWORD dwServerInfoSize = sizeof(WebServerInfo);
	//BOOL bRet = HTTP_GET(szUrl,lpBuff,1023,lpHeader,1023,dwTimeOut,&dwHttpState,WebServerInfo,dwServerInfoSize,lpScanInfo->user,lpScanInfo->pass);
	string buff,headbuff;
	BOOL bRet = HTTP_GET_E(WStringToString(szUrl),&buff,&headbuff,dwTimeOut,&dwHttpState,lpScanInfo->isssl,TRUE,lpScanInfo->user,lpScanInfo->pass);
	if (bRet && dwHttpState == 200) //破解成功
	{
		ResetEvent(lpScanInfo->hDone);
		wchar_t szInfo[1024] = {0};
		wsprintf(szInfo,TEXT("%s 返回状态：%d  %s  %s %s"),szUrl,dwHttpState,StringToWString(WebServerInfo).c_str(),StringToWString(lpScanInfo->user).c_str(),StringToWString(lpScanInfo->pass).c_str());
		AppPushInfo(list,3,szInfo);
	}
	delete lpScanInfo;
	//delete []lpBuff;
	//delete []lpHeader;
	return TRUE;
}

DWORD WINAPI HttpScanWorkProc(PVOID lpThreadParameter)
{
	PORT_SCAN *lpScanInfo = (PORT_SCAN *)lpThreadParameter;
	int port = lpScanInfo->port;
	arglist *list = lpScanInfo->list;
	wchar_t *szHost = (wchar_t *)AppGetParam(list,"host");
	DWORD dwTimeOut = AppGetTimeOut(lpScanInfo->list);
	wchar_t szUrl[1024] = {0};
	wchar_t szUrlPath[1024] = {0};
	if (port == 0)
	{
		wsprintf(szUrl,szHost);
	}
	else
	{
		AppGetString(list,TEXT("path"),szUrlPath,1024);
		if (lpScanInfo->isssl)
		{
			wsprintf(szUrl,TEXT("https://%s:%d%s"),szHost,lpScanInfo->port,szUrlPath);
		}
		else
		{
			wsprintf(szUrl,TEXT("http://%s:%d%s"),szHost,lpScanInfo->port,szUrlPath);
		}
	}
	//PBYTE lpBuff = new BYTE[1024];
	//ZeroMemory(lpBuff,1024);
	//PBYTE lpHeader = new BYTE[1024];
	//ZeroMemory(lpHeader,1024);
	int dwHttpState;
	char WebServerInfo[1024] = {0};
	char WebAuthInfo[1024] = {0};
	DWORD dwServerInfoSize = sizeof(WebServerInfo);
	//BOOL bRet = HTTP_GET(szUrl,lpBuff,1023,lpHeader,1023,dwTimeOut,&dwHttpState,WebServerInfo,dwServerInfoSize);
	string buff,headbuff;
	BOOL bRet = HTTP_GET_E(WStringToString(szUrl),&buff,&headbuff,dwTimeOut,&dwHttpState,lpScanInfo->isssl);
	if (bRet && dwHttpState == 401)
	{
		//if (StrStrI((wchar_t *)lpHeader,TEXT("WWW-Authenticate: Basic")))
		//{
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
				index = httphead[i].find("WWW-Authenticate: Basic");
				if (index != string::npos)
				{
					temps.clear();
					split(httphead[i],"=",&temps);
					if (temps.size() == 2)
					{
						sprintf(WebAuthInfo,temps[1].c_str());
					}
				}

			}
			wchar_t szInfo[1024] = {0};
			wsprintf(szInfo,TEXT("%s 返回状态：%d Web服务器：%s 基础认证信息：%s"),szUrl,dwHttpState,StringToWString(WebServerInfo).c_str(),StringToWString(WebAuthInfo).c_str());
			AppPushInfo(list,1,szInfo);
			//开始破解
			wchar_t TempPath[MAX_PATH] = {0};
			GetCurrentDirectory(MAX_PATH,TempPath);
			lstrcat(TempPath,TEXT("\\dic\\"));
			wchar_t szUD[MAX_PATH] = {0};
			wchar_t szPD[MAX_PATH] = {0};
			wchar_t szUP[MAX_PATH] = {0};
			AppGetString(list,TEXT("dic_user"),szUD,MAX_PATH);
			AppGetString(list,TEXT("dic_pass"),szPD,MAX_PATH);
			AppGetString(list,TEXT("dic_up"),szUP,MAX_PATH);
			BOOL bIsDone = FALSE;
			wchar_t szPath[MAX_PATH] = {0};
			wsprintf(szPath,TEXT("%s%s"),TempPath,szUP);
			ifstream fup(szPath,ios::in);
			char strUP[MAX_PATH] = {0};
			HANDLE hDone = CreateEvent(NULL,FALSE,FALSE,NULL);
			SetEvent(hDone);
			while (fup.getline(strUP,sizeof(strUP)))
			{
				if (WaitForSingleObject(hDone,500) == WAIT_TIMEOUT)//破解完成
				{
					bIsDone = TRUE;
					break;
				}
				SetEvent(hDone);
				vector<string> listUP;
				split(strUP,"|",&listUP);
				PORT_SCAN *lpScanNew = new PORT_SCAN;
				lpScanNew->isssl = lpScanInfo->isssl;
				lpScanNew->list = lpScanInfo->list;
				lpScanNew->port = lpScanInfo->port;
				lpScanNew->hDone = hDone;
				sprintf(lpScanNew->user,listUP[0].c_str());
				sprintf(lpScanNew->pass,listUP[1].c_str());
				AppAddWork(list,CrackScanWorkProc,lpScanNew);
			}
			fup.clear();
			if (!bIsDone)
			{
				wsprintf(szPath,TEXT("%s%s"),TempPath,szUD);
				ifstream fud(szPath,ios::in);
				char line[MAX_PATH] = {0};
				wsprintf(szPath,TEXT("%s%s"),TempPath,szPD);
				while (fud.getline(line,sizeof(line)))
				{
					char line2[MAX_PATH] = {0};
					ifstream fpd(szPath,ios::in);
					while (fpd.getline(line2,sizeof(line2)))
					{
						string password = line2;
						if (password.find("$NAME$") != string::npos)
						{
							password = replace_all(password,"$NAME$",line);
						}
						if (password.find("$NULL$") != string::npos)
						{
							password = replace_all(password,"$NULL$","");
						}
						if (WaitForSingleObject(hDone,500) == WAIT_TIMEOUT)//破解完成
						{
							bIsDone = TRUE;
							break;
						}
						SetEvent(hDone);
						PORT_SCAN *lpScanNew = new PORT_SCAN;
						lpScanNew->isssl = lpScanInfo->isssl;
						lpScanNew->list = lpScanInfo->list;
						lpScanNew->port = lpScanInfo->port;
						lpScanNew->hDone = hDone;
						sprintf(lpScanNew->user,line);
						sprintf(lpScanNew->pass,password.c_str());
						AppAddWork(list,CrackScanWorkProc,lpScanNew);
					}
					fpd.clear();
				}
				fud.clear();
			}
			
			
		//}
	}
	delete lpScanInfo;
	//delete []lpBuff;
	//delete []lpHeader;
	
	return 0;
}

extern "C" __declspec(dllexport) BOOL AppGetInfo(APP_INFO *lpInfo)
{
	wsprintf(lpInfo->szName,TEXT("webauth基础认证弱口令"));
	wsprintf(lpInfo->szVer,TEXT("1.0"));
	wsprintf(lpInfo->szAuthorName,TEXT("YGF"));
	wsprintf(lpInfo->szDescription,TEXT("本模块用于WEB基础认证弱口令破解，目标为URL文件时，不需要指定端口路径。\r\n参数\r\nport:端口\r\nsslport:https端口\r\npath:路径\r\nnokw:排除的关键字\r\ndic_user:用户名字典\r\ndic_pass:密码字典"));
	wsprintf(lpInfo->szDefaultParam,TEXT("port=80,81,8080\r\nsslport=443\r\npath=/\r\nnokw=vedio,tplink\r\ndic_user=WEBAUTH_UD.TXT\r\ndic_pass=WEBAUTH_PD.TXT\r\ndic_up=WEBAUTH_UP.TXT"));
	return TRUE;
}

extern "C" __declspec(dllexport) BOOL AppScan(arglist *lpList)
{
	DWORD tagType = AppGetTagType(lpList);
	if (tagType == 3)
	{
		PORT_SCAN *lpScanInfo = new PORT_SCAN;
		lpScanInfo->port = 0;
		lpScanInfo->list = lpList;
		lpScanInfo->isssl = FALSE;
		AppAddWork(lpList,HttpScanWorkProc,lpScanInfo);
		AppWaitForWorks(lpList);
	}
	else
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
			AppAddWork(lpList,HttpScanWorkProc,lpScanInfo);
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
			AppAddWork(lpList,HttpScanWorkProc,lpScanInfo);
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
	}
	
	return TRUE;
}