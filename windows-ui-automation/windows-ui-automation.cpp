#include <windows.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
using namespace std;
enum SPOTIFY
{
	SPOTIFY_MUTE = 524288,
	SPOTIFY_VOLUMEDOWN = 589824,
	SPOTIFY_VOLUMEUP = 655360,
	SPOTIFY_NEXT = 720896,
	SPOTIFY_PREV = 786432,
	SPOTIFY_STOP = 851968,
	SPOTIFY_PLAYPAUSE = 917504
};

typedef struct EnumHWndsArg
{
	std::vector<HWND>* vecHWnds;
	DWORD dwProcessId;
} EnumHWndsArg, * LPEnumHWndsArg;

void ReadF(char* str, char* buffer)
{
	HANDLE pfile;
	pfile = ::CreateFile(LPCWSTR(str), GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pfile == INVALID_HANDLE_VALUE)
	{
		wcout << "Failed to open file" << endl;;
		CloseHandle(pfile); // Be sure to release the handle before the function exits
		return;
	}
	DWORD filesize = GetFileSize(pfile, NULL);
	DWORD readsize;
	ReadFile(pfile, buffer, filesize, &readsize, NULL);
	buffer[filesize] = 0;
	CloseHandle(pfile); // close the handle

	DeleteFile(LPCWSTR(str));
}
void WriteF(char* str, const char* buffer, int size)
{
	HANDLE pfile;
	pfile = ::CreateFile(LPCWSTR(str), GENERIC_WRITE | GENERIC_READ, 0,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH, NULL);
	if (pfile == INVALID_HANDLE_VALUE)
	{
		wcout << "Failed to open file" << endl;;
		CloseHandle(pfile); // Be sure to release the handle before the function exits
		return;
	}
	DWORD readsize;
	WriteFile(pfile, buffer, size, &readsize, NULL);
	CloseHandle(pfile); // close the handle
	DeleteFile(LPCWSTR(str));
}

HANDLE GetProcessHandleByID(int nID)//Get process handle by process ID
{
	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, nID);
}

DWORD GetProcessIDByName(const wchar_t* pName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (_wcsicmp(pe.szExeFile, pName) == 0) {
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
		printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
	}
	CloseHandle(hSnapshot);
	return 0;
}

BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam)
{
	EnumHWndsArg* pArg = (LPEnumHWndsArg)lParam;
	DWORD  processId;
	GetWindowThreadProcessId(hwnd, &processId);
	if (processId == pArg->dwProcessId)
	{
		pArg->vecHWnds->push_back(hwnd);
		printf("%p\n", hwnd);
	}
	return TRUE;
}

void GetHWndsByProcessID(DWORD processID, std::vector<HWND>& vecHWnds)
{
	EnumHWndsArg wi;
	wi.dwProcessId = processID;
	wi.vecHWnds = &vecHWnds;
	EnumWindows(lpEnumFunc, (LPARAM)&wi);
}
void pause_spotify()
{
	long int HHWW;
	HHWW = 264082;

	printf("%d --->This Wnd\n", HHWW);
	SetFocus((HWND)HHWW);
	SendMessage((HWND)659436, WM_APPCOMMAND, 0, SPOTIFY_PLAYPAUSE);
}

int32_t main()
{
	long int HHWW;
	DWORD pid = GetProcessIDByName(L"spotify.exe");
	printf("pid = %u end\n", pid);
	char strPid[15];
	sprintf_s(strPid, 15, "%u", pid);
	char fileName[10] = "pid.cfg";
	char snPid[5] = {};
	ReadF(fileName, snPid);
	if (strncmp(snPid, "", strlen(snPid)) == 0) {
		WriteF(fileName, strPid, strlen(strPid));
	}
	else {
		ReadF(fileName, snPid);
	}
	if (pid != 0)
	{
		std::vector<HWND> vecHWnds;
		GetHWndsByProcessID(pid, vecHWnds);
		printf("vecHWnds.size() = %u\n", vecHWnds.size());
		for (const HWND &h : vecHWnds)
		{
			HWND parent = GetParent(h);

			if (parent == NULL)
			{
				HHWW = (long)h;
				printf("%d --->Main Wnd\n", h);
			}
			else
			{
				printf("%p %p\n", h, parent);
			}
		}
	}
	char szPid[15] = "";
	ReadF(fileName, szPid);
	printf("[ReadF] szPid:%s\n", szPid);
	//pause_spotify();
	HHWW = 0x000A02BC;
	printf("%d --->This Wnd\n", HHWW);
	//SetFocus((HWND)HHWW);
	DWORD_PTR dwResult;


	// SendMessage((HWND)HHWW, WM_APPCOMMAND, 0, SPOTIFY_PLAYPAUSE);
	


	HWND editWnd = FindWindowEx((HWND)HHWW, NULL, L"Edit", L"");
	printf("%d --->editwnd\n", HHWW);
	int textLength = SendMessage(editWnd, WM_GETTEXTLENGTH, 0, 0) + 1;
	wcout << textLength << endl;
	TCHAR text[256];
	SendMessage(editWnd, WM_GETTEXT, sizeof(text), (LPARAM)text);
	wcout << text << endl;
	//printf("%s\n", str);
}
