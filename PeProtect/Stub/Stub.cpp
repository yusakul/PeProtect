// Stub.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "string"
#include "stub.h"
#include "windows.h"
#include "../aplib/aplib.h"
#pragma comment(lib,"..//aplib//aplib.lib")

using namespace std;
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")


void  Start();
extern "C" _declspec(dllexport) PACKINFO g_PackInfo = { (DWORD)Start};

__declspec (thread) int g_nNum = 0x11111111;


//=============窗口创建===========================================
//CreateWindow			User32.dll
//GetModuleHandle		Kernel32.dll
//ShowWindow			User32.dll
//GetMessage			User32.dll
//RegisterClass			User32.dll
//DispatchMessage		User32.dll
//WindowProc			直接用
//PostQuitMessage		User32.dll
//DefWindowProc			User32.dll
//UpdateWindow			User32.dll

//显示窗口
typedef BOOL(WINAPI* SHOWWINDOW)(_In_ HWND hWnd, _In_ int nCmdShow);

//获取信息
typedef BOOL(WINAPI* GETMESAGE)(
	_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd,
	_In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax);

//分发消息
typedef LRESULT(WINAPI* DISPATCHMESSAGE)(_In_ const MSG * lpmsg);

//注册窗口类
typedef ATOM(WINAPI* REGISTERCLASS)(
	_In_ const WNDCLASS * lpWndClass);

//创建窗口
typedef HWND(WINAPI * CREATEWINDOWEX)(
	_In_     DWORD     dwExStyle,
	_In_opt_ LPCTSTR   lpClassName,
	_In_opt_ LPCTSTR   lpWindowName,
	_In_     DWORD     dwStyle,
	_In_     int       x,
	_In_     int       y,
	_In_     int       nWidth,
	_In_     int       nHeight,
	_In_opt_ HWND      hWndParent,
	_In_opt_ HMENU     hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID    lpParam
	);

//发送列队消息
typedef VOID(WINAPI* POSTQUITMESSAGE)(
	_In_ int nExitCode
	);


//默认窗口处理函数
typedef LRESULT(WINAPI* DEFWINDOWPROC)(
_In_ HWND   hWnd,
_In_ UINT   Msg,
_In_ WPARAM wParam,
_In_ LPARAM lParam
);

//更新窗口
typedef BOOL(*UPDATEWINDOW)(
	_In_ HWND hWnd
	);

//获取窗口文本
typedef int (WINAPI* GETWINDOWTEXT)(
	_In_  HWND   hWnd,
	_Out_ LPTSTR lpString,
	_In_  int    nMaxCount
	);

//获取窗口文本长度
typedef int (WINAPI* GETWINDOWTEXTLENGTH)(
	_In_ HWND hWnd
	);

//根据控件获取窗口句柄
typedef HWND(WINAPI* GETDLGITEM)(
	_In_opt_ HWND hDlg,
	_In_     int  nIDDlgItem
	);

//设置窗口文本
typedef BOOL(WINAPI* SETWINDOWTEXT)(
	_In_     HWND    hWnd,
	_In_opt_ LPCTSTR lpString
	);

typedef BOOL(WINAPI* TRANSLATEMESSAGE)(
	_In_ const MSG *lpMsg
	);

typedef BOOL (WINAPI* DESTROYWINDOWS)(
	_In_ HWND hWnd
);


typedef VOID (WINAPI* EXITPROCESS)(
	_In_ UINT uExitCode
);

CREATEWINDOWEX      g_funCreateWindowEx = nullptr;
POSTQUITMESSAGE     g_funPostQuitMessage = nullptr;
DEFWINDOWPROC       g_funDefWindowProc = nullptr;
GETMESAGE			g_funGetMessage = nullptr;
REGISTERCLASS       g_funRegisterClass = nullptr;
SHOWWINDOW          g_funShowWindow = nullptr;
UPDATEWINDOW        g_funUpdateWindow = nullptr;
DISPATCHMESSAGE     g_funDispatchMessage = nullptr;
GETWINDOWTEXT       g_funGetWindowText = nullptr;
GETWINDOWTEXTLENGTH g_funGetWindowTextLength = nullptr;
GETDLGITEM          g_funGetDlgItem = nullptr;
SETWINDOWTEXT       g_funSetWindowText = nullptr;
TRANSLATEMESSAGE    g_funTranslateMessage = nullptr;
DESTROYWINDOWS		g_funDestroyWindows = nullptr;
EXITPROCESS			g_funExitProcess = nullptr;
//////////////////////////////////////////////////////////===============================



typedef FARPROC(WINAPI *MYGETPROCADDRESS)
(_In_ HMODULE hModule , _In_ LPCSTR lpProcName);

typedef HMODULE(WINAPI *MYLOADLIBRARY)(
	_In_ LPCSTR lpLibFileName
	);

typedef HMODULE(WINAPI *MYGETMODULEHANDLEA)(
	_In_opt_ LPCSTR lpModuleName
	);

typedef  int(__cdecl * MY__STDIO_COMMON_VSPRINTF)(
	_In_                                    unsigned __int64 _Options ,
	_Out_writes_z_(_BufferCount)            char*            _Buffer ,
	_In_                                    size_t           _BufferCount ,
	_In_z_ _Printf_format_string_params_(2) char const*      _Format ,
	_In_opt_                                _locale_t        _Locale ,
	va_list          _ArgList
	);

typedef BOOL(WINAPI *MYVIRTUALPROTECT)(
	_In_ LPVOID lpAddress ,
	_In_ SIZE_T dwSize ,
	_In_ DWORD flNewProtect ,
	_Out_ PDWORD lpflOldProtect
	);
typedef LPVOID(WINAPI *MYVIRTUALALLOC)(
	_In_opt_ LPVOID lpAddress ,
	_In_     SIZE_T dwSize ,
	_In_     DWORD  flAllocationType ,
	_In_     DWORD  flProtect
	);
typedef BOOL(WINAPI *MYVIRTUALFREE)(
	_In_ LPVOID lpAddress ,
	_In_ SIZE_T dwSize ,
	_In_ DWORD  dwFreeType
	);

typedef int (WINAPI *MYMESSAGEBOXA)(
	_In_opt_ HWND    hWnd ,
	_In_opt_ PCHAR lpText ,
	_In_opt_ PCHAR lpCaption ,
	_In_     UINT    uType
	);

typedef errno_t(__cdecl * MYFOPEN_S)(
	_Outptr_result_maybenull_ FILE**      _Stream ,
	_In_z_                    char const* _FileName ,
	_In_z_                    char const* _Mode
	);

typedef	 char* (__cdecl * MYFGETS)(
	_Out_writes_z_(_MaxCount) char* _Buffer ,
	_In_                      int   _MaxCount ,
	_Inout_                   FILE* _Stream
	);

typedef int(__cdecl * MYSTRCMP)(
	_In_z_ char const* _Str1 ,
	_In_z_ char const* _Str2
	);

typedef DWORD(WINAPI * MYGETLASTERROR)(VOID);

// 请一定注意把函数调用约定加上,否则汇编会对不上号的
typedef BOOL(WINAPI * MYSHGETSPECIALFOLDERPATHA)(
	HWND   hwndOwner ,
	_Out_ PCHAR lpszPath ,
	_In_  int    csidl ,
	_In_  BOOL   fCreate
	);




MYGETPROCADDRESS g_GetProcAddress = NULL;
MYLOADLIBRARY    g_LoadLibraryA = NULL;
MYGETMODULEHANDLEA g_GetModuleHandleA = NULL;
MYVIRTUALPROTECT g_VirtualProtect = NULL;
MYVIRTUALALLOC g_VirtualAlloc = NULL;
MYVIRTUALFREE g_VirtualFree = NULL;
MYMESSAGEBOXA g_MessageBoxA = NULL;
MY__STDIO_COMMON_VSPRINTF g_stdio_common_vsprintf = NULL;
MYFOPEN_S g_fopen_s = NULL;
MYFGETS g_fgets = NULL;
MYSTRCMP g_strcmp = NULL;
MYGETLASTERROR g_GetLastError = NULL;
MYSHGETSPECIALFOLDERPATHA g_SHGetSpecialFolderPathA = NULL;

DWORD g_dwImageBase;//加载基址
DWORD g_oep;

//获取GetProcAddress和LoadLibraryA的函数地址
void  MyGetProcAddress(LPVOID *pGetProc , LPVOID *pLoadLibrary)
{
	PCHAR pBuf = NULL;
	_asm
	{
		mov eax , fs:[0x30];//找到PEB
		mov eax , [ eax + 0x0C ];//找到了LDR
		mov eax , [ eax + 0x0C ];//找到了第一个节点
		mov eax , [ eax ];       //找到了ntdll
		mov eax , [ eax ];       //找到了kernel32.dll
		mov ebx , dword ptr ds : [eax + 0x18];//在0x18偏移处取出基址(DllBase)
		mov pBuf , ebx;
	}

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);

	PIMAGE_DATA_DIRECTORY pExportDir =
		(pNt->OptionalHeader.DataDirectory + 0);

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		(pExportDir->VirtualAddress + pBuf);
	//后面的步骤

	//1  找到三个表：名称，地址，序号
	PDWORD pAddress = (PDWORD)(pExport->AddressOfFunctions + pBuf);
	PDWORD pName = (PDWORD)(pExport->AddressOfNames + pBuf);
	PWORD  pId = (PWORD)(pExport->AddressOfNameOrdinals + pBuf);
	PVOID GetProAddress = 0;
	PVOID LoadLibry = 0;
	//2  在名称表中去遍历GetProcAddress这个字符串
	for(size_t i = 0; i < pExport->NumberOfNames; i++)
	{
		char* Name = (pName[ i ] + pBuf);
		if(strcmp(Name , "GetProcAddress") == 0)
		{
			GetProAddress = pAddress[ pId[ i ] ] + pBuf;
		}
		if(strcmp(Name , "LoadLibraryA") == 0)
		{
			LoadLibry = pAddress[ pId[ i ] ] + pBuf;
		}
	}
	*pGetProc = GetProAddress;
	*pLoadLibrary = LoadLibry;
}

//获取函数地址
void Init()
{
	g_nNum; //使用tls变量,产生tls节表

	MyGetProcAddress((LPVOID*)&g_GetProcAddress , (LPVOID*)&g_LoadLibraryA);
	//什么API函数都可以动态获取了
	g_GetModuleHandleA = (MYGETMODULEHANDLEA)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll") , "GetModuleHandleA");
	g_VirtualProtect = (MYVIRTUALPROTECT)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll") , "VirtualProtect");
	g_VirtualAlloc = (MYVIRTUALALLOC)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll") , "VirtualAlloc");
	g_VirtualFree = (MYVIRTUALFREE)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll") , "VirtualFree");
	g_MessageBoxA = (MYMESSAGEBOXA)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "MessageBoxA");
	g_stdio_common_vsprintf = (MY__STDIO_COMMON_VSPRINTF)
		g_GetProcAddress(g_LoadLibraryA("ucrtbased.dll") , "__stdio_common_vsprintf");

	g_fopen_s = (MYFOPEN_S)
		g_GetProcAddress(g_LoadLibraryA("ucrtbased.dll") , "fopen_s");
	g_fgets = (MYFGETS)
		g_GetProcAddress(g_LoadLibraryA("ucrtbased.dll") , "fgets");
	g_strcmp = (MYSTRCMP)
		g_GetProcAddress(g_LoadLibraryA("ucrtbased.dll") , "strcmp");
	g_GetLastError = (MYGETLASTERROR)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll") , "GetLastError");
	g_SHGetSpecialFolderPathA = (MYSHGETSPECIALFOLDERPATHA)
		g_GetProcAddress(g_LoadLibraryA("Shell32.dll") , "SHGetSpecialFolderPathA");


	//窗口相关======================
	g_funCreateWindowEx = (CREATEWINDOWEX)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "CreateWindowExW");
	g_funPostQuitMessage = (POSTQUITMESSAGE)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "PostQuitMessage");
	g_funDefWindowProc = (DEFWINDOWPROC)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "DefWindowProcW");
	g_funGetMessage = (GETMESAGE)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "GetMessageW");
	g_funRegisterClass = (REGISTERCLASS)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "RegisterClassW");
	g_funShowWindow = (SHOWWINDOW)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "ShowWindow");
	g_funUpdateWindow = (UPDATEWINDOW)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "UpdateWindow");
	g_funDispatchMessage = (DISPATCHMESSAGE)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "DispatchMessageW");
	g_funGetWindowText = (GETWINDOWTEXT)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "GetWindowTextW");
	g_funGetWindowTextLength = (GETWINDOWTEXTLENGTH)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "GetWindowTextLengthW");
	g_funGetDlgItem = (GETDLGITEM)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "GetDlgItem");
	g_funSetWindowText = (SETWINDOWTEXT)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "SetWindowTextW");
	g_funTranslateMessage = (TRANSLATEMESSAGE)
		g_GetProcAddress(g_LoadLibraryA("User32.dll") , "TranslateMessage");
	g_funDestroyWindows = (DESTROYWINDOWS)
		g_GetProcAddress(g_LoadLibraryA("User32.dll"), "DestroyWindows");
	g_funExitProcess = (EXITPROCESS)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll"), "ExitProcess");

	//获取加载基址
	g_dwImageBase = (DWORD)g_GetModuleHandleA(NULL);
	//获取OEP
	g_oep = g_PackInfo.TargetOepRva + g_dwImageBase;

	
}

//填充IAT
void DealwithIAT()
{

	// 1.获取第一项iat项
	PIMAGE_IMPORT_DESCRIPTOR pImportTable =
		(PIMAGE_IMPORT_DESCRIPTOR)((DWORD)g_PackInfo.ImportTableRva + g_dwImageBase);
	if(g_PackInfo.ImportTableRva) //如果没用导入表则跳过
	{
		HMODULE lib;
		IMAGE_THUNK_DATA *IAT , *INTable;
		IMAGE_IMPORT_BY_NAME *IatByName;

		while(pImportTable->Name)//(pImportTable->FirstThunk)
		{
			lib = g_LoadLibraryA((char *)(pImportTable->Name + (DWORD)g_dwImageBase));

			IAT = (IMAGE_THUNK_DATA *)(pImportTable->FirstThunk + (DWORD)g_dwImageBase);
			INTable = (IMAGE_THUNK_DATA *)((pImportTable->OriginalFirstThunk ? pImportTable->OriginalFirstThunk : pImportTable->FirstThunk) + (DWORD)g_dwImageBase);
			while(INTable->u1.AddressOfData)
			{
				if((((DWORD)INTable->u1.Function) & 0x80000000) == 0)
				{
					IatByName = (IMAGE_IMPORT_BY_NAME *)((DWORD)INTable->u1.AddressOfData + (DWORD)g_dwImageBase);
					IAT->u1.Function = (DWORD)g_GetProcAddress(lib , (char *)(IatByName->Name));
				}
				else
				{
					IAT->u1.Function = (DWORD)g_GetProcAddress(lib , (LPCSTR)(INTable->u1.Ordinal & 0xFFFF));
				}
				INTable++;
				IAT++;
			}
			pImportTable++;
		}
	}
}

//修复Exe重定位
void FixExeReloc()
{

	//以下是重定位
	DWORD *tmp;
	if(g_PackInfo.RelocRva)  //如果没有重定位表表示不用重定位，跳过重定位代码
	{
		DWORD relocation = (DWORD)g_dwImageBase - g_PackInfo.ImageBase;
		IMAGE_BASE_RELOCATION  *relocationAddress = (IMAGE_BASE_RELOCATION*)(g_PackInfo.RelocRva + (DWORD)g_dwImageBase);

		while(relocationAddress->VirtualAddress != 0)
		{
			LPVOID rva = (LPVOID)((DWORD)g_dwImageBase + relocationAddress->VirtualAddress);
			DWORD BlockNum = (relocationAddress->SizeOfBlock - 8) / 2;
			if(BlockNum == 0) break;
			WORD *Offset = (WORD *)((DWORD)relocationAddress + 8);
			for(int i = 0; i < (int)BlockNum; i++)
			{
				if((Offset[ i ] & 0xF000) != 0x3000) continue;
				tmp = (DWORD*)((Offset[ i ] & 0xFFF) + (DWORD)rva);
				*tmp = (*tmp) + relocation;
			}
			relocationAddress = (IMAGE_BASE_RELOCATION*)((DWORD)relocationAddress + relocationAddress->SizeOfBlock);
		}
	}
}

//解密
void Decryption()
{

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_dwImageBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_dwImageBase);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	// 找到.text段,并解密
	while(TRUE)
	{
		if(!strcmp((char*)pSection->Name , ".text"))
		{
			PCHAR pStart = pSection->VirtualAddress + (PCHAR)g_dwImageBase;
			for(int i = 0; i < pSection->Misc.VirtualSize; i++)
			{
				pStart[ i ] ^= 0x15;
			}
			break;
		}
		pSection = pSection + 1;
	}
}

//执行TLS回调
void TlsCallBackFun()
{
	
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_dwImageBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_dwImageBase);

	//如果TLS可以用，则调用TLS
	if (g_PackInfo.bIsTlsUserful == TRUE)
	{
		
		//将TLS回调函数表指针设置回去
		PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)
			(pNt->OptionalHeader.DataDirectory[9].VirtualAddress + g_dwImageBase);
		pTlsDir->AddressOfCallBacks = g_PackInfo.TlsCallbackFuncRva;

		PIMAGE_TLS_CALLBACK* lpTlsFun = (PIMAGE_TLS_CALLBACK*)
			(g_PackInfo.TlsCallbackFuncRva - pNt->OptionalHeader.ImageBase + g_dwImageBase);
		while ((*lpTlsFun) != NULL)
		{
			
			(*lpTlsFun)((PVOID)g_dwImageBase, DLL_PROCESS_ATTACH, NULL);	//启动一个新进程
			lpTlsFun++;
		}
	}
}





wchar_t g_wcbuf100[100] = { 0 };
wchar_t g_MIMA100[100] = L"000";
wchar_t wStrtext[100] = L"";

//验证密码
int CmpPassWord() {
	int a = 0;
	//wchar_t g_MIMA100[100] = L"haidragon"; // h68 a61 i69 d64   72	r  a61   67	g   6F	o   6E	n
	//wchar_t wStrtext[100] = L"请输入密码";*/
	__asm
	{
		push eax
		push ebx
		push ecx
		push edi
		push esi
		////////////////////////////////////////////////////////////
		mov ecx, 18
		mov edi, offset g_MIMA100;//正解密码
		mov esi, offset g_wcbuf100
			repz cmpsb
			je  T
			jmp F
			T :
		mov a, 1
			F :
			////////////////////////////////////////////////////////////
			pop esi
			pop edi
			pop ecx
			pop ebx
			pop eax
	}
	return a;
}

//窗口回调函数
LRESULT CALLBACK WindowProc(
	_In_ HWND	hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
	{
		//g_MessageBoxA(NULL, "窗口回调函数触发", "Tip", NULL);

		//创建文本框窗口==============================================================

		//窗口风格左对齐、子窗口、重叠窗口、最初可视
		DWORD dwStyle = ES_LEFT | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE;
		//扩展窗口风格
		DWORD dwExStyle = WS_EX_CLIENTEDGE | WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR;
		HWND hWnd = g_funCreateWindowEx(
			dwExStyle, //dwExStyle 扩展样式
			L"Edit", //lpClassName 窗口类名
			wStrtext, //lpWindowName 窗口标题
			dwStyle, //dwStyle 窗口样式
			150, //x 左边位置
			100, //y 顶边位置
			200, //nWidth 宽度
			20, //nHeight 高度
			hwnd, //hWndParent 父窗口句柄 
			(HMENU)0x1002, //ID
			g_GetModuleHandleA(0), //hInstance 应用程序句柄
			NULL //lpParam 附加参数
		);
		return 0;
	}
	case WM_COMMAND:
	{
		WORD wId = LOWORD(wParam);		//低字节 控件ID
		WORD wCode = HIWORD(wParam);	//高字节 控件码
		HANDLE hChild = (HANDLE)lParam;	
		
		//如果是点击确认密码按钮 0x1001按钮窗口ID
		if (wId == 0x1001 && wCode == BN_CLICKED)	
		{
			//获取文本框窗口句柄
			HWND hwndCombo = g_funGetDlgItem(hwnd, 0x1002);
			int cTxtLen = g_funGetWindowTextLength(hwndCombo);
			//获取文本框内容
			g_funGetWindowText(hwndCombo, g_wcbuf100, 100);

			//g_MessageBoxA(NULL, "按钮触发", "Tip", NULL);
			
			//验证密码
			if (CmpPassWord() == 1)
			{
				//验证通过
				g_funShowWindow(hwnd, SW_HIDE);	//隐藏窗口
				
				Decryption();		//解密
				FixExeReloc();		//修复exe重定位
				DealwithIAT();		
				TlsCallBackFun();
				_asm jmp g_oep;
			}
			else 
			{
				g_MessageBoxA(NULL, "密码错误", "PwError", NULL);
			}
			//清空文本框，等待下次输入
			g_funSetWindowText(hwndCombo, L"");
			return 1;
		}
		break;
	}
	case  WM_CLOSE:
	{
		//g_MessageBoxA(NULL, "close", "close", NULL);
		g_funExitProcess(0);
		//g_funPostQuitMessage(0);
		
		break;
	}
	case WM_DESTROY:
	{
		g_MessageBoxA(NULL, "destroy", "destroy", NULL);
		break;
	}

	}
	// 返回默认的窗口处理过程
	return g_funDefWindowProc(hwnd, uMsg, wParam, lParam);
}




void CreateWindows() {

	MSG msg = { 0 };
	//g_MessageBoxA(NULL, "new", "Tip", NULL);
	// 先注册窗口类
	WNDCLASS wcs = {};
	wcs.lpszClassName = L"password";		//窗口名
	wcs.lpfnWndProc = WindowProc;
	wcs.hbrBackground = (HBRUSH)(COLOR_GRAYTEXT+1);
	/////////////////////////////////////////////////////////////////////////////////////////
	g_funRegisterClass(&wcs);

//注册主窗口

//窗口类名一定要与上面的一致
	HWND hWnd = g_funCreateWindowEx(
		0L, 
		L"password",	//类名
		L"password",	//窗口名
		WS_OVERLAPPEDWINDOW | WS_VISIBLE,
		500, //x 左边位置
		200, //y 顶边位置
		500, //nWidth 宽度
		300, // nHeight 高度
		NULL, NULL, NULL, NULL);
	// 三种风格  WS_OVERLAPPEDWINDOW  WS_POPUPWINDOW  WS_CHILDWINDOW


	//创建按钮窗口
	g_funCreateWindowEx(0L, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE,
		200, 150,// 在父窗口的客户区的位置，
		100, 50,// 宽 高
		hWnd,// 父窗口
		(HMENU)0x1001,// 如果是顶层窗口 就是菜单句柄 子窗口就是本身的ID			  
		g_GetModuleHandleA(0), 
		NULL);

	g_funShowWindow(hWnd, SW_SHOW);
	g_funUpdateWindow(hWnd);
	
	while (g_funGetMessage(&msg, 0, 0, 0))
	{

		//DispatchMessage(&msg);
		g_funTranslateMessage(&msg);
		g_funDispatchMessage(&msg);
	}
}

//解压
void DeCompress()
{
	//1. 获取区段首地址
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)g_dwImageBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + g_dwImageBase);
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);

	//2. 解压缩区段
	PCHAR lpPacked = ((PCHAR)g_dwImageBase + g_PackInfo.packSectionRva);// 内存地址
	DWORD dwPackedSize = aPsafe_get_orig_size(lpPacked);// 获取解压后的大小
	PCHAR lpBuffer = (PCHAR)g_VirtualAlloc(NULL, dwPackedSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//申请内存
	aPsafe_depack(lpPacked, g_PackInfo.packSectionSize, lpBuffer, dwPackedSize);// 解压

																				// 3.将各区段还原回去
	DWORD offset = 0;
	for (int i = 0; i < g_PackInfo.PackSectionNumber; i++)
	{
		// 区段的标号
		int index = g_PackInfo.PackInfomation[i][0];
		// 这个区段的SizeOfRawData
		int size = g_PackInfo.PackInfomation[i][1];
		int * pint = &size;
		PCHAR destionVA = (PCHAR)g_dwImageBase + pSecHeader[index].VirtualAddress;
		PCHAR srcVA = lpBuffer + offset;
		_asm {
			mov eax, eax
			mov eax, eax
			mov eax, eax
			mov eax, eax
			mov eax, eax
			mov eax, eax
		}
		//memcpy(destionVA, srcVA, size);
		_asm {
			mov esi, srcVA
			mov edi, destionVA
			mov ebx, pint
			mov ecx, [ebx]
			cld; 地址增量传送
			rep movsb; rep执行一次串指令后ecx减一
		}
		offset += size;
	}
	g_VirtualFree(lpBuffer, dwPackedSize, MEM_DECOMMIT);
}





//混淆函数
void _stdcall FusedFunc(DWORD funcAddress)
{

	_asm
	{
		jmp label1
		label2 :
		_emit 0xeb; //跳到下面的call
		_emit 0x04;
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; //执行EB 02  也就是跳到下一句

														  //	call Init;// 获取一些基本函数的地址

														  // call下一条,用于获得eip
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		//-------跳到下面的call
		_emit 0xEB;
		_emit 0x0E;

		//-------花
		PUSH 0x0;
		PUSH 0x0;
		MOV EAX, DWORD PTR FS : [0];
		PUSH EAX;
		//-------花


		// fused:
		//作用push下一条语句的地址
		//pop eax;
		//add eax, 0x1b;
		/*push eax;*/
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];

		push funcAddress; //这里如果是参数传入的需要注意上面的add eax,??的??
		retn;

		jmp label3

			// 花
			_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		// 花


	label1:
		jmp label2
			label3 :
	}
}

// 壳程序
int g_num11 = 10;
void AllFunc()
{
	// 递归执行10次后执行壳程序
	if (!g_num11)
	{
		_asm
		{
			nop
			mov   ebp, esp
			push - 1
			push   0
			push   0
			mov   eax, fs:[0]
			push   eax
			mov   fs : [0], esp
			sub   esp, 0x68
			push   ebx
			push   esi
			push   edi
			pop   eax
			pop   eax
			pop   eax
			add   esp, 0x68
			pop   eax
			mov   fs : [0], eax
			pop   eax

			sub g_num11, 1

			pop   eax
			pop   eax
			pop   eax
			mov   ebp, eax

			push AllFunc
			call FusedFunc
		}
	}

	//获取API
	FusedFunc((DWORD)Init);

	// 压缩
	FusedFunc((DWORD)DeCompress);
	
	// 创建密码窗口
	FusedFunc((DWORD)CreateWindows);
}


_declspec(naked) void  Start()
{

	// 花指令
	_asm
	{
		PUSH - 1
		PUSH 0
		PUSH 0
		MOV EAX, DWORD PTR FS : [0]
		PUSH EAX
		MOV DWORD PTR FS : [0], ESP
		SUB ESP, 0x68
		PUSH EBX
		PUSH ESI
		PUSH EDI
		POP EAX
		POP EAX
		POP EAX
		ADD ESP, 0x68
		POP EAX
		MOV DWORD PTR FS : [0], EAX
		POP EAX
		POP EAX
		POP EAX
		POP EAX
		MOV EBP, EAX
	}

	// 执行壳
	FusedFunc((DWORD)AllFunc);

// 	
// 	Init();
// 	DeCompress();
// 	CreateWindows();
	
// 	Decryption();
// 	FixReloc();
// 	DealwithIAT();
	//TlsCallBackFun();
// 	_asm {
// 		jmp g_oep;
// 	}
}
