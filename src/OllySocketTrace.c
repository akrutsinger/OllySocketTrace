/******************************************************************************
 * OllySocketTrace - A rewritten Socket Tracer plugin for OllyDbg v2.01
 *
 * Rewritten by: Austyn Krutsinger
 *
 * Original OllySocketTrace by Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 *****************************************************************************/

/******************************************************************************
 * Things to change as I think of them...
 * [ ] = To do
 * [?] = Might be a good idea?
 * [!] = Implemented
 * [+] = Added
 * [-] = Removed
 * [*] = Changed
 * [~] = Almost there...
 *
 *
 * Version 0.1.0 (20NOV2014)
 * [+] Initial release
 *
 *
 * ----------------------------------------------------------------------------
 * TODO
 * ----------------------------------------------------------------------------
 *
 * [ ] graphical return values for send/receive functions in log view
 * [ ] View Data Trace - allow auto updating of trace dialog
 * [ ] rearrange source files into directories
 * [ ] ViewBufferInDump - change view if dump window is already created, otherwise make new dump window
 *
 *****************************************************************************/
#include <stdio.h>
#include "OllySocketTrace.h"
#include "Hooks.h"
#include "DlgSocketTrace.h"
#include "plugin.h"


#ifdef DEBUG
#include "MemCheck.h"
#endif /* DEBUG */

struct HOOK hooks[] = {
	// wininet.dll
	// InternetOpenUrl ...
	// HttpOpenRequest ...

	// mswsock.dll
	// AcceptEx
	// WSARecvEx
	// WSARecvMsg
	// TransmitFile
	// ConnectEx
	// DisconnectEx
	// TransmitPackets

	// ws2_32.dll
	// WSAIoctl
	// WSAJoinLeaf
	// WSARecvDisconnect
	// WSASendDisconnect
	// WSACloseEvent
	// WSASetEvent
	// WSACreateEvent
	// WSAResetEvent


	{ L"ws2_32",  "WSASocketA",		0, WSASocket_Call,		socket_Return		},
	{ L"ws2_32",  "WSASocketW",		0, WSASocket_Call,		socket_Return		},
	{ L"ws2_32",  "WSAAccept",		0, WSAAccept_Call,		accept_Return		},
	{ L"ws2_32",  "WSAConnect",		0, WSAConnect_Call,		DefaultINT_Return	},
	{ L"ws2_32",  "WSARecv",		0, WSARecv_Call,		WSARecv_Return		},
	{ L"ws2_32",  "WSARecvFrom",	0, WSARecvFrom_Call,	WSARecvFrom_Return	},
	{ L"ws2_32",  "WSASend",		0, WSASend_Call,		WSASend_Return		},
	{ L"ws2_32",  "WSASendTo",		0, WSASendTo_Call,		WSASend_Return		},
	{ L"ws2_32",  "WSAAsyncSelect",	0, WSAAsyncSelect_Call,	DefaultINT_Return	},
	{ L"ws2_32",  "WSAEventSelect",	0, WSAAsyncSelect_Call,	DefaultINT_Return	},
	{ L"ws2_32",  "WSACloseEvent",	0, WSACloseEvent_Call,	DefaultBOOL_Return	},


	{ L"ws2_32",  "listen",			0, listen_Call,			DefaultINT_Return	},
	{ L"ws2_32",  "ioctlsocket",	0, ioctlsocket_Call,	DefaultINT_Return	},
	{ L"ws2_32",  "connect",		0, connect_Call,		DefaultINT_Return	},
	{ L"ws2_32",  "bind",			0, bind_Call,			DefaultINT_Return	},
	{ L"ws2_32",  "accept",			0, accept_Call,			accept_Return		},
	{ L"ws2_32",  "socket",			0, socket_Call,			socket_Return		},
	{ L"ws2_32",  "closesocket",	0, closesocket_Call,	DefaultINT_Return	},
	{ L"ws2_32",  "shutdown",		0, shutdown_Call,		DefaultINT_Return	},
	{ L"ws2_32",  "recv",			0, recv_Call,			recv_Return			},
	{ L"ws2_32",  "recvfrom",		0, recvfrom_Call,		recvfrom_Return		},
	{ L"ws2_32",  "send",			0, send_Call,			DefaultINT_Return	},
	{ L"ws2_32",  "sendto",			0, sendto_Call,			DefaultINT_Return	},

	{ L"wsock32", "listen",			0, listen_Call,			DefaultINT_Return	},
	{ L"wsock32", "ioctlsocket",	0, ioctlsocket_Call,	DefaultINT_Return	},
	{ L"wsock32", "connect",		0, connect_Call,		DefaultINT_Return	},
	{ L"wsock32", "bind",			0, bind_Call,			DefaultINT_Return	},
	{ L"wsock32", "accept",			0, accept_Call,			accept_Return		},
	{ L"wsock32", "socket",			0, socket_Call,			socket_Return		},
	{ L"wsock32", "closesocket",	0, closesocket_Call,	DefaultINT_Return	},
	{ L"wsock32", "shutdown",		0, shutdown_Call,		DefaultINT_Return	},
	{ L"wsock32", "recv",			0, recv_Call,			recv_Return			},
	{ L"wsock32", "recvfrom",		0, recvfrom_Call,		recvfrom_Return		},
	{ L"wsock32", "send",			0, send_Call,			DefaultINT_Return	},
	{ L"wsock32", "sendto",			0, sendto_Call,			DefaultINT_Return	},

	{ NULL, NULL, 0, NULL, NULL }
};

/*
 * Plugin menu that will appear in the main OllyDbg menu
 * and in popup menu.
 */
static t_menu OllySocketTraceMainMenu[] = {
	{ L"&Enable/Disable",
		L"Enable or Disable Logging",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'E', MenuHandler, NULL, MENU_ENABLEDISABLE },
	{ L"&View Log",
		L"Open Log Window",
		KK_DIRECT|KK_CTRL|KK_SHIFT|'L', MenuHandler, NULL, MENU_VIEWLOG },
	{ L"|About",
		L"About OllySocketTrace",
		K_NONE, MenuHandler, NULL, MENU_ABOUT },
	/* End of menu. */
	{ NULL, NULL, K_NONE, NULL, NULL, 0 }
};

// pop-up menu that will appear in the log window. If
// item name has form >STANDARD, >FULLCOPY or >APPEARANCE, this item is a
// forwarder to the standard OllyDbg table menu or its part.
static t_menu LogWindowMenu[] = {
	{ L"Follow Caller In CPU Disasm",
		L"",
		K_NONE, MenuHandler, NULL, MENU_FOLLOW_IN_DISASM },
	{ L"View Dump of Buffer",
		L"",
		K_NONE, MenuHandler, NULL, MENU_VIEW_BUFFER_DUMP },
	{ L"View Data Packet for Socket",
		L"",
		K_NONE, MenuHandler, NULL, MENU_VIEW_TRACE_FOR_SOCKET },
	{ L"|Delete Entire Trace",
		L"",
		K_NONE, MenuHandler, NULL, MENU_DELETE_TRACE },
	{ L"Delete Socket From Trace",
		L"",
		K_NONE, MenuHandler, NULL, MENU_DELETE_SOCKET_FROM_TRACE },
	{ L"|>FULLCOPY",
		L"",                            // Forwarder to copy menus
		K_NONE, NULL, NULL, 0 }
};

struct COLORS
{
	BYTE	bColor;
	DWORD	dwSocket;
};

#define COLOR_COUNT		NCOLORS - 1
struct COLORS colors[COLOR_COUNT] = {0};

/* globals */
HINSTANCE		hDll		= NULL;
HANDLE			hMyHeap		= NULL;
volatile BOOL	bEnabled	= FALSE;
volatile DWORD	dwLogIndex	= 0;
t_table			logtable;		/* log table used for code cave data */


/*****************************************************************************/
/**
 *
 * Plugin specific functions
 *
 */
/*****************************************************************************/
LPVOID MyMalloc(DWORD dwSize)
{
	if (dwSize == 0) {
		return NULL;
	}
	return HeapAlloc(hMyHeap, HEAP_ZERO_MEMORY, dwSize);
}
/*****************************************************************************/
LPVOID MyReAlloc(LPVOID lpAddress, DWORD dwSize)
{
	if (lpAddress == NULL || dwSize == 0) {
		return NULL;
	}
	return HeapReAlloc(hMyHeap, 0, lpAddress, dwSize);
}
/*****************************************************************************/
BOOL MyFree(LPVOID lpAddress)
{
	if (lpAddress == NULL) {
		return FALSE;
	}
	return (BOOL)HeapFree(hMyHeap, 0, lpAddress);
}
/*****************************************************************************/
BOOL EnableBreakpoints(void)
{
	BOOL bSuccess = FALSE;
	int i = 0;
	int count = 0;
	t_module *pTempModule = NULL;
	wchar_t wszBuffer[SHORTNAME] = {0};

	/* get the address to the functions that will be hooked */
	UpdateHookFunctionsAddresses();

	while (hooks[i].pwszModuleName != NULL) {
		pTempModule = Findmodulebyname((wchar_t *)hooks[i].pwszModuleName);
		if (pTempModule == NULL) {
            Asciitounicode(hooks[i].pszFunctionName, SHORTNAME, wszBuffer, SHORTNAME);
			Addtolist(0, DRAW_HILITE, L"%s: Failed to find module %s.%s", OLLYST_NAME, hooks[i].pwszModuleName, wszBuffer);
		} else {
			if (hooks[i].dwFunctionAddress != 0) {
				Suspendallthreads();
				if (Setint3breakpoint(hooks[i].dwFunctionAddress, BP_TEMP, 0, 0, 0, BA_PERMANENT|BA_PLUGIN, NULL, NULL, NULL) == -1) {
					Asciitounicode(hooks[i].pszFunctionName, SHORTNAME, wszBuffer, SHORTNAME);
					Addtolist(0, DRAW_HILITE, L"%s: Failed to create a breakpoint for %s.%s", OLLYST_NAME, hooks[i].pwszModuleName, wszBuffer);
				} else {
					count++;
				}
				Resumeallthreads();
			}
		}
		i++;
	}

	if (count > 0) {
		bSuccess = TRUE;
	}

	if (bSuccess == FALSE) {
		DisableBreakpoints();
		Addtolist(0, DRAW_HILITE, L"%s: Failed to enable any of the required breakpoints", OLLYST_NAME);
	}
	return bSuccess;
}
/*****************************************************************************/
void DisableBreakpoints(void)
{
	int i = 0;

	while (hooks[i].pwszModuleName != NULL) {
		if (hooks[i].dwFunctionAddress != 0) {
			Suspendallthreads();
			Removeint3breakpoint(hooks[i].dwFunctionAddress, BP_TEMP);
			Resumeallthreads();
			hooks[i].dwFunctionAddress = 0;
		}
		i++;
	}
}
/*****************************************************************************/
BOOL BreakpointHandler(t_thread *pThread, t_reg *pRegisters)
{
	BOOL bHandleReturn = TRUE;
	int i = 0;
	LPLOGDATA pLogData = NULL;
	DWORD stack[NARG + 1] = { 0 };

	while (hooks[i].pwszModuleName != NULL) {
		if (pRegisters->ip == hooks[i].dwFunctionAddress) {
			pLogData = (LPLOGDATA)MyMalloc(sizeof(LOGDATA));
			if (pLogData == NULL) {
				break;
			}

			pLogData->dwAddress = dwLogIndex++;
			pLogData->dwSize = 1;
			pLogData->iHookIndex = i;
			pLogData->dwThreadId = pThread->threadid;

			if (Readmemory(&pLogData->dwCallerBreakpointAddr, pRegisters->r[REG_ESP], 4, MM_SILENT) == 0) {
				MyFree(pLogData);
				pLogData = NULL;
				break;
			}

			if (Readmemory(stack, pRegisters->r[REG_ESP], sizeof(stack), MM_SILENT) == 0) {
				MyFree(pLogData);
				pLogData = NULL;
				break;
			}
			pLogData->dwCallerAddress = Isretaddr(stack[0], NULL);

			if (hooks[i].handle_call != NULL) {	/* make sure function has a hook function */
				if (hooks[i].handle_call(pLogData, pRegisters) == TRUE) {
					if (hooks[i].handle_return != NULL) {
						Suspendallthreads();
						/* set breakpoint at command following calling address */
						/* to get the return value later */
						Setint3breakpoint(pLogData->dwCallerBreakpointAddr, BP_TEMP, 0, 0, 0, BA_PLUGIN, NULL, NULL, NULL);
						Resumeallthreads();
					}
					Addsorteddata(&(logtable.sorted), pLogData);
					bHandleReturn = FALSE;
				}
			}
			/* ensure pLogData is freed */
			MyFree(pLogData);
			pLogData = NULL;
			/* found the API call currently in the program Instruction Pointer */
			/* no need to continue searching the hook list */
			break;
		}
		i++;
	}

	/* Check for return value */
	if (bHandleReturn == TRUE) {
		pLogData = (LPLOGDATA)logtable.sorted.data;
		for (i = 0; i < logtable.sorted.n; i++) {
			if (pRegisters->ip == pLogData[i].dwCallerBreakpointAddr &&
				pLogData[i].bReturnMessageSet == FALSE) {
					if (hooks[pLogData[i].iHookIndex].handle_return != NULL) {
						pLogData[i].bReturnMessageSet = hooks[pLogData[i].iHookIndex].handle_return(&pLogData[i], pRegisters);
					}
					bHandleReturn = FALSE;
					break;
				}
		}
	}

	return bHandleReturn;
}
/*****************************************************************************/
void UpdateHookFunctionsAddresses(void)
{
	int i = 0;
	HMODULE hModule = NULL;

	while (hooks[i].pwszModuleName != NULL) {
		hModule = GetModuleHandle(hooks[i].pwszModuleName);
		if (hModule == NULL) {
			break;
		} else {
			hooks[i].dwFunctionAddress = (DWORD)GetProcAddress(hModule, (LPCSTR)hooks[i].pszFunctionName);
		}
		i++;
	}
}
/*****************************************************************************/
void DisplayAboutMessage(void)
{
	wchar_t wszMessage[TEXTLEN] = { 0 };
	wchar_t wszBuffer[SHORTNAME];
	int n;

	Resumeallthreads();

	n = StrcopyW(wszMessage, TEXTLEN, OLLYST_NAME);
	n = StrcopyW(wszMessage, TEXTLEN, L" v");
	n += StrcopyW(wszMessage + n, TEXTLEN - n, OLLYST_VERSION);
	n += StrcopyW(wszMessage + n, TEXTLEN - n, L"\n\nCoded by Austyn Krutsinger <akrutsinger@gmail.com>");
	n += StrcopyW(wszMessage + n, TEXTLEN - n, L"\nOriginal by Stephen Fewer");
	n += StrcopyW(wszMessage + n, TEXTLEN - n, L"\n\nCompiled on ");
	Asciitounicode(__DATE__, SHORTNAME, wszBuffer, SHORTNAME);
	n += StrcopyW(wszMessage + n, TEXTLEN - n, wszBuffer);
	n += StrcopyW(wszMessage + n, TEXTLEN - n, L" ");
	Asciitounicode(__TIME__, SHORTNAME, wszBuffer, SHORTNAME);
	n += StrcopyW(wszMessage + n, TEXTLEN - n, wszBuffer);

	MessageBox(hwollymain, wszMessage, L"About OllySocketTrace", MB_OK|MB_ICONINFORMATION);

	Suspendallthreads();
}
/*****************************************************************************/
void FollowCallerInDisasm(t_table *pTable)
{
	LPLOGDATA pLogData = NULL;
	pLogData = (LPLOGDATA)Getsortedbyselection(&pTable->sorted, pTable->sorted.selected);
	if (pLogData != NULL) {
		Setcpu(0, pLogData->dwCallerAddress, 0, 0, 0, CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS);
	}
}
/*****************************************************************************/
/* Create new dump window to view buffer data or change selection of already
 * created dump data
 */
void ViewBufferInDump(t_table *pTable)
{
	LPLOGDATA pLogData = NULL;
	pLogData = (LPLOGDATA)Getsortedbyselection(&pTable->sorted, pTable->sorted.selected);

	/* TODO: if dump window already opened, change selection of that window */

	/* dwDbgBuffer points to parameter data */
	Createdumpwindow(L"OllySocketTrace - Dump Buffer", pLogData->dwDbgBuffer, pLogData->dwDbgBufferSize, NULL, DUMP_HEXA16|DMT_FIXTYPE, pLogData->dwDbgBuffer, 0, NULL);
}
/*****************************************************************************/
/* Displays the packet trace for the selected sockets data */
void ViewDataTrace(t_table *pTable)
{
	TraceDialog_Create(hDll, pTable);
}
/*****************************************************************************/
void DeleteEntireTrace(void)
{
	int i;
	LPLOGDATA pLogData = NULL;

	Resumeallthreads();
	if (MessageBox(hwollymain, L"Delete entire trace?", L"OllySocketTrace - Delete trace", MB_YESNO | MB_ICONQUESTION) == IDYES) {
		/* make sure any allocated buffers are cleared before removing from log */
		pLogData = (LPLOGDATA)logtable.sorted.data;
		for (i = 0; i < logtable.sorted.n; i++) {
			if (pLogData[i].lpOllyBuffer != NULL) {
				MyFree(pLogData[i].lpOllyBuffer);
				pLogData[i].lpOllyBuffer = NULL;
			}
		}

		Deletesorteddatarange(&(logtable.sorted), 0x00000000, 0xFFFFFFFF);
	}
	Suspendallthreads();
}
/*****************************************************************************/
void DeleteSocketFromTrace(t_table *pTable)
{
	LPLOGDATA pLogData = NULL;
	wchar_t wszBuffer[BUFFER_SIZE];
	int i;

	pLogData = (LPLOGDATA)Getsortedbyselection(&pTable->sorted, pTable->sorted.selected);

	Resumeallthreads();
	snwprintf(wszBuffer, BUFFER_SIZE, L"Delete the trace for socket %d?", pLogData->dwSocket);
	if (MessageBox(hwollymain, wszBuffer, L"OllySocketTrace - Delete socket", MB_YESNO | MB_ICONQUESTION) == IDYES) {
		DWORD dwSocket = pLogData->dwSocket;
		pLogData = (LPLOGDATA)logtable.sorted.data;
		for (i = 0; i < logtable.sorted.n; i++) {
			if (pLogData[i].dwSocket == dwSocket) {
				if (pLogData[i].lpOllyBuffer != NULL) {
					MyFree(pLogData[i].lpOllyBuffer);
					pLogData[i].lpOllyBuffer = NULL;
				}
				Deletesorteddata(&(logtable.sorted), pLogData[i].dwAddress, 0);
				i = -1;
				continue;
			}
		}
	}
	Suspendallthreads();
}
/*****************************************************************************/
int MenuHandler(t_table* pTable, wchar_t* pwszName, DWORD dwIndex, int iMode)
{
	UNREFERENCED_PARAMETER(pwszName);

	switch (iMode) {
	case MENU_VERIFY:
		return MENU_NORMAL;

	case MENU_EXECUTE:
		switch (dwIndex) {
		case MENU_ENABLEDISABLE:
			if (bEnabled == TRUE) {
				bEnabled = FALSE;
			} else {
				bEnabled = TRUE;
			}

			if (bEnabled == TRUE) {
				bEnabled = EnableBreakpoints();
			} else {
				DisableBreakpoints();
			}
			Flash(L"%s %s.", OLLYST_NAME, (bEnabled ? L"Enabled" : L"Disabled"));
			break;
		case MENU_VIEWLOG:
			if (logtable.hw == NULL) {
				Createtablewindow(&logtable, 0, logtable.bar.nbar, NULL, L"ICO_PLUGIN", OLLYST_NAME);
			} else {
				Activatetablewindow(&logtable);
			}
			break;
		case MENU_FOLLOW_IN_DISASM:
			FollowCallerInDisasm(pTable);
			break;
		case MENU_VIEW_BUFFER_DUMP:
			ViewBufferInDump(pTable);
			break;
		case MENU_VIEW_TRACE_FOR_SOCKET:
			ViewDataTrace(pTable);
			break;
		case MENU_DELETE_TRACE:
			DeleteEntireTrace();
			break;
		case MENU_DELETE_SOCKET_FROM_TRACE:
			DeleteSocketFromTrace(pTable);
			break;
		case MENU_ABOUT:
			DisplayAboutMessage();
			break;
		default:
			break;
		}
		return MENU_NOREDRAW;
	default:
		break;
	}

	return MENU_ABSENT;
}
/*****************************************************************************/
void CreateLogWindow(void)
{
	StrcopyW(logtable.name, SHORTNAME, OLLYST_NAME);
	logtable.mode = TABLE_SAVEPOS|TABLE_AUTOUPD;
	logtable.bar.visible = 1;

	logtable.bar.name[0] = L"Caller";
	logtable.bar.expl[0] = L"";
	logtable.bar.mode[0] = BAR_FLAT;
	logtable.bar.defdx[0] = 20;

	logtable.bar.name[1] = L"Thread";
	logtable.bar.expl[1] = L"";
	logtable.bar.mode[1] = BAR_FLAT;
	logtable.bar.defdx[1] = 10;

	logtable.bar.name[2] = L"Function Call";
	logtable.bar.expl[2] = L"";
	logtable.bar.mode[2] = BAR_FLAT;
	logtable.bar.defdx[2] = 56;

	logtable.bar.name[3] = L"Return Value";
	logtable.bar.expl[3] = L"";
	logtable.bar.mode[3] = BAR_FLAT;
	logtable.bar.defdx[3] = 14;

	logtable.bar.name[4] = L"Hint";
	logtable.bar.expl[4] = L"";
	logtable.bar.mode[4] = BAR_FLAT;
	logtable.bar.defdx[4] = 48;

	logtable.bar.nbar = 5;
	logtable.tabfunc = (TABFUNC*)LogWindowProc;
	logtable.custommode = 0;
	logtable.customdata = NULL;
	logtable.updatefunc = NULL;
	logtable.drawfunc = (DRAWFUNC*)LogWindowGetText;
	logtable.tableselfunc = NULL;
	logtable.menu = LogWindowMenu;
}
/*****************************************************************************/
void InitializeColors(void)
{
	int i;
	for (i = 0; i < COLOR_COUNT; i++) {
		colors[i].bColor = i + 1;
		colors[i].dwSocket = 0;
	}
	colors[COLOR_COUNT-1].bColor = BLACK;
}
/*****************************************************************************/
BYTE GetColor(DWORD dwSocket)
{
	int i;
	for (i = 0; i < COLOR_COUNT; i++) {
		if(colors[i].dwSocket == dwSocket) {
			return colors[i].bColor;
		}
	}
	for (i = 0; i < COLOR_COUNT; i++) {
		if (colors[i].dwSocket == 0) {
			colors[i].dwSocket = dwSocket;
			return colors[i].bColor;
		}
	}
	return GRAY;
}
/*****************************************************************************/
long LogWindowGetText(wchar_t *pwszBuffer, uchar *pMask, int *pSelect, t_table *pTable, t_drawheader *pHeader, int iColumn, void *pCache)
{
	UNREFERENCED_PARAMETER(pTable);
	UNREFERENCED_PARAMETER(pCache);

	int	i = 0;
	LPLOGDATA pLogData = (LPLOGDATA)pHeader;

	/* If there is no header, don't do anything */
	if (pLogData == NULL) {
		return i;
	}

	BYTE bColor = GetColor(pLogData->dwSocket);

	switch (iColumn) {
	case 0:	/* caller address */
		*pSelect = DRAW_GRAY;
		i = Decodeaddress(pLogData->dwCallerAddress, 0, DM_VALID|DM_INMOD|DM_WIDEFORM|DM_MODNAME, pwszBuffer, BUFFER_SIZE, NULL);
		break;
	case 1: /* thread id */
		*pSelect = DRAW_GRAY;
		i = snwprintf(pwszBuffer, BUFFER_SIZE, L"%.8X", pLogData->dwThreadId);
		break;
	case 2:	/* called hooked function with parameters */
		i = snwprintf(pwszBuffer, BUFFER_SIZE, L"%s", pLogData->wszMessage);
		*pSelect = DRAW_MASK;
		memset(pMask, DRAW_NORMAL|bColor, i);
		break;
	case 3:	/* return message */
		if (wcslen(pLogData->wszReturnMessage) > 0) {
			i = snwprintf(pwszBuffer, BUFFER_SIZE, L"%s", pLogData->wszReturnMessage);
			*pSelect = DRAW_MASK;
			memset(pMask, DRAW_NORMAL|bColor, i);
		}
		break;
	case 4:	/* hint about called hooked function */
		*pSelect = DRAW_GRAY;
		i = snwprintf(pwszBuffer, BUFFER_SIZE, L"%s", pLogData->wszHint);
		break;
	default:
		break;
	}
	return i;
}
/*****************************************************************************/
long LogWindowProc(t_table *pTable, HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(hWnd);
	UNREFERENCED_PARAMETER(wParam);
	UNREFERENCED_PARAMETER(lParam);

	switch (uMsg)
	{
	case WM_USER_UPD:
	case WM_USER_CHGALL:
	case WM_USER_CHGMEM:
		InvalidateRect(pTable->hw, NULL, FALSE);
		break;
	case WM_USER_DBLCLK:
		FollowCallerInDisasm(pTable);
		return 1;
	case WM_USER_CREATE:
		Setautoupdate(&logtable, 1);
		break;
	default:
		break;
	}
	return 0;
}
/*****************************************************************************/
/**
 *
 * OllyDbg internal functions
 *
 */
/*****************************************************************************/
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(lpReserved);

	if (fdwReason == DLL_PROCESS_ATTACH) {
		hDll = hinstDll;		/* Save plugin instance */
	}
	return 1;					/* Report success */
}
/*****************************************************************************/
extc int __cdecl ODBG2_Pluginquery(int iOllyDbgVersion, DWORD *dwFeatures, wchar_t wszPluginName[SHORTNAME], wchar_t wszPluginVersion[SHORTNAME])
{
	UNREFERENCED_PARAMETER(dwFeatures);

	if (iOllyDbgVersion < 201) {
		return 0;
	}
	/* Report name and version to OllyDbg */
	StrcopyW(wszPluginName, SHORTNAME, OLLYST_NAME);
	StrcopyW(wszPluginVersion, SHORTNAME, OLLYST_VERSION);
	return PLUGIN_VERSION;			/* Expected API version */
}
/*****************************************************************************/
extc int __cdecl ODBG2_Plugininit(void)
{
	hMyHeap = HeapCreate(0, 4096, 0);
	if (hMyHeap == NULL) {
		Addtolist(0, DRAW_HILITE, L"%s: Failed to create internal heap", OLLYST_NAME);
		return -1;
	}

	memset(&logtable.sorted, 0, sizeof(t_sorted));
	if (Createsorteddata(&(logtable.sorted), sizeof(LOGDATA), 1, NULL, NULL, 0) == -1) {
		Addtolist(0, DRAW_HILITE, L"%s: Unable to created sorted table data.", OLLYST_NAME);
		return -1;
	}

	CreateLogWindow();
	InitializeColors();

	bEnabled = FALSE;

	Addtolist(0, DRAW_NORMAL, L"[*] %s v%s by Austyn Krutsinger <akrutsinger@gmail.com>", OLLYST_NAME, OLLYST_VERSION);
	Addtolist(0, DRAW_NORMAL, L"[*] Original plugin by: Stephen Fewer");

	/* Report success. */
	return 0;
}
/*****************************************************************************/
void ODBG2_Pluginnotify(int iCode, void *pData, DWORD dwParam1, DWORD dwParam2)
{
	UNREFERENCED_PARAMETER(pData);
	UNREFERENCED_PARAMETER(dwParam1);
	UNREFERENCED_PARAMETER(dwParam2);

	switch (iCode) {
	case PN_NEWMOD:
		if (bEnabled == TRUE) {
			UpdateHookFunctionsAddresses();
		}
		break;
	default:
		break;
	}
}
/*****************************************************************************/
void ODBG2_Plugintempbreakpoint(DWORD dwAddress, const t_disasm *pDisasm, t_thread *pThread, t_reg *pRegisters)
{
	UNREFERENCED_PARAMETER(dwAddress);
	UNREFERENCED_PARAMETER(pDisasm);

	if (bEnabled == TRUE && pRegisters != NULL) {
		BreakpointHandler(pThread, pRegisters);
	}
}
/*****************************************************************************/
extc t_menu * __cdecl ODBG2_Pluginmenu(wchar_t *pwszType)
{
	if (wcscmp(pwszType, PWM_MAIN) == 0) {
		/* Main menu. */
		return OllySocketTraceMainMenu;
	}
	return NULL;                /* No menu */
}
/*****************************************************************************/
extc void __cdecl ODBG2_Pluginreset(void)
{
	int i;
	LPLOGDATA pLogData = NULL;
	bEnabled = FALSE;

	pLogData = (LPLOGDATA)logtable.sorted.data;
	for (i = 0; i < logtable.sorted.n; i++) {
		if (pLogData[i].lpOllyBuffer != NULL ) {
			MyFree(pLogData[i].lpOllyBuffer);
			pLogData[i].lpOllyBuffer = NULL;
		}
	}

	Deletesorteddatarange(&(logtable.sorted), 0x00000000, 0xFFFFFFFF);

	DisableBreakpoints();

	#ifdef DEBUG
		report_mem_leak();
	#endif

	// don't destroy heap on reset
}
/*****************************************************************************/
extc void __cdecl ODBG2_Plugindestroy(void)
{
	int i;
	LPLOGDATA pLogData = NULL;

	pLogData = (LPLOGDATA)logtable.sorted.data;
	for (i = 0; i < logtable.sorted.n; i++) {
		if (pLogData[i].lpOllyBuffer != NULL ) {
			MyFree(pLogData[i].lpOllyBuffer);
			pLogData[i].lpOllyBuffer = NULL;
		}
	}

	Destroysorteddata(&(logtable.sorted));

	DisableBreakpoints();

	HeapDestroy(hMyHeap);

	#ifdef DEBUG
		report_mem_leak();
	#endif
}
/*****************************************************************************/
