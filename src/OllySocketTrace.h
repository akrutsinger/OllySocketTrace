/******************************************************************************
 * OllySocketTrace - A rewritten Socket Tracer plugin for OllyDbg v2.01
 *
 * Rewritten by: Austyn Krutsinger
 *
 * Original OllySocketTrace by Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 *****************************************************************************/
#ifndef __OLLYSOCKETTRACE_H__
#define __OLLYSOCKETTRACE_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "plugin.h"


/*  To use this exported function of dll, include this header
 *  in the project.
 */
#ifdef BUILD_DLL
    #define DLL_EXPORT __declspec(dllexport)
#else
    #define DLL_EXPORT __declspec(dllimport)
#endif

#define OLLYST_NAME			L"OllySocketTrace"  /* Unique plugin name */
#define OLLYST_VERSION		L"0.1.0"            /* Plugin version (stable . update . patch  - status) */

/* Menu items */
#define MENU_ENABLEDISABLE				1
#define	MENU_VIEWLOG					2
#define	MENU_ABOUT						3
#define MENU_FOLLOW_IN_DISASM			4
#define MENU_VIEW_BUFFER_DUMP			5
#define MENU_VIEW_TRACE_FOR_SOCKET		6
#define MENU_DELETE_TRACE				7
#define MENU_DELETE_SOCKET_FROM_TRACE	8

#define BUFFER_SIZE				256

/* Global Declarations */


/**
 * Forward declarations
 */
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved);

LPVOID MyMalloc(DWORD dwSize);
LPVOID MyReAlloc(LPVOID lpAddress, DWORD dwSize);
BOOL MyFree(LPVOID lpAddress);
BOOL EnableBreakpoints(void);
void DisableBreakpoints(void);
BOOL BreakpointHandler(t_thread *pThread, t_reg *pRegisters);
void UpdateHookFunctionsAddresses(void);
void FollowCallerInDisasm(t_table *pTable);
void ViewBufferInDump(t_table *pTable);
void ViewDataTrace(t_table *pTable);
void DeleteEntireTrace(void);
void DeleteSocketFromTrace(t_table *pTable);

 /* Menu functions */
int MenuHandler(t_table* pTable, wchar_t* pwszName, DWORD dwIndex, int iMode);
void DisplayAboutMessage(void);

/* Log window functions */
void CreateLogWindow(void);
long LogWindowProc(t_table *pTable, HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
long LogWindowGetText(wchar_t *pwszBuffer, uchar *pMask, int *pSelect, t_table *pTable, t_drawheader *pHeader, int iColumn, void *pCache);

void InitializeColors(void);
BYTE GetColor(DWORD dwSocket);

#ifdef DEVELOPMENT_MODE
void test_code(void);
#endif

typedef struct _LOGDATA {
	/* Obligatory header, its layout _must_ coincide with t_sorthdr! */
	DWORD	dwAddress;	/* address of the call */
	DWORD	dwSize;		/* Size of index, always 1 in our case */
	DWORD	dwType;		/* Type of entry, TY_xxx */

	/* Custom data follows header. */
	DWORD	dwCallerAddress;		/* address of the caller */
	DWORD	dwCallerBreakpointAddr;	/* command after call; use to set breakpoint in order to read return value */
	DWORD	dwThreadId;				/* id of caller thread */

	DWORD	dwSocket;

	DWORD	dwDbgBuffer;			/* address of buffer, if any, in debugged process */
	DWORD	dwDbgBufferSize;		/* size of said buffer in debugged process */

	LPVOID	lpOllyBuffer;			/* a malloc'd buffer in OllyDbg's address space */
	DWORD	dwOllyBufferSize;		/* size of said buffer in OllyDbg's address space */

	wchar_t	wszMessage[BUFFER_SIZE];		/* information about called hooked function */
	wchar_t	wszReturnMessage[BUFFER_SIZE];	/* return data */
	wchar_t	wszHint[BUFFER_SIZE];			/* helpful information on the called hooked function */
	BOOL	bReturnMessageSet;				/* whether there was a return message or not */
	int		iHookIndex;						/* index of hook */

	DWORD	dwValueA;
	DWORD	dwValueB;
	DWORD	dwValueC;
} LOGDATA, *LPLOGDATA;

#endif	/* __OLLYSOCKETTRACE_H__ */
