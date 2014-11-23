/******************************************************************************
 * OllySocketTrace - A rewritten Socket Tracer plugin for OllyDbg v2.01
 *
 * Rewritten by: Austyn Krutsinger
 *
 * Original OllySocketTrace by Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 *****************************************************************************/
#ifndef __DLGSOCKETTRACE_H__
#define __DLGSOCKETTRACE_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "resource.h"
#include "Hooks.h"

void PrintHex(wchar_t *cpOutput, DWORD dwOutputSize, BYTE *pBuffer, int size);
LRESULT CALLBACK DlgProc(HWND hWndDlg, UINT Msg, WPARAM wParam, LPARAM lParam);
void append_log_text(HWND edit_control, wchar_t *new_text);
BOOL TraceDialog_Create(HINSTANCE hInstance, t_table *pTable);
BOOL TraceDialog_FormatTrace(HWND edit_control, LPLOGDATA pLogData, int iCount, DWORD dwSocket);


#endif /* DLGSOCKETTRACE_H_INCLUDED */
