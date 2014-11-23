/******************************************************************************
 * OllySocketTrace - A rewritten Socket Tracer plugin for OllyDbg v2.01
 *
 * Rewritten by: Austyn Krutsinger
 *
 * Original OllySocketTrace by Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 *****************************************************************************/
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

#include "DlgSocketTrace.h"

/*****************************************************************************/
HWND	hWnd			= NULL;
wchar_t	*g_wszTraceText	= NULL;
LPLOGDATA g_selected_socket_data	= NULL;
t_table	*g_socket_table	= NULL;
/*****************************************************************************/
void PrintHex(wchar_t *wszOutput, DWORD dwOutputSize, BYTE *pBuffer, int size)
{
	#define BUFFSIZE 128
	int x, y;
	wchar_t wszBuff[BUFFSIZE];

	memset(wszBuff, 0, BUFFSIZE);
	memset(wszOutput, 0, dwOutputSize);
	dwOutputSize -= 4;

	if (size > 0xFFFF) {
		/* return error some some kind */
		Addtolist(0, DRAW_HILITE, L"buffer size too big to support");
		return;
	}

	/* Print the first offset line header */
	snwprintf(wszBuff, BUFFSIZE, L"%04X  ", 0);
	wcsncat(wszOutput, wszBuff, dwOutputSize);

	for (x = 1; x <= size; x++) {
		/* print the hex value */
		snwprintf(wszBuff, BUFFSIZE, L"%02X ", pBuffer[x-1]);
		wcsncat(wszOutput, wszBuff, dwOutputSize);

		if (x % 16 == 0) {
			/* We're at the end of a line of hex, print the printable characters */
			wcsncat(wszOutput, L" ", dwOutputSize);
			/* loop back through last 16 bytes of data to print character */
			for (y = x - 15; y <= x; y++) {
				/* if it's printable, print it otherwise substitute a period */
				if (iswprint(pBuffer[y-1])) {
					snwprintf(wszBuff, BUFFSIZE, L"%lc", pBuffer[y-1]);
					wcsncat(wszOutput, wszBuff, dwOutputSize);
				}
				else {
					wcsncat(wszOutput, L".", dwOutputSize);
				}
			}

			if (x < size) {
				/* Print an offset line header for the next line to be printed */
				snwprintf(wszBuff, BUFFSIZE, L"\r\n%04X  ", x);
				wcsncat(wszOutput, wszBuff, dwOutputSize);
			}
		}
	}
	x--;

	/* If we didn't end on a 16 byte boundary, print some placeholder spaces before printing the characters */
	if (x % 16 != 0) {
		for (y = x + 1; y <= x + (16-(x % 16)); y++) {
			 /* placeholder spacing between hex values and characters */
			wcsncat(wszOutput, L"   ", dwOutputSize);
		}

		/* print the printable characters */
		wcsncat(wszOutput, L" ", dwOutputSize);
		for (y = (x + 1) - (x % 16); y <= x; y++) {
			/* if it's printable, print it otherwise substitute a period */
			if (iswprint(pBuffer[y-1])) {
				snwprintf(wszBuff, BUFFSIZE, L"%lc", pBuffer[y-1]);
				wcsncat(wszOutput, wszBuff, dwOutputSize);
			} else {
				wcsncat(wszOutput, L".", dwOutputSize);
			}
		}
	}

	wcsncat(wszOutput, L"\r\n", dwOutputSize);
}
/*****************************************************************************/
LRESULT CALLBACK DlgProc(HWND hWndDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);

	static HWND hEditText = NULL;
	HFONT hFont = NULL;

	switch(Msg)
	{
		case WM_INITDIALOG:
			hEditText = GetDlgItem(hWndDlg, IDC_EDIT_TRACE);

			if(hEditText) {

				HDC hdc = GetDC(NULL);
				long height = -MulDiv(10, GetDeviceCaps(hdc, LOGPIXELSY), 72);
				ReleaseDC(NULL, hdc);

				hFont = CreateFont(height, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, L"Courier New");

				SendMessage(hEditText, WM_SETFONT, (WPARAM)hFont, TRUE);

				/* set text limit to the maximum windows NT/2000/XP can support */
				SendMessage(hEditText, EM_SETLIMITTEXT, (WPARAM)0x7FFFFFFE, 0);

				int ret = TraceDialog_FormatTrace(hEditText, (LPLOGDATA)g_socket_table->sorted.data, g_socket_table->sorted.n, g_selected_socket_data->dwSocket);
				if (ret == FALSE) {
					MessageBox(hwollymain, L"No data to display.", L"OllySocketTrace - Data Trace", MB_OK | MB_ICONINFORMATION);
					EndDialog(hWndDlg, 0);
				}
			}
			return TRUE;

		case WM_COMMAND:
			switch(wParam)
			{
				case ID_CLOSE:
					EndDialog(hWndDlg, 0);
					return TRUE;
				default:
					break;
			}
			break;
		case WM_CLOSE:
			EndDialog(hWndDlg, 0);
			break;
		default:
			break;
	}
	return FALSE;
}
/*****************************************************************************/
BOOL TraceDialog_Create(HINSTANCE hInstance, t_table *pTable)
{
	int ret = TRUE;

	/* set the global variables */
	g_socket_table = pTable;
	g_selected_socket_data = (LPLOGDATA)Getsortedbyselection(&g_socket_table->sorted, g_socket_table->sorted.selected);

	if (!DialogBox(hInstance, MAKEINTRESOURCE(IDD_DATA_TRACE), hWnd, (DLGPROC)DlgProc)) {
		ret = FALSE;
	}

	return ret;
}
/*****************************************************************************/
void append_log_text(HWND edit_control, wchar_t *new_text)
{
	DWORD left;
	DWORD right;
	int text_len;

	SendMessage(edit_control, EM_GETSEL,(WPARAM)&left,(LPARAM)&right);
	text_len = GetWindowTextLength(edit_control);
    SendMessage(edit_control, EM_SETSEL, text_len, text_len);
	SendMessage(edit_control, EM_REPLACESEL, 0, (LPARAM)new_text);
	SendMessage(edit_control, EM_SETSEL,left,right);
}
/*****************************************************************************/
BOOL TraceDialog_FormatTrace(HWND edit_control, LPLOGDATA pLogData, int iCount, DWORD dwSocket)
{
    int i = 0;
    int ret = TRUE;
    int iPacketCount	= 0;
    wchar_t *wszBuffer	= NULL;
    DWORD dwBuffSize	= 0;

	for (i = 0 ; i < iCount ; i++) {
		if (pLogData[i].dwSocket == dwSocket && pLogData[i].lpOllyBuffer != NULL && pLogData[i].dwOllyBufferSize > 0) {
			/*
			 * 0000  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa\r\n
			 * WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWBB
			 *			71 wide characters plus 2 bytes (\r\n) per line
			 *
			 *	(71 * sizeof(wchar_t)) + 2 per line
			 *
			 * number_of_lines = (buffer_length / 16 bytes)
			 */
			dwBuffSize = ((pLogData[i].dwOllyBufferSize / 16) + 1) * 73 * sizeof(wchar_t);
			wszBuffer = (wchar_t *)MyMalloc(dwBuffSize);

			if (wszBuffer != NULL) {
				iPacketCount++;

				PrintHex(wszBuffer, dwBuffSize, pLogData[i].lpOllyBuffer, pLogData[i].dwOllyBufferSize);

				wchar_t wszHeader[TEXTLEN];
				snwprintf(wszHeader, TEXTLEN, L"\r\n----[ %ls == %ls\r\n", pLogData[i].wszMessage, pLogData[i].wszReturnMessage);
				append_log_text(edit_control, wszHeader);
				append_log_text(edit_control, wszBuffer);

				MyFree(wszBuffer);
				wszBuffer = NULL;
			}
		}
	}

	if (iPacketCount == 0) {
		ret = FALSE;
	}

	return ret;
}
/*****************************************************************************/
