/******************************************************************************
 * OllySocketTrace - A rewritten Socket Tracer plugin for OllyDbg v2.01
 *
 * Rewritten by: Austyn Krutsinger
 *
 * Original OllySocketTrace by Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 *****************************************************************************/
#ifndef __OLLYSOCKETTRACE_HOOKS_H__
#define __OLLYSOCKETTRACE_HOOKS_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#include "OllySocketTrace.h"

/* since winsock2.h doesn't have them */
#define AF_TCNPROCESS   29
#define AF_TCNMESSAGE   30
#define AF_ICLFXBM      31

#define SIZE_THRESHOLD		0x0000FFFF	/* 65535 bytes */

/* forward declarations */
struct FLAGS;
enum record_reason;

/*
 * Prototypes
 */
VOID ResolveFlags(struct FLAGS *pFlags, BOOL bORed, DWORD dwFlags, wchar_t *pwszOutput);
BOOL record_sockaddr(LPLOGDATA pLogData, enum record_reason reason, DWORD dwpSockAddr, DWORD dwSockAddrLength, DWORD dwNumberBytesUsed);
BOOL record_buffer(LPLOGDATA pLogData, DWORD dwThreshold );

/*
 * WSA Hooks
 */
BOOL WSASocket_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSAAccept_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSAConnect_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSARecv_Return(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSARecv_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSASend_Return(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSASend_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSAAsyncSelect_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSAEventSelect_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSACloseEvent_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSASendTo_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSARecvFrom_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL WSARecvFrom_Return(LPLOGDATA pLogData, t_reg *pRegisters);

/*
 * ws2_32.dll and mswsock.dll Hooks
 */

//BOOL DefaultDWORD_Return(LPLOGDATA, t_reg *, t_reg *pRegisters);
BOOL DefaultBOOL_Return(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL DefaultINT_Return(LPLOGDATA pLogData, t_reg *pRegisters);

BOOL listen_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL ioctlsocket_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL connect_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL bind_Call(LPLOGDATA pLogData, t_reg *pRegisters);

BOOL accept_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL accept_Return(LPLOGDATA pLogData, t_reg *pRegisters);

BOOL socket_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL socket_Return(LPLOGDATA pLogData, t_reg *pRegisters);

BOOL shutdown_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL closesocket_Call(LPLOGDATA pLogData, t_reg *pRegisters);

BOOL recv_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL recv_Return(LPLOGDATA pLogData, t_reg *pRegisters);

BOOL recvfrom_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL recvfrom_Return(LPLOGDATA pLogData, t_reg *pRegisters);

BOOL send_Call(LPLOGDATA pLogData, t_reg *pRegisters);
BOOL sendto_Call(LPLOGDATA pLogData, t_reg *pRegisters);

typedef BOOL HOOKFUNC(LPLOGDATA pLogData, t_reg * pRegisters);

struct HOOK {
	const wchar_t *pwszModuleName;
	const char *pszFunctionName;	/* function names are always ANSI */
	DWORD dwFunctionAddress;
	HOOKFUNC *handle_call;
	HOOKFUNC *handle_return;
};

#endif	/* __OLLYSOCKETTRACE_HOOKS_H__ */
