/******************************************************************************
 * OllySocketTrace - A rewritten Socket Tracer plugin for OllyDbg v2.01
 *
 * Rewritten by: Austyn Krutsinger
 *
 * Original OllySocketTrace by Stephen Fewer of Harmony Security (www.harmonysecurity.com)
 *****************************************************************************/
#include <stdio.h>
#include "Hooks.h"

struct FLAGS {
	DWORD dwValue;
	const wchar_t *pszName;
};

/*
 * WSA flags
 */
struct FLAGS wsasocket_flags[] = {
	{ WSA_FLAG_OVERLAPPED,			L"WSA_FLAG_OVERLAPPED"			},
	{ WSA_FLAG_MULTIPOINT_C_ROOT,	L"WSA_FLAG_MULTIPOINT_C_ROOT"	},
	{ WSA_FLAG_MULTIPOINT_C_LEAF,	L"WSA_FLAG_MULTIPOINT_C_LEAF"	},
	{ WSA_FLAG_MULTIPOINT_D_ROOT,	L"WSA_FLAG_MULTIPOINT_D_ROOT"	},
	{ WSA_FLAG_MULTIPOINT_D_LEAF,	L"WSA_FLAG_MULTIPOINT_D_LEAF"	},
	{ 0, NULL }
};

struct FLAGS asyncselect_flags[] = {
	{ FD_READ,						L"FD_READ"						},
	{ FD_WRITE,						L"FD_WRITE"						},
	{ FD_OOB,						L"FD_OOB"						},
	{ FD_ACCEPT,					L"FD_ACCEPT"					},
	{ FD_CONNECT,					L"FD_CONNECT"					},
	{ FD_CLOSE,						L"FD_CLOSE"						},
	{ FD_QOS,						L"FD_QOS"						},
	{ FD_GROUP_QOS,					L"FD_GROUP_QOS"					},
	{ FD_ROUTING_INTERFACE_CHANGE,	L"FD_ROUTING_INTERFACE_CHANGE"	},
	{ FD_ADDRESS_LIST_CHANGE,		L"FD_ADDRESS_LIST_CHANGE"		},
	{ FD_MAX_EVENTS,				L"FD_MAX_EVENTS"				},
	{ 0, NULL }
};

/*
 * ws2_32 flags
 */
struct FLAGS af_flags[] = {
	{ AF_UNSPEC,		L"AF_UNSPEC"	},
	{ AF_UNIX,			L"AF_UNIX"		},
	{ AF_INET,			L"AF_INET"		},
	{ AF_IMPLINK,		L"AF_IMPLINK"	},
	{ AF_PUP,			L"AF_PUP"		},
	{ AF_CHAOS,			L"AF_CHAOS"		},
	{ AF_NS,			L"AF_NS"		},
	{ AF_IPX,			L"AF_IPX"		},
	{ AF_ISO,			L"AF_ISO"		},
	{ AF_OSI,			L"AF_OSI"		},
	{ AF_ECMA,			L"AF_ECMA"		},
	{ AF_DATAKIT,		L"AF_DATAKIT"	},
	{ AF_CCITT,			L"AF_CCITT"		},
	{ AF_SNA,			L"AF_SNA"		},
	{ AF_DECnet,		L"AF_DECnet"	},
	{ AF_DLI,			L"AF_DLI"		},
	{ AF_LAT,			L"AF_LAT"		},
	{ AF_HYLINK,		L"AF_HYLINK"	},
	{ AF_APPLETALK,		L"AF_APPLETALK"	},
	{ AF_NETBIOS,		L"AF_NETBIOS"	},
	{ AF_VOICEVIEW,		L"AF_VOICEVIEW"	},
	{ AF_FIREFOX,		L"AF_FIREFOX"	},
	{ AF_UNKNOWN1,		L"AF_UNKNOWN1"	},
	{ AF_BAN,			L"AF_BAN"		},
	{ AF_ATM,			L"AF_ATM"		},
	{ AF_INET6,			L"AF_INET6"		},
	{ AF_CLUSTER,		L"AF_CLUSTER"	},
	{ AF_12844,			L"AF_12844"		},
	{ AF_IRDA,			L"AF_IRDA"		},
	{ AF_NETDES,		L"AF_NETDES"	},
	{ AF_TCNPROCESS,	L"AF_TCNPROCESS"},
	{ AF_TCNMESSAGE,	L"AF_TCNMESSAGE"},
	{ AF_ICLFXBM,		L"AF_ICLFXBM"	},
	{ 0, NULL }
};

struct FLAGS type_flags[] = {
	{ SOCK_STREAM,		L"SOCK_STREAM"		},
	{ SOCK_DGRAM,		L"SOCK_DGRAM"		},
	{ SOCK_RAW,			L"SOCK_RAW"			},
	{ SOCK_RDM,			L"SOCK_RDM"			},
	{ SOCK_SEQPACKET,	L"SOCK_SEQPACKET"	},
	{ 0, NULL }
};

/* missing winsock2.h defines */
#define IPPROTO_IPV4	4
#define IPPROTO_ICLFXBM	78
struct FLAGS protocol_flags[] = {
	{ IPPROTO_IP,		L"IPPROTO_IP"		},
	{ IPPROTO_ICMP,		L"IPPROTO_ICMP"		},
	{ IPPROTO_IGMP,		L"IPPROTO_IGMP"		},
	{ IPPROTO_GGP,		L"IPPROTO_GGP"		},
	{ IPPROTO_IPV4,		L"IPPROTO_IPV4"		},
	{ IPPROTO_TCP,		L"IPPROTO_TCP"		},
	{ IPPROTO_PUP,		L"IPPROTO_PUP"		},
	{ IPPROTO_UDP,		L"IPPROTO_UDP"		},
	{ IPPROTO_IDP,		L"IPPROTO_IDP"		},
	{ IPPROTO_IPV6,		L"IPPROTO_IPV6"		},
	{ IPPROTO_ROUTING,	L"IPPROTO_ROUTING"	},
	{ IPPROTO_FRAGMENT,	L"IPPROTO_FRAGMENT"	},
	{ IPPROTO_ESP,		L"IPPROTO_ESP"		},
	{ IPPROTO_AH,		L"IPPROTO_AH"		},
	{ IPPROTO_ICMPV6,	L"IPPROTO_ICMPV6"	},
	{ IPPROTO_NONE,		L"IPPROTO_NONE"		},
	{ IPPROTO_DSTOPTS,	L"IPPROTO_DSTOPTS"	},
	{ IPPROTO_ND,		L"IPPROTO_ND"		},
	{ IPPROTO_ICLFXBM,	L"IPPROTO_ICLFXBM"	},
	{ IPPROTO_RAW,		L"IPPROTO_RAW"		},
	{ IPPROTO_MAX,		L"IPPROTO_MAX"		},
	{ 0, NULL }
};

/* missing winsock2.h defines */
#define MSG_WAITALL	0x8
struct FLAGS msg_flags[] = {
	{ MSG_OOB,			L"MSG_OOB"		},
	{ MSG_PEEK,			L"MSG_PEEK"		},
	{ MSG_DONTROUTE,	L"MSG_DONTROUTE"},
	{ MSG_WAITALL,		L"MSG_WAITALL"	},
	{ MSG_PARTIAL,		L"MSG_PARTIAL"	},
	{ MSG_INTERRUPT,	L"MSG_INTERRUPT"},
	{ 0, NULL }
};

struct FLAGS ioctl_flags[] = {
	{ FIONREAD,		L"FIONREAD"		},
	{ FIONBIO,		L"FIONBIO"		},
	{ FIOASYNC,		L"FIOASYNC"		},
	{ SIOCATMARK,	L"SIOCATMARK"	},
	{ SIOCGHIWAT,	L"SIOCGHIWAT"	},
	{ SIOCSLOWAT,	L"SIOCSLOWAT"	},
	{ SIOCGLOWAT,	L"SIOCGLOWAT"	},
	{ SIOCATMARK,	L"SIOCATMARK"	},
	{ 0, NULL }
};

struct FLAGS shutdown_flags[] = {
	{ SD_RECEIVE,	L"SD_RECEIVE"	},
	{ SD_SEND,		L"SD_SEND"		},
	{ SD_BOTH,		L"SD_BOTH"		},
	{ 0, NULL }
};

enum record_reason {
	CONNECT,
	ACCEPT,
	BIND,
	RECEIVE,
	SEND
};
/*****************************************************************************/
/**
 * Common procedures
 */
/*****************************************************************************/
VOID ResolveFlags(struct FLAGS *pFlags, BOOL bORed, DWORD dwFlags, wchar_t *pwszOutput)
{
	int iCount = 0;
	int i = 0;
	memset(pwszOutput, 0, MAX_PATH);

	if (bORed) {
		while (pFlags[i].pszName != NULL) {
			if ((dwFlags & pFlags[i].dwValue) == pFlags[i].dwValue) {
				if (iCount > 0) {
					wcscat(pwszOutput, L" | ");
				}
				wcscat(pwszOutput, pFlags[i].pszName);
				iCount++;
			}
			i++;
		}
	} else {
		while (pFlags[i].pszName != NULL) {
			if (dwFlags == pFlags[i].dwValue) {
				wcscat(pwszOutput, pFlags[i].pszName);
				iCount++;
				break;
			}
			i++;
		}
	}

	if (iCount == 0){
		snwprintf(pwszOutput, MAX_PATH, L"0x%X", dwFlags);
	}
}
/*****************************************************************************/
BOOL record_sockaddr(LPLOGDATA pLogData, enum record_reason reason, DWORD dwpSockAddr, DWORD dwSockAddrLength, DWORD dwNumberBytesUsed)
{
	struct sockaddr_in *p_saddr;
	wchar_t wszBuffer[BUFFER_SIZE];
	wchar_t wszSin_Addr[SHORTNAME];

	if (dwSockAddrLength != 0 && dwpSockAddr != 0) {
		p_saddr = (struct sockaddr_in *)MyMalloc(dwSockAddrLength);
		if (p_saddr != NULL && Readmemory(p_saddr, dwpSockAddr, dwSockAddrLength, MM_SILENT) != 0) {
			Asciitounicode(inet_ntoa(p_saddr->sin_addr), SHORTNAME, wszSin_Addr, SHORTNAME);
			switch (reason) {
			case CONNECT:
				snwprintf(wszBuffer, BUFFER_SIZE, L"Connecting to: %s:%d", wszSin_Addr, ntohs(p_saddr->sin_port));
				break;
			case ACCEPT:
				snwprintf(wszBuffer, BUFFER_SIZE, L"Connection from: %s:%d", wszSin_Addr, ntohs(p_saddr->sin_port));
				break;
			case BIND:
				snwprintf(wszBuffer, BUFFER_SIZE, L"Binding to: %s:%d", wszSin_Addr, ntohs(p_saddr->sin_port));
				break;
			case RECEIVE:
				snwprintf(wszBuffer, BUFFER_SIZE, L"Received %d bytes from: %s:%d", dwNumberBytesUsed, wszSin_Addr, ntohs(p_saddr->sin_port));
				break;
			case SEND:
				snwprintf(wszBuffer, BUFFER_SIZE, L"Sent %d bytes to: %s:%d", dwNumberBytesUsed, wszSin_Addr, ntohs(p_saddr->sin_port));
				break;
			default:
				break;
			}
			wcsncat(pLogData->wszHint, wszBuffer, BUFFER_SIZE);
			MyFree(p_saddr);
			return TRUE;
		}
		MyFree(p_saddr);
	}
	return FALSE;
}
/*****************************************************************************/
BOOL record_buffer(LPLOGDATA pLogData, DWORD dwThreshold)
{
	if (pLogData->dwDbgBuffer != 0 && pLogData->dwDbgBufferSize > 0) {
		if (pLogData->dwDbgBufferSize > dwThreshold) {
			pLogData->dwOllyBufferSize = dwThreshold;
		} else {
			pLogData->dwOllyBufferSize = pLogData->dwDbgBufferSize;
		}

		pLogData->lpOllyBuffer = MyMalloc(pLogData->dwOllyBufferSize);
		if (pLogData->lpOllyBuffer != NULL) {
			if (Readmemory(pLogData->lpOllyBuffer, pLogData->dwDbgBuffer, pLogData->dwOllyBufferSize, MM_SILENT) != 0) {
				return TRUE;
			}
			MyFree(pLogData->lpOllyBuffer);
		}
		pLogData->dwOllyBufferSize = 0;
	}
	return FALSE;
}
/*****************************************************************************/
BOOL DefaultINT_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// this is kind of cheating but works
	if (pRegisters->r[REG_EAX] == INVALID_SOCKET) {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"INVALID_SOCKET");
	} else {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"%d", pRegisters->r[REG_EAX]);
	}
	return TRUE;
}
/*****************************************************************************/
BOOL DefaultBOOL_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"%s", (pRegisters->r[REG_EAX] ? L"TRUE" : L"FALSE"));
	return TRUE;
}
/*****************************************************************************/
/**
 * WSA Calls
 */
/*****************************************************************************/
BOOL WSASocket_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// SOCKET WSASocket(int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo, GROUP g, DWORD dwFlags);
	DWORD dwParameters[6];
	wchar_t wcFlagsOutput[MAX_PATH];
	wchar_t wcFlagsOutput_AF[MAX_PATH];
	wchar_t wcFlagsOutput_TYPE[MAX_PATH];
	wchar_t wcFlagsOutput_PROTOCOL[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 6, MM_SILENT) == 0) {
		return FALSE;
	}

	ResolveFlags((struct FLAGS *)&af_flags, FALSE, dwParameters[0], (wchar_t *)&wcFlagsOutput_AF);
	ResolveFlags((struct FLAGS *)&type_flags, FALSE, dwParameters[1], (wchar_t *)&wcFlagsOutput_TYPE);
	ResolveFlags((struct FLAGS *)&protocol_flags, FALSE, dwParameters[2], (wchar_t *)&wcFlagsOutput_PROTOCOL);
	ResolveFlags((struct FLAGS *)&wsasocket_flags, FALSE, dwParameters[5], (wchar_t *)&wcFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSASocket(%s, %s, %s, 0x%08X, %d, %s)", wcFlagsOutput_AF, wcFlagsOutput_TYPE, wcFlagsOutput_PROTOCOL, dwParameters[3], dwParameters[4], wcFlagsOutput);

	return TRUE;
}
/*****************************************************************************/
BOOL WSAAccept_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// SOCKET WSAAccept(SOCKET s, struct sockaddr *addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD dwCallbackData);
	DWORD dwParameters[5];
	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 5, MM_SILENT) == 0 ) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	// accept_Return() will resolve the connecting sockaddr...
	if (dwParameters[2] != 0) {
		if (Readmemory(&pLogData->dwValueB, dwParameters[2], sizeof(DWORD), MM_SILENT) != 0) {
			pLogData->dwValueA = dwParameters[1];
		}
	}

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSAAccept(%d, 0x%08X, 0x%08X, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], dwParameters[4]);

	return TRUE;
}
/*****************************************************************************/
BOOL WSAConnect_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData,
	// 				LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
	DWORD dwParameters[7];
	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 7, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	record_sockaddr(pLogData, CONNECT, dwParameters[1], dwParameters[2], 0);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSAConnect(%d, 0x%08X, %d, 0x%08X, 0x%08X, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], dwParameters[4], dwParameters[5], dwParameters[6]);

	return TRUE;
}
/*****************************************************************************/
BOOL WSARecv_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	DWORD dwNumberOfBytesRecvd = 0;

	if (pLogData->dwValueA != 0 && pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR) {
		if (Readmemory(&dwNumberOfBytesRecvd, pLogData->dwValueA, sizeof(DWORD), MM_SILENT) != 0) {
			/* only save hint if it hasn't already been written to (e.g. WSARecvFrom_Return) */
			if (wcslen(pLogData->wszHint) == 0) {
				snwprintf(pLogData->wszHint, BUFFER_SIZE, L"Received %d bytes", dwNumberOfBytesRecvd);
			}

			if (dwNumberOfBytesRecvd > 0) {
				if (dwNumberOfBytesRecvd < SIZE_THRESHOLD) {
					record_buffer(pLogData, dwNumberOfBytesRecvd);
				} else {
					record_buffer(pLogData, SIZE_THRESHOLD);
				}
			}
		}
	}

	if (pRegisters->r[REG_EAX] == (DWORD)SOCKET_ERROR) {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"SOCKET_ERROR");
	} else {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"%d", pRegisters->r[REG_EAX]);
	}

	return TRUE;
}
/*****************************************************************************/
BOOL WSARecv_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd,
	//		LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped,
	//		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	DWORD dwParameters[7];
	WSABUF wsaBuffer;
	wchar_t wcFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 7, MM_SILENT) == 0) {
		return FALSE;
	}
	pLogData->dwSocket = dwParameters[0];

	if (dwParameters[2] > 0) {
		// TODO: support multiple buffers...
		if (Readmemory(&wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT) != 0) {
			pLogData->dwDbgBuffer = (DWORD)wsaBuffer.buf;
			pLogData->dwDbgBufferSize = wsaBuffer.len;
		}
	}

	pLogData->dwValueA = dwParameters[3];

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (wchar_t *)&wcFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSARecv(%d, 0x%08X, %d, 0x%08X, %s, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], wcFlagsOutput, dwParameters[5], dwParameters[6]);

	return TRUE;
}
/*****************************************************************************/
BOOL WSASend_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	DWORD dwNumberOfBytesSent = 0;
	wchar_t wcBuffer[BUFFER_SIZE];

	if (pLogData->dwValueA != 0 && pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR) {
		if (Readmemory(&dwNumberOfBytesSent, pLogData->dwValueA, sizeof(DWORD), MM_SILENT) != 0) {
			snwprintf(wcBuffer, BUFFER_SIZE, L"Sent %d bytes", dwNumberOfBytesSent);
			wcsncat(pLogData->wszHint, wcBuffer, BUFFER_SIZE);
		}
	}

	return DefaultINT_Return(pLogData, pRegisters);
}
/*****************************************************************************/
BOOL WSASend_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
	//		DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	DWORD dwParameters[7];
	WSABUF wsaBuffer;
	wchar_t wcFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 7, MM_SILENT) == 0) {
		return FALSE;
	}
	pLogData->dwSocket = dwParameters[0];

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (wchar_t *)&wcFlagsOutput );

	pLogData->dwValueA = dwParameters[3];

	if (dwParameters[2] > 0) {
		// TODO: support multiple buffers...
		if (Readmemory(&wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT) != 0) {
			pLogData->dwDbgBuffer = (DWORD)wsaBuffer.buf;
			pLogData->dwDbgBufferSize = wsaBuffer.len;

			record_buffer(pLogData, SIZE_THRESHOLD);
		}
	}

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSASend(%d, 0x%08X, %d, 0x%08X, %s, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], wcFlagsOutput, dwParameters[5], dwParameters[6]);

	return TRUE;
}
/*****************************************************************************/
BOOL WSAAsyncSelect_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	//int WSAAsyncSelect(SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent);
	DWORD dwParameters[4];
	wchar_t wcFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 4, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	ResolveFlags((struct FLAGS *)&asyncselect_flags, TRUE, dwParameters[3], (wchar_t *)&wcFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSAAsyncSelect(%d, 0x%08X, 0x%08X, %s)", dwParameters[0], dwParameters[1], dwParameters[2], wcFlagsOutput);

	return TRUE;
}
/*****************************************************************************/
BOOL WSAEventSelect_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	//int WSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents);
	DWORD dwParameters[3];
	wchar_t wcFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 3, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	ResolveFlags((struct FLAGS *)&asyncselect_flags, TRUE, dwParameters[2], (wchar_t *)&wcFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSAEventSelect(%d, 0x%08X, %s)", dwParameters[0], dwParameters[1], wcFlagsOutput);

	return TRUE;
}
/*****************************************************************************/
BOOL WSACloseEvent_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// BOOL WSACloseEvent(WSAEVENT hEvent);
	DWORD dwParameter;

	if (Readmemory(&dwParameter, pRegisters->r[REG_ESP] + 4, sizeof(DWORD), MM_SILENT) == 0) {
		return FALSE;
	}
	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSACloseEvent(0x%08X)", dwParameter);

	return TRUE;
}
/*****************************************************************************/
BOOL WSASendTo_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent,
	//		DWORD dwFlags, const struct sockaddr *lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped,
	//		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	DWORD dwParameters[9];
	wchar_t wcFlagsOutput[MAX_PATH];
	WSABUF wsaBuffer;

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 9, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	pLogData->dwValueA = dwParameters[3];

	record_sockaddr(pLogData, SEND, dwParameters[5], dwParameters[6], dwParameters[3]);

	if (dwParameters[2] > 0) {
		// TODO: support multiple buffers...
		if (Readmemory(&wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT) != 0) {
			pLogData->dwDbgBuffer = (DWORD)wsaBuffer.buf;
			pLogData->dwDbgBufferSize = wsaBuffer.len;

			record_buffer(pLogData, SIZE_THRESHOLD);
		}
	}

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (wchar_t *)&wcFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSASendTo(%d, 0x%08X, %d, 0x%08X, %s, 0x%08X, %d, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], wcFlagsOutput, dwParameters[5], dwParameters[6], dwParameters[7], dwParameters[8]);

	return TRUE;
}
/*****************************************************************************/
BOOL WSARecvFrom_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	record_sockaddr(pLogData, RECEIVE, pLogData->dwValueB, pLogData->dwValueC, pLogData->dwValueA);
	return WSARecv_Return(pLogData, pRegisters);
}
/*****************************************************************************/
BOOL WSARecvFrom_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd,
	//		LPDWORD lpFlags, struct sockaddr *lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
	//		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	DWORD dwParameters[9];
	wchar_t wszFlagsOutput[MAX_PATH];
	WSABUF wsaBuffer;

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP]+4, sizeof(DWORD)*9, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];
	if (dwParameters[2] > 0) {
		// TODO: support multiple buffers...
		if (Readmemory(&wsaBuffer, dwParameters[1], sizeof(WSABUF), MM_SILENT) != 0) {
			pLogData->dwDbgBuffer = (DWORD)wsaBuffer.buf;
			pLogData->dwDbgBufferSize = wsaBuffer.len;
		}
	}

	pLogData->dwValueA = dwParameters[3]; // lpNumberOfBytesRecvd

	if (dwParameters[6] != 0) {	// lpFromlen
		if (Readmemory(&pLogData->dwValueC, dwParameters[6], sizeof(DWORD), MM_SILENT) != 0) {
			pLogData->dwValueB = dwParameters[5]; // lpFrom
		}
	}

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[4], (wchar_t *)&wszFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"WSARecvFrom(%d, 0x%08X, %d, 0x%08X, %s, 0x%08X, 0x%08X, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2], dwParameters[3], wszFlagsOutput, dwParameters[5], dwParameters[6], dwParameters[7], dwParameters[8]);

	return TRUE;
}

/*****************************************************************************/
/**
 * ws2_32 Calls
 */
/*****************************************************************************/
BOOL listen_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int listen(SOCKET s, int backlog);
	DWORD dwParameters[2];
	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 2, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"listen(%d, %d)", dwParameters[0], dwParameters[1]);

	return TRUE;
}
/*****************************************************************************/
BOOL ioctlsocket_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int ioctlsocket(SOCKET s, long cmd, u_long *argp);
	DWORD dwParameters[3];
	wchar_t wszFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 3, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	ResolveFlags((struct FLAGS *)&ioctl_flags, FALSE, dwParameters[1], (wchar_t *)&wszFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"ioctlsocket(%d, %s, 0x%08X)", dwParameters[0], wszFlagsOutput, dwParameters[2]);

	return TRUE;
}
/*****************************************************************************/
BOOL connect_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int connect(SOCKET s, const struct sockaddr *name, int namelen);
	DWORD dwParameters[3];
	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 3, MM_SILENT ) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	record_sockaddr(pLogData, CONNECT, dwParameters[1], dwParameters[2], 0);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"connect(%d, 0x%08X, %d)", dwParameters[0], dwParameters[1], dwParameters[2]);

	return TRUE;
}
/*****************************************************************************/
BOOL accept_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	if (pRegisters->r[REG_EAX] == INVALID_SOCKET) {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"INVALID_SOCKET");
	} else {
		record_sockaddr(pLogData, ACCEPT, pLogData->dwValueA, pLogData->dwValueB, 0);
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"%d", pRegisters->r[REG_EAX]);
	}
	return TRUE;
}
/*****************************************************************************/
BOOL accept_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen);
	DWORD dwParameters[3];
	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 3, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	// accept_Return() will resolve the connecting sockaddr...
	if (dwParameters[2] != 0) {
		if (Readmemory(&pLogData->dwValueB, dwParameters[2], sizeof(DWORD), MM_SILENT) != 0) {
			pLogData->dwValueA = dwParameters[1];
		}
	}

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"accept(%d, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2]);

	return TRUE;
}
/*****************************************************************************/
BOOL bind_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int bind(SOCKET s, const struct sockaddr *name, int namelen);
	DWORD dwParameters[3];
	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 3, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	record_sockaddr(pLogData, BIND, dwParameters[1], dwParameters[2], 0);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"bind(%d, 0x%08X, %d)", dwParameters[0], dwParameters[1], dwParameters[2]);

	return TRUE;
}
/*****************************************************************************/
BOOL socket_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// SOCKET socket(int af, int type, int protocol);
	DWORD dwParameters[3];
	wchar_t wszFlagsOutput_AF[MAX_PATH];
	wchar_t wszFlagsOutput_TYPE[MAX_PATH];
	wchar_t wszFlagsOutput_PROTOCOL[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 3, MM_SILENT) == 0)
		return FALSE;

	ResolveFlags((struct FLAGS *)&af_flags, FALSE, dwParameters[0], (wchar_t *)&wszFlagsOutput_AF);
	ResolveFlags((struct FLAGS *)&type_flags, FALSE, dwParameters[1], (wchar_t *)&wszFlagsOutput_TYPE);
	ResolveFlags((struct FLAGS *)&protocol_flags, FALSE, dwParameters[2], (wchar_t *)&wszFlagsOutput_PROTOCOL);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"socket(%s, %s, %s)", wszFlagsOutput_AF, wszFlagsOutput_TYPE, wszFlagsOutput_PROTOCOL);

	return TRUE;
}
/*****************************************************************************/
BOOL socket_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	pLogData->dwSocket = pRegisters->r[REG_EAX];
	if (pLogData->dwSocket == INVALID_SOCKET) {
		pLogData->dwSocket = 0;
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"INVALID_SOCKET");
	} else {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"%d", pRegisters->r[REG_EAX]);
	}
	return TRUE;
}
/*****************************************************************************/
BOOL shutdown_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int shutdown(SOCKET s, int how);
	DWORD dwParameters[2];
	wchar_t wszFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 2, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];

	ResolveFlags((struct FLAGS *)&shutdown_flags, TRUE, dwParameters[1], (wchar_t *)&wszFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"shutdown(%d, %s)", dwParameters[0], wszFlagsOutput);

	return TRUE;
}
/*****************************************************************************/
BOOL closesocket_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int closesocket(SOCKET s);
	DWORD dwParameter;

	if (Readmemory(&dwParameter, pRegisters->r[REG_ESP] + 4, sizeof(DWORD), MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameter;

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"closesocket(%d)", dwParameter);

	return TRUE;
}
/*****************************************************************************/
BOOL recv_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	/* should we test the return value for success/bytes read and use that value>?? */
	if (pRegisters->r[REG_EAX] != 0 && pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR) {
		/* save received data chunk to log data buffer */
		if (pRegisters->r[REG_EAX] > 0 && pRegisters->r[REG_EAX] < SIZE_THRESHOLD) {
			record_buffer(pLogData, pRegisters->r[REG_EAX]);
		} else {
			record_buffer(pLogData, SIZE_THRESHOLD);
		}
		/* set hint to how many bytes were received. Since EAX is a positive value, we know bytes were actually received */
		if (wcslen(pLogData->wszHint) == 0) {
			snwprintf(pLogData->wszHint, BUFFER_SIZE, L"Received %d bytes", pRegisters->r[REG_EAX]);
		}
	}

	if (pRegisters->r[REG_EAX] == (DWORD)SOCKET_ERROR) {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"SOCKET_ERROR");
	} else {
		snwprintf(pLogData->wszReturnMessage, BUFFER_SIZE, L"%d", pRegisters->r[REG_EAX]);
	}

	return TRUE;
}
/*****************************************************************************/
BOOL recv_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int recv(SOCKET s, char *buf, int len, int flags);
	DWORD dwParameters[4];
	wchar_t wszFlagsOutput[MAX_PATH];

	if (Readmemory( &dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 4, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];
	pLogData->dwDbgBuffer = dwParameters[1];
	pLogData->dwDbgBufferSize = dwParameters[2];

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (wchar_t *)&wszFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"recv(%d, 0x%08X, %d, %s)", dwParameters[0], dwParameters[1], dwParameters[2], wszFlagsOutput);

	return TRUE;
}
/*****************************************************************************/
BOOL recvfrom_Return(LPLOGDATA pLogData, t_reg *pRegisters)
{
	if (pRegisters->r[REG_EAX] != (DWORD)SOCKET_ERROR) {
		record_sockaddr(pLogData, RECEIVE, pLogData->dwValueA, pLogData->dwValueB, pLogData->dwValueA);
	}

	return recv_Return(pLogData, pRegisters);
}
/*****************************************************************************/
BOOL recvfrom_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
	DWORD dwParameters[6];
	wchar_t wszFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 6, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];
	pLogData->dwDbgBuffer = dwParameters[1];
	pLogData->dwDbgBufferSize = dwParameters[2];

	// recvfrom_Return will resolve the sockaddr if success...
	if (dwParameters[5] != 0)
	{
		if (Readmemory(&pLogData->dwValueB, dwParameters[5], sizeof(DWORD), MM_SILENT) != 0) {
			pLogData->dwValueA = dwParameters[4];
		}
	}

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (wchar_t *)&wszFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"recvfrom(%d, 0x%08X, %d, %s, 0x%08X, 0x%08X)", dwParameters[0], dwParameters[1], dwParameters[2], wszFlagsOutput, dwParameters[4], dwParameters[5]);

	return TRUE;
}
/*****************************************************************************/
BOOL send_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int send(SOCKET s, char *buf, int len, int flags);
	DWORD dwParameters[4];
	wchar_t wszFlagsOutput[MAX_PATH];

	if (Readmemory( &dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 4, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];
	pLogData->dwDbgBuffer = dwParameters[1];
	pLogData->dwDbgBufferSize = dwParameters[2];

	record_buffer(pLogData, SIZE_THRESHOLD);

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (wchar_t *)&wszFlagsOutput);

	snwprintf(pLogData->wszMessage, BUFFER_SIZE, L"send(%d, 0x%08X, %d, %s)", dwParameters[0], dwParameters[1], dwParameters[2], wszFlagsOutput);
	snwprintf(pLogData->wszHint, BUFFER_SIZE, L"Sent %d bytes", dwParameters[2]);
	return TRUE;
}
/*****************************************************************************/
BOOL sendto_Call(LPLOGDATA pLogData, t_reg *pRegisters)
{
	// int sendto(SOCKET s, char *buf, int len, int flags, struct sockaddr *to, int *tolen);
	DWORD dwParameters[6];
	wchar_t wszFlagsOutput[MAX_PATH];

	if (Readmemory(&dwParameters, pRegisters->r[REG_ESP] + 4, sizeof(DWORD) * 6, MM_SILENT) == 0) {
		return FALSE;
	}

	pLogData->dwSocket = dwParameters[0];
	pLogData->dwDbgBuffer = dwParameters[1];
	pLogData->dwDbgBufferSize = dwParameters[2];

	record_buffer(pLogData, SIZE_THRESHOLD);

	record_sockaddr(pLogData, SEND, dwParameters[4], dwParameters[5], 0);

	ResolveFlags((struct FLAGS *)&msg_flags, TRUE, dwParameters[3], (wchar_t *)&wszFlagsOutput);

	snwprintf( pLogData->wszMessage, BUFFER_SIZE, L"sendto(%d, 0x%08X, %d, %s, 0x%08X, %d)", dwParameters[0], dwParameters[1], dwParameters[2], wszFlagsOutput, dwParameters[4], dwParameters[5]);

	return TRUE;
}
/*****************************************************************************/
