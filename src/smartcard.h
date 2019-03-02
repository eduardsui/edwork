#ifndef __SMARTCARD_H
#define __SMARTCARD_H

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
    #undef UNICODE
    #include <windows.h>
    #include <winscard.h>
#else
    #include <PCSC/winscard.h>
    #include <PCSC/wintypes.h>

    #define SCARD_AUTOALLOCATE (DWORD)(-1)
    #define SCARD_ATTR_VALUE(Class, Tag) ((((ULONG)(Class)) << 16) | ((ULONG)(Tag)))
    #define SCARD_PROTOCOL_Tx (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
    #define SCARD_ATTR_ATR_STRING SCARD_ATTR_VALUE(9, 0x0303)
#endif

extern LONG SC_errno;
extern const BYTE SC_GET_DATA_APDU[5];
extern const BYTE SC_GET_JAVA_CARD_ID_APDU[5];

const char *SC_GetErrorString(LONG lRetValue);
char **SC_ListReaders(SCARDCONTEXT hContext);
void SC_FreeReaders(char **readers);
SCARDCONTEXT SC_Connect();
int SC_Disconnect(SCARDCONTEXT hContext);
int SC_WaitForCard(SCARDCONTEXT hContext, char *szSelectedReader, int max_time);
int SC_WaitForCardRemoval(SCARDCONTEXT hContext, char *szSelectedReader, int max_time);
SCARDHANDLE SC_ActivateCard(SCARDCONTEXT hContext, char *szSelectedReader, DWORD *protocol);
int SC_DisconnectCard(SCARDHANDLE hCard);
int SC_ResetCard(SCARDHANDLE hCard);
int SC_EjectCard(SCARDHANDLE hCard);
int SC_GetAttributeType(SCARDHANDLE hCard, DWORD dwAttrId, char *pbAttr, DWORD *len);
int SC_GetAttribute(SCARDHANDLE hCard, char *pbAttr, DWORD *len);
int SC_GetAttributeAuto(SCARDHANDLE hCard, char **pbAttr, DWORD *len);
int SC_Exchange(SCARDHANDLE hCard, DWORD m_dwActiveProtocol, LPCBYTE pbSendBuffer, DWORD cbSendLength, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);
int SC_Control(SCARDHANDLE hCard, DWORD dwControlCode, LPCBYTE pbSendBuffer, DWORD cbSendLength, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);
int SC_SelectApplet(SCARDHANDLE hCard, DWORD protocol, unsigned char *applet_id, int len_applet_id);
int SC_Features(SCARDHANDLE hCard, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);

#endif
