#include "smartcard.h"

LONG SC_errno = 0;

const BYTE SC_GET_DATA_APDU[]            = { 0x00, 0xCA, 0x00, 0x00, 0x00};
const BYTE SC_GET_JAVA_CARD_ID_APDU[]    = { 0x80, 0xCA, 0x9F, 0x7F, 0x00 };
const BYTE SC_SELECT_APPLET[]            = { 0x00, 0xA4, 0x04, 0x00, 0x00 };

const char *SC_GetErrorString(LONG lRetValue) {
    switch (lRetValue) {
        case 0x0l:
            return "SCard OK";
        case 0x80100001:
            return "SCard internal error";
        case 0x80100002:
            return "SCard cancelled";
        case 0x80100003:
            return "SCard invalid handle";
        case 0x80100004:
            return "SCard invalid parameter";
        case 0x80100005:
            return "SCard invalid target";
        case 0x80100006:
            return "SCard no memory";
        case 0x80100007:
            return "SCard waited too long";
        case 0x80100008:
            return "SCard insufficient buffer";
        case 0x80100009:
            return "SCard unknown reader";
        case 0x8010000a:
            return "SCard timeout";
        case 0x8010000b:
            return "SCard sharing violation";
        case 0x8010000c:
            return "SCard no smartcard";
        case 0x8010000d:
            return "SCard unknown card";
        case 0x8010000e:
            return "SCard cant dispose";
        case 0x8010000f:
            return "SCard proto mismatch";
        case 0x80100010:
            return "SCard not ready";
        case 0x80100011:
            return "SCard invalid value";
        case 0x80100012:
            return "SCard system cancelled";
        case 0x80100013:
            return "SCard communications error";
        case 0x80100014:
            return "SCard unknown error";
        case 0x80100015:
            return "SCard invalid atr";
        case 0x80100016:
            return "SCard not transacted";
        case 0x80100017:
            return "SCard reader unavailable";
        case 0x80100018:
            return "SCard p shutdown";
        case 0x80100019:
            return "SCard pci too small";
        case 0x8010001a:
            return "SCard reader unsupported";
        case 0x8010001b:
            return "SCard duplicate reader";
        case 0x8010001c:
            return "SCard card unsupported";
        case 0x8010001d:
            return "SCard no service";
        case 0x8010001e:
            return "SCard service stopped";
        case 0x8010001f:
            return "SCard unexpected";
        case 0x80100020:
            return "SCard icc installation";
        case 0x80100021:
            return "SCard icc createorder";
        case 0x80100022:
            return "SCard unsupported feature";
        case 0x80100023:
            return "SCard dir not found";
        case 0x80100024:
            return "SCard file not  ound";
        case 0x80100025:
            return "SCard no dir";
        case 0x80100026:
            return "SCard no file";
        case 0x80100027:
            return "SCard no access";
        case 0x80100028:
            return "SCard write too many";
        case 0x80100029:
            return "SCard bad seek";
        case 0x8010002a:
            return "SCard invalid chv";
        case 0x8010002b:
            return "SCard unknown res mng";
        case 0x8010002c:
            return "SCard no such certificate";
        case 0x8010002d:
            return "SCard certificate unavailable";
        case 0x8010002e:
            return "SCard no readers available";
        case 0x80100065:
            return "SCard warning unsupported card";
        case 0x80100066:
            return "SCard warning unresponsive card";
        case 0x80100067:
            return "SCard warning unpowered card";
        case 0x80100068:
            return "SCard warning reset card";
        case 0x80100069:
            return "SCard warning removed card";
        case 0x8010006a:
            return "SCard warning security violation";
        case 0x8010006b:
            return "SCard warning wrong chv";
        case 0x8010006c:
            return "SCard warning chv blocked";
        case 0x8010006d:
            return "SCard warning eof";
        case 0x8010006e:
            return "SCard warning cancelled by user";
        case 0x0000007b:
            return "SCard inaccessible boot device";
        default:
            return "invalid error code";
    }
}

LONG SC_ListReaders(SCARDCONTEXT hContext, LPTSTR *pszaReaders, int max_readers) {
    LONG lRetValue;
    LPTSTR pmszReaders = NULL;
    LPTSTR pszReader;
    DWORD cch = SCARD_AUTOALLOCATE;
    int iNumberOfReaders;
    int iSelectedReader;

    SC_errno = 0;

    if (pszaReaders)
        pszaReaders[0] = 0;
    max_readers --;
    if (max_readers <= 0)
    return 0;

    lRetValue = SCardListReaders(hContext, NULL, (LPTSTR)&pmszReaders, &cch);
    if (lRetValue != SCARD_S_SUCCESS) {
        SC_errno = lRetValue;
        return -1;
    }
        
    iNumberOfReaders = 0;
    pszReader = pmszReaders;

    while ((*pszReader != '\0') && (iNumberOfReaders < max_readers)) {
        pszaReaders[iNumberOfReaders] = strdup((LPTSTR)pszReader);
        pszReader = pszReader + strlen(pszReader) + 1;
        iNumberOfReaders++;
    }
    pszaReaders[iNumberOfReaders] = 0;
    
    // Releases memory that has been returned from the resource manager 
    // using the SCARD_AUTOALLOCATE length designator.
    lRetValue = SCardFreeMemory(hContext, pmszReaders);
    if (lRetValue != SCARD_S_SUCCESS)
        SC_errno = lRetValue;
    return iNumberOfReaders;
}

void SC_Free(SCARDCONTEXT hContext, LPBYTE addr) {
    if (addr)
        SCardFreeMemory(hContext, addr);
}

void SC_FreeReaders(char **readers) {
    SC_errno = 0;

    while (*readers) {
        free(*readers);
        readers ++;
    }
}

SCARDCONTEXT SC_Connect() {
    LONG lRetValue;
    SCARDCONTEXT hContext;
    
    SC_errno = 0;

    LONG error = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
    if (error) {
        SC_errno = error;
        return -1;
    }
    return hContext;
}

int SC_Disconnect(SCARDCONTEXT hContext) {
    SC_errno = 0;
    LONG error = SCardReleaseContext(hContext);    
    if (error) {
        SC_errno = error;
        return -1;
    }
    return 0;
}

int SC_WaitForCard(SCARDCONTEXT hContext, char *szSelectedReader, int max_time) {
    SCARD_READERSTATE sReaderState;
    LONG lRetValue;

    SC_errno = 0;
    sReaderState.szReader = szSelectedReader;
    sReaderState.dwCurrentState = SCARD_STATE_UNAWARE;
    sReaderState.dwEventState = SCARD_STATE_UNAWARE;

    lRetValue = SCardGetStatusChange(hContext, 0, &sReaderState, 1);
    if (lRetValue)
        return 0;
    
    if ((sReaderState.dwEventState & SCARD_STATE_PRESENT) != SCARD_STATE_PRESENT) {
        // wait for card
        do {
            lRetValue = SCardGetStatusChange(hContext, 0, &sReaderState, 1);
            if (lRetValue != SCARD_S_SUCCESS) {
                SC_errno = lRetValue;
                return 0;
            }
            Sleep(10);
            max_time -= 10;
            if ((max_time <= 0) && ((sReaderState.dwEventState & SCARD_STATE_PRESENT) == 0))
                return 0;
        } while ((sReaderState.dwEventState & SCARD_STATE_PRESENT) == 0);
    }
    return 1;
}

int SC_WaitForCardRemoval(SCARDCONTEXT hContext, char *szSelectedReader, int max_time) {
    SCARD_READERSTATE sReaderState;
    LONG lRetValue;

    SC_errno = 0;

    sReaderState.szReader = szSelectedReader;
    sReaderState.dwCurrentState = SCARD_STATE_UNAWARE;
    sReaderState.dwEventState = SCARD_STATE_UNAWARE;
    
    lRetValue = SCardGetStatusChange(hContext, 0, &sReaderState, 1);
    if (lRetValue)
        return 0;
    
    if((sReaderState.dwEventState & SCARD_STATE_EMPTY) != SCARD_STATE_EMPTY) {
        do {
            lRetValue = SCardGetStatusChange(hContext, 0, &sReaderState, 1);
            if (lRetValue) {
                SC_errno = lRetValue;
                return 0;
            }
            Sleep(10);
            max_time -= 10;
            if ((max_time <= 0) && ((sReaderState.dwEventState & SCARD_STATE_EMPTY) == 0))
                return 0;
        } while ((sReaderState.dwEventState & SCARD_STATE_EMPTY) == 0);    
    }
    return 1;
}

SCARDHANDLE SC_ActivateCard(SCARDCONTEXT hContext, char *szSelectedReader, DWORD *protocol) {
    LONG lRetValue;
    SCARDHANDLE hCard;
    DWORD m_dwActiveProtocol;

    SC_errno = 0;
    if (protocol)
        *protocol = 0;

    lRetValue = SCardConnect(hContext, szSelectedReader, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_Tx, &hCard, &m_dwActiveProtocol);
    if (lRetValue) {
        SC_errno = lRetValue;
        return 0;
    }

    if (protocol)
        *protocol = m_dwActiveProtocol;

    switch(m_dwActiveProtocol) {
        case SCARD_PROTOCOL_T0:
        case SCARD_PROTOCOL_T1:
            break;

        case SCARD_PROTOCOL_UNDEFINED:
            SC_errno = 0x8010000f;
            break;
    }
    return hCard;
}

static int SC_DisconnectCardDisposition(SCARDHANDLE hCard, DWORD dwDisposition) {
    SC_errno = SCardDisconnect(hCard, dwDisposition);
    if (SC_errno)
        return 0;
    return 1;
}

int SC_DisconnectCard(SCARDHANDLE hCard) {
    return SC_DisconnectCardDisposition(hCard, SCARD_UNPOWER_CARD);
}

int SC_ResetCard(SCARDHANDLE hCard) {
    return SC_DisconnectCardDisposition(hCard, SCARD_RESET_CARD);
}

int SC_EjectCard(SCARDHANDLE hCard) {
    return SC_DisconnectCardDisposition(hCard, SCARD_EJECT_CARD);
}

int SC_GetAttributeType(SCARDHANDLE hCard, DWORD dwAttrId, char *pbAttr, DWORD *len) {
    SC_errno = SCardGetAttrib(hCard, dwAttrId, (LPBYTE)pbAttr, len);
    if (SC_errno)
        return 0;
    return 1;
}

int SC_GetAttribute(SCARDHANDLE hCard, char *pbAttr, DWORD *len) {
    return SC_GetAttributeType(hCard, SCARD_ATTR_ATR_STRING, pbAttr, len);
}

int SC_GetAttributeAuto(SCARDHANDLE hCard, char **pbAttr, DWORD *len) {
    *len = SCARD_AUTOALLOCATE;
    *pbAttr = NULL;

    SC_errno = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, (LPBYTE)pbAttr, len);
    if (SC_errno)
        return 0;
    return 1;
}

int SC_Exchange(SCARDHANDLE hCard, DWORD m_dwActiveProtocol, LPCBYTE pbSendBuffer, DWORD cbSendLength, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) {
    LPCSCARD_IO_REQUEST ioRequest;
    LONG lRetValue;

    switch (m_dwActiveProtocol) {
        case SCARD_PROTOCOL_T0:
            ioRequest = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            ioRequest = SCARD_PCI_T1;
            break;
        default:
            ioRequest = SCARD_PCI_RAW;
            break;
    }

    SC_errno = SCardTransmit(hCard, ioRequest, pbSendBuffer, cbSendLength, NULL, pbRecvBuffer, pcbRecvLength);
    if (SC_errno)
        return 0;

    return 1;
}

int SC_Control(SCARDHANDLE hCard, DWORD dwControlCode, LPCBYTE pbSendBuffer, DWORD cbSendLength, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) {
    DWORD lpBytesReturned;
    LONG lRetValue;

    SC_errno = SCardControl(hCard, dwControlCode, pbSendBuffer, cbSendLength, pbRecvBuffer, *pcbRecvLength, &lpBytesReturned);
    *pcbRecvLength = lpBytesReturned;
    if (SC_errno)
        return 0;

    return 1;
}

int SC_Features(SCARDHANDLE hCard, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) {
    return SC_Control(hCard, 1107299656, NULL, 0, pbRecvBuffer, pcbRecvLength);
}

int SC_SelectApplet(SCARDHANDLE hCard, DWORD protocol, unsigned char *applet_id, int len_applet_id) {
    BYTE baResponseApdu[300];
    DWORD lResponseApduLen = sizeof(baResponseApdu);
    LPBYTE apdu;

    if ((!applet_id) || (len_applet_id <= 0))
        return 0;

    apdu = (LPBYTE)malloc(5 + len_applet_id + 1);
    if (!apdu)
        return 0;
  
    memcpy(apdu, SC_SELECT_APPLET, 5);
    memcpy(apdu + 5, applet_id, len_applet_id);
    apdu[4] = (BYTE)len_applet_id;
    apdu[5 + len_applet_id] = 0;

    if (SC_Exchange(hCard, protocol, apdu, 5 + len_applet_id + 1, baResponseApdu, &lResponseApduLen)) {
        free(apdu);
        if ((lResponseApduLen == 2) && (baResponseApdu[0] == 0x90) && (baResponseApdu[1] == 0x00))
            return 1;
    }
    free(apdu);
    return 0;
}
