#ifdef _WIN32
    #undef UNICODE
    #include <windows.h>
    #include <winscard.h>
#else
    #include <PCSC/winscard.h>
    #include <PCSC/wintypes.h>
#endif

static LONG SC_errno;

const char *SCardGetErrorString(LONG lRetValue) {
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

LONG SC_ListReaders(SCARDCONTEXT m_hContext, LPTSTR *pszaReaders, int max_readers) {
    LONG lRetValue;
	LPTSTR          pmszReaders = NULL;
	LPTSTR          pszReader;
	DWORD           cch = SCARD_AUTOALLOCATE;
	INT				iNumberOfReaders;
	INT				iSelectedReader;

    SC_errno = 0;

    if (pszaReaders)
        pszaReaders[0] = 0;
    max_readers --;
    if (max_readers <= 0)
        return 0;

	lRetValue = SCardListReaders(m_hContext, NULL, (LPTSTR)&pmszReaders, &cch);
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
	lRetValue = SCardFreeMemory(m_hContext, pmszReaders);
	if (lRetValue != SCARD_S_SUCCESS)
        SC_errno = lRetValue;
	return iNumberOfReaders;
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
    SCARDCONTEXT m_hContext;
    
    SC_errno = 0;

	LONG error = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
    if (error) {
        SC_errno = error;
        return -1;
    }
	return m_hContext;
}

int SC_Disconnect(SCARDCONTEXT m_hContext) {
    SC_errno = 0;
	LONG error = SCardReleaseContext(m_hContext);	
    if (error) {
        SC_errno = error;
        return -1;
    }
	return 0;
}


int SC_WaitForCard(SCARDCONTEXT m_hContext, CHAR *m_szSelectedReader, int max_time) {
    SCARD_READERSTATE sReaderState;
    LONG lRetValue;

    SC_errno = 0;
    sReaderState.szReader = m_szSelectedReader;
    sReaderState.dwCurrentState = SCARD_STATE_UNAWARE;
    sReaderState.dwEventState = SCARD_STATE_UNAWARE;

    lRetValue = SCardGetStatusChange(m_hContext, 30000, &sReaderState, 1);
    if (lRetValue)
        return 0;
    
    if ((sReaderState.dwEventState & SCARD_STATE_PRESENT) != SCARD_STATE_PRESENT) {
        // wait for card
        do {
            lRetValue = SCardGetStatusChange(m_hContext, 30, &sReaderState, 1);
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

int SC_WaitForCardRemoval(SCARDCONTEXT m_hContext, CHAR *m_szSelectedReader, int max_time) {
    SCARD_READERSTATE sReaderState;
    LONG lRetValue;

    SC_errno = 0;

    sReaderState.szReader = m_szSelectedReader;
    sReaderState.dwCurrentState = SCARD_STATE_UNAWARE;
    sReaderState.dwEventState = SCARD_STATE_UNAWARE;
    
    lRetValue = SCardGetStatusChange(m_hContext, 30, &sReaderState, 1);
    if (lRetValue)
        return 0;    
    
    if((sReaderState.dwEventState & SCARD_STATE_EMPTY) != SCARD_STATE_EMPTY) {
        do {
            lRetValue = SCardGetStatusChange(m_hContext,30,&sReaderState,1);
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
