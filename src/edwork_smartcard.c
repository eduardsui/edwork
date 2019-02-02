#include <stdio.h>
#include <string.h>
#include "edwork_smartcard.h"
#include "log.h"

static const BYTE SC_EDWORK_HELLO[]            =   {0x10, 0x01, 0x00,0x00, 0x00};
static const BYTE SC_EDWORK_PUBLIC_KEY[]       =   {0x10, 0x45, 0x00,0x00, 0x00};
static const BYTE SC_EDWORK_SIGN[]             =   {0x10, 0x48, 0x00,0x00, 0x00};
static const BYTE SC_EDWORK_VERIFY[]           =   {0x10, 0x49, 0x00,0x00, 0x00};

static char *edwork_strstr(const char *s, const char *find) {
    char c, sc;
    size_t len;

    if ((c = *find++) != 0) {
        c = tolower((unsigned char)c);
        len = strlen(find);
        do {
            do {
                if ((sc = *s++) == 0)
                    return (NULL);
            } while ((char)tolower((unsigned char)sc) != c);
        } while (strncasecmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

static int edwork_smartcard_get_name(struct edwork_smartcard_context *context, char *buffer, int buf_len) {
    BYTE baResponseApdu[300];
    DWORD lResponseApduLen = sizeof(baResponseApdu);

    if ((!buffer) || (buf_len <= 0) || (!context))
        return 0;

    buffer[0] = 0;
    if (SC_Exchange(context->hCard, context->protocol, SC_EDWORK_HELLO, sizeof(SC_EDWORK_HELLO), baResponseApdu, &lResponseApduLen)) {
        if ((lResponseApduLen >= 10) && (!memcmp(baResponseApdu, "\x06\xED\xED\xED\xED\xED\x01\x01", 8))) {
            int len = baResponseApdu[9];
            if (len <= lResponseApduLen - 10) {
                if (len >= buf_len - 1)
                    len = buf_len - 1;
                memcpy(buffer, baResponseApdu + 10, len);
                buffer[len] = 0;
                log_info("using smart card for %s", buffer);
                return len;
            }
        }
    } else
        log_error("smartcard error %x: %s", (int)SC_errno, SC_GetErrorString(SC_errno));

    return 0;
}

static int edwork_smartcard_get_public_key(struct edwork_smartcard_context *context, char *buffer, int buf_len) {
    DWORD lResponseApduLen = buf_len;

    if ((!buffer) || (buf_len <= 0) || (!context))
        return 0;

    buffer[0] = 0;

    if (SC_Exchange(context->hCard, context->protocol, SC_EDWORK_PUBLIC_KEY, sizeof(SC_EDWORK_PUBLIC_KEY), (LPBYTE)buffer, &lResponseApduLen)) {
        return lResponseApduLen;
    } else
        log_error("smartcard error %x: %s", (int)SC_errno, SC_GetErrorString(SC_errno));

    return 0;
}

int edwork_smartcard_sign(struct edwork_smartcard_context *context, const char *buffer, int buf_len, char *signature, int sig_len) {
    BYTE baResponseApdu[300];
    DWORD lResponseApduLen = sizeof(baResponseApdu);
    LPBYTE apdu;

    if ((!buffer) || (buf_len <= 0) || (!signature) || (sig_len <= 0) || (!context) || (context->status != 4))
        return 0;

    apdu = (LPBYTE)malloc(5 + buf_len + 1);
    if (!apdu)
        return 0;
  
    memcpy(apdu, SC_EDWORK_SIGN, 5);
    memcpy(apdu + 5, buffer, buf_len);
    apdu[4] = (BYTE)buf_len;
    apdu[5 + buf_len] = 0;

    thread_mutex_lock(&context->lock);
    if (SC_Exchange(context->hCard, context->protocol, apdu, 5 + buf_len + 1, baResponseApdu, &lResponseApduLen)) {
        thread_mutex_unlock(&context->lock);
        free(apdu);
        if ((lResponseApduLen > 2) && (baResponseApdu[lResponseApduLen - 2] == 0x90) && (baResponseApdu[lResponseApduLen - 1] == 0x00)) {            
            if (lResponseApduLen - 2 > sig_len) {
                memcpy(signature, baResponseApdu, sig_len);
                return sig_len;
            } else {
                memcpy(signature, baResponseApdu, lResponseApduLen - 2);
                return lResponseApduLen - 2;
            }
        }
    } else {
        thread_mutex_unlock(&context->lock);
        free(apdu);
        log_error("smartcard error %x: %s", (int)SC_errno, SC_GetErrorString(SC_errno));
    }

    return 0;
}

int edwork_smartcard_verify(struct edwork_smartcard_context *context, const char *buffer, int buf_len, const char *signature, int sig_len) {
    BYTE responseApdu[300];
    DWORD lResponseApduLen = sizeof(responseApdu);
    LPBYTE apdu;

    if ((!buffer) || (buf_len <= 0) || (!signature) || (sig_len <= 0) || (!context) || (context->status != 4))
        return 0;

    apdu = (LPBYTE)malloc(5 + sig_len + buf_len + 1);
    if (!apdu)
        return 0;

    memcpy(apdu, SC_EDWORK_VERIFY, 5);
    memcpy(apdu + 5, signature, sig_len);
    memcpy(apdu + 5 + sig_len, buffer, buf_len);
    apdu[2] = (BYTE)sig_len;
    apdu[4] = (BYTE)sig_len + buf_len;
    apdu[5 + sig_len + buf_len + 1] = 0;
    
    thread_mutex_lock(&context->lock);
    if (SC_Exchange(context->hCard, context->protocol, apdu, 5 + sig_len + buf_len + 1, (LPBYTE)responseApdu, &lResponseApduLen)) {
        thread_mutex_unlock(&context->lock);
        free(apdu);
        if ((lResponseApduLen == 3) && (responseApdu[0] == 1) && (responseApdu[1] == 0x90) && (responseApdu[2] == 0x00))
            return 1;
    } else {
        thread_mutex_unlock(&context->lock);
        free(apdu);
        log_error("smartcard error %x: %s", (int)SC_errno, SC_GetErrorString(SC_errno));
    }

    return 0;
}

int edwork_smartcard_iterate(struct edwork_smartcard_context *context) {
    if (!context)
        return -1;

    int count;
    thread_mutex_lock(&context->lock);
    switch (context->status) {
        case 0:
            context->hContext = SC_Connect();
            if (!SC_errno) {
                char *readers[16];
                count = SC_ListReaders(context->hContext, readers, 16);
                if (count > 0) {
                    free(context->reader);
                    context->reader = NULL;
                    for (int i = 0; i < count; i++) {
                        if (edwork_strstr(readers[i], "contactless")) {
                            context->reader = strdup(readers[i]);
                            break;
                        }
                    }
                    if (!context->reader)
                        context->reader = strdup(readers[0]);

                    SC_FreeReaders(readers);
                    context->status = 1;
                } else {
                    SC_Disconnect(context->hContext);
                }
            }
            break;
        case 1:
            if (SC_WaitForCard(context->hContext, context->reader, 0))
                context->status = 2;
            else
            if (SC_errno)
                context->status = 20;
            break;
        case 2:
            context->hCard = SC_ActivateCard(context->hContext, context->reader, &context->protocol);
            if (SC_errno) {
                log_warn("smartcard error %x: %s", (int)SC_errno, SC_GetErrorString(SC_errno));
                context->status = 20;
            } else
                context->status = 3;
            break;
        case 3:
            context->public_key_len = edwork_smartcard_get_public_key(context, context->public_key, sizeof(context->public_key));
            if ((context->public_key_len) && (edwork_smartcard_get_name(context, context->buf_name, sizeof(context->buf_name)))) {
                context->status = 4;
                char signature[0x100];
                thread_mutex_unlock(&context->lock);
                // perform a test signature and verify
                int sig_len = edwork_smartcard_sign(context, "signature", 9, signature, sizeof(signature));
                if (sig_len > 0) {
                    if (!edwork_smartcard_verify(context, "signature", 9, signature, sig_len))
                        context->status = 20;
                } else
                    context->status = 20;
                // important to return (no lock held) !!
                if ((context->status_changed) && (context->status == 4))
                    context->status_changed(context);
                return 0;
            } else
                context->status = 20;
            break;
        case 4:
            if ((SC_WaitForCardRemoval(context->hContext, context->reader, 0)) || (SC_errno)) {
                context->status = 22;
                if (context->status_changed)
                    context->status_changed(context);
                context->public_key_len = 0;
                memset(context->public_key, 0, sizeof(context->public_key));
                memset(context->buf_name, 0, sizeof(context->buf_name));
            }
            break;
        case 20:
            SC_DisconnectCard(context->hCard);
            context->status = 21;
            context->timestamp = time(NULL);
            break;
        case 21:
            if ((SC_WaitForCardRemoval(context->hContext, context->reader, 0)) || (SC_errno))
                context->status = 22;
            else
            if (time(NULL) - context->timestamp >= 3)
                context->status = 22;
            break;
        case 22:
            SC_Disconnect(context->hContext);
            free(context->reader);
            context->reader = NULL;
            context->status = 0;
            break;
    }
    thread_mutex_unlock(&context->lock);
    return 0;
}

int edwork_smartcard_valid(struct edwork_smartcard_context *context) {
    if ((context) && (context->status == 4))
        return 1;

    return 0;
}

void edwork_smartcard_init(struct edwork_smartcard_context *context) {
    if (!context)
        return;
    memset(context, 0, sizeof(struct edwork_smartcard_context));
    thread_mutex_init(&context->lock);
}

void edwork_smartcard_done(struct edwork_smartcard_context *context) {
    if (!context)
        return;
    free(context->reader);
    context->reader = 0;
    thread_mutex_term(&context->lock);
}
