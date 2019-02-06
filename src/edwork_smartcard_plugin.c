#include "edwork_smartcard_plugin.h"
#include "log.h"

// ============================ plugin helper macros ============================
#define TRY_APDU_DATA_RESPONSE(apdu, data, data_len, out, out_len)   if (!helper_do_expect_success(hCard, protocol, apdu, sizeof(apdu), (const unsigned char *)data, (int)data_len, out, out_len)) return 0;
#define TRY_APDU_RESPONSE(apdu, out, out_len)                        TRY_APDU_DATA_RESPONSE(apdu, NULL, 0, out, out_len)
#define TRY_APDU_DATA(apdu, data, data_len)                          TRY_APDU_DATA_RESPONSE(apdu, data, data_len, NULL, NULL)
#define TRY_APDU(apdu)                                               TRY_APDU_DATA(apdu, NULL, 0)
// =========================== /plugin helper macros ============================

// smartcard specific APDU (European ID Card)
static const unsigned char SELECT_ROOT[] = {0x00, 0xA4, 0x04, 0x04, 0x0B, 0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD6, 0x42, 0x00, 0x00, 0x01, 0x01, 0x00};
static const unsigned char SELECT_CERT[] = {0x00, 0xA4, 0x02, 0x0C, 0x02, 0xC0, 0x01, 0x00};
static const unsigned char SELECT_DATA[] = {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x01, 0x00};
static const unsigned char READ_FILE[]   = {0x00, 0xB0, 0x00, 0x00, 0x00};
static const unsigned char VERIFY_PIN[]  = {0x00, 0x20, 0x00, 0x81};
static const unsigned char MSU_RESTORE[] = {0x00, 0x22, 0xF3, 0x01, 0x00};
static const unsigned char SET_HASH[]    = {0x00, 0x2A, 0x90, 0xA0, 0x00, 0x90, 0x20};
static const unsigned char DO_SIGNATURE[]= {0x00, 0x2A, 0x9E, 0x9A, 0x00};

// ============================ plugin helper functions =========================
static void debug_buffer(const char *tag, LPBYTE data, int len) {
    fprintf(stderr, "%s: ", tag);
    for (int i = 0; i < len; i++)
            fprintf(stderr, "%02X ", (int)data[i]);
    fprintf(stderr, "\n");
}

static int helper_do_expect_success(SCARDHANDLE hCard, DWORD protocol, const unsigned char *use_apdu, int apdu_len, const unsigned char *data, int data_len, unsigned char *output, int *out_len) {
    BYTE baResponseApdu[300];
    DWORD lResponseApduLen = sizeof(baResponseApdu);
    LPBYTE apdu;

    if ((!use_apdu) || (apdu_len <= 0) || (data_len < 0) || ((data_len) && (!data)))
        return 0;

    int buf_len = apdu_len;
    if ((data) && (data_len)) {
        int apdu_len2 = apdu_len < 5 ? 5 : apdu_len;
        buf_len = apdu_len2 + data_len + 1;
        apdu = (LPBYTE)malloc(buf_len);
        if (!apdu)
            return 0;
  
        memcpy(apdu, use_apdu, apdu_len);
        memcpy(apdu + apdu_len2, data, data_len);
        apdu[4] = (BYTE)data_len;
        if (apdu_len > 5)
            apdu[4] += (BYTE)(apdu_len - 5);
        apdu[buf_len - 1] = 0;
    } else
        apdu = (LPBYTE)use_apdu;

    // debug_buffer("sent", apdu, buf_len);
    if (SC_Exchange(hCard, protocol, apdu, buf_len, baResponseApdu, &lResponseApduLen)) {
        if (apdu != use_apdu)
            free(apdu);
        // debug_buffer("received", baResponseApdu, lResponseApduLen);
        if ((lResponseApduLen >= 2) && (baResponseApdu[lResponseApduLen - 2] == 0x90) && (baResponseApdu[lResponseApduLen - 1] == 0x00)) {
            if ((out_len) && (*out_len > 0) && (output)) {
                int len = lResponseApduLen - 2;
                if (*out_len > len)
                    *out_len = len;
                memcpy(output, baResponseApdu, *out_len);
            }
            return 1;
        }
    } else {
        if (apdu != use_apdu)
            free(apdu);
        log_error("smartcard error %x: %s", (int)SC_errno, SC_GetErrorString(SC_errno));
    }
    return 0;
}
// ============================ /plugin helper functions ========================

int edwork_plugin_init_smartcard(SCARDHANDLE hCard, DWORD protocol) {
    TRY_APDU(SELECT_ROOT);
    return 1;
}

int edwork_plugin_deinit_smartcard(SCARDHANDLE hCard, DWORD protocol) {
    // nothing special to do
    return 1;
}

int edwork_plugin_verify_smartcard(SCARDHANDLE hCard, DWORD protocol, const char *pin, int len) {
    // avoid query for invalid PIN numbers
    if ((!pin) || (len < 4))
        return 0;
    TRY_APDU_DATA(VERIFY_PIN, pin, len);
    return 1;
}

int edwork_plugin_get_id_data(SCARDHANDLE hCard, DWORD protocol, char *name, int *name_len, unsigned char *public_key, int *pub_len) {
    unsigned char buf[0x100];
    int data_size = sizeof(buf);
    TRY_APDU(SELECT_DATA);
    if (name) {
        *name = 0;
        TRY_APDU_RESPONSE(READ_FILE, buf, &data_size);
        int limit = data_size - 4;
        int str_size;
        int name_count = 0;
        int i = 2;
        while (i < limit) {
            if (!buf[i + 1])
                break;

            switch (buf[i]) {
                case 0xA1:
                case 0xA2:
                    // name
                    if (buf[i + 2] == 0x0C) {
                        // string
                        str_size = buf[i + 3];
                        if (i + str_size < limit) {
                            if (name_count) {
                                *name = ' ';
                                name ++;
                            }
                            memcpy(name, &buf[i + 4], str_size);
                            name += str_size;
                            *name = 0;
                            name_count ++;
                        }
                    }
                    i += buf[i + 1] + 1;
                    break;
                default:
                    i += buf[i + 1] + 1;
                    break;
            }
            i ++;
        }
    }

    TRY_APDU(SELECT_CERT);
    if ((public_key) && (pub_len) && (*pub_len)) {
        TRY_APDU_RESPONSE(READ_FILE, public_key, pub_len);
    }
    return 1;
}

int edwork_plugin_sign_data(SCARDHANDLE hCard, DWORD protocol, const unsigned char *hash_data, int len, unsigned char *sig_data, int *sig_len) {
    TRY_APDU(SELECT_CERT);
    TRY_APDU(MSU_RESTORE);
    TRY_APDU_DATA(SET_HASH, hash_data, len);
    TRY_APDU_RESPONSE(DO_SIGNATURE, sig_data, sig_len);
    return 1;
}

int edwork_plugin_verify_data(SCARDHANDLE hCard, DWORD protocol, const unsigned char *hash_data, int len, const unsigned char *sig_data, int sig_len) {
    TRY_APDU(SELECT_CERT);
    TRY_APDU(MSU_RESTORE);
    // not implemented
    return 0;
}
