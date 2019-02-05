#ifndef __EDWORK_SMARTCARD_PLUGIN_H
#define __EDWORK_SMARTCARD_PLUGIN_H

#include "smartcard.h"

int edwork_plugin_init_smartcard(SCARDHANDLE hCard, DWORD protocol);
int edwork_plugin_deinit_smartcard(SCARDHANDLE hCard, DWORD protocol);
int edwork_plugin_verify_smartcard(SCARDHANDLE hCard, DWORD protocol, const char *pin, int len);
int edwork_plugin_get_id_data(SCARDHANDLE hCard, DWORD protocol, char *name, int *name_len, unsigned char *public_key, int *pub_len);
int edwork_plugin_sign_data(SCARDHANDLE hCard, DWORD protocol, const unsigned char *hash_data, int len, unsigned char *sig_data, int *sig_len);
int edwork_plugin_verify_data(SCARDHANDLE hCard, DWORD protocol, const unsigned char *hash_data, int len, const unsigned char *sig_data, int sig_len);

#endif
