#ifndef __EDWORK_SMARTCARD_H
#define __EDWORK_SMARTCARD_H

#include <time.h>
#include "smartcard.h"
#include "thread.h"

struct edwork_smartcard_context;

typedef void (*edwork_smartcard_ui_callback)(struct edwork_smartcard_context *context);

struct edwork_smartcard_context {
    SCARDCONTEXT hContext;
    char *reader;

    SCARDHANDLE hCard;
    DWORD protocol;

    char buf_name[0x100];
    char public_key[1024];
    int public_key_len;

    time_t timestamp;
    int status;

    thread_mutex_t lock;

    edwork_smartcard_ui_callback status_changed;
};

void edwork_smartcard_init(struct edwork_smartcard_context *context);
int edwork_smartcard_iterate(struct edwork_smartcard_context *context);
int edwork_smartcard_sign(struct edwork_smartcard_context *context, const unsigned char *buffer, int buf_len, unsigned char *signature, int sig_len);
int edwork_smartcard_verify(struct edwork_smartcard_context *context, const unsigned char *buffer, int buf_len, const unsigned char *signature, int sig_len);
int edwork_smartcard_valid(struct edwork_smartcard_context *context);
void edwork_smartcard_done(struct edwork_smartcard_context *context);

#endif
