#include "edfs_js.h"
#include "log.h"
#include "edfs_key_data.h"

#if defined(_WIN32) || defined(__APPLE__)
    #define EDFS_UI

    #include "ui/htmlwindow.h"

    void edfs_tray_notify(void *menuwindow);
#endif

struct edfs;
char *edfs_key_id(void *key, char *buffer);
char *edfs_public_key(void *key, char *buffer);
char *edfs_private_key(void *key, char *buffer);
char *edfs_lazy_read_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *filename, int *file_size);

#define JS_REGISTER(js, js_c_function)  edfs_js_register(js, js_c_function, #js_c_function)

static const char EDFS_JS_API[] = ""
    "var edwork = {\n"
        "\"key\": {\n"
            "\"id\": \"%s\",\n"
            "\"read\": \"%s\",\n"
            "\"write\": \"%s\"\n"
        "},\n"
        "\"ui\": {\n"
            "\"alert\": alert,\n"
            "\"input\": input,\n"
            "\"confirm\": confirm,\n"
            "\"notify\": __edfs_private_notify\n"
        "},\n"
        "\"fs\": {\n"
            "\"readFile\": function(filename, encoding, callback) {\n"
                "if (callback) {\n"
                    "var buffer = __edfs_private_readfile(filename, encoding ? true : false);\n"
                    "callback(buffer);\n"
                    "return;\n"
                "}\n"
                "return __edfs_private_readfile(filename, encoding ? true : false);\n"
            "}\n"
        "},\n"
        "\"smartcard\": {\n"
            "\"request\": __edfs_private_request,\n"
            "\"disconnect\": __edfs_private_disconnect,\n"
            "\"connected\": __edfs_private_connected\n"
        "},\n"
        "\"events\": {\n"
        "},\n"
        "\"queue\": function(looper) {\n"
            "this.__edfs_private_pending.push(looper);\n"
        "},\n"
        "\"__edfs_private_pending\": [ ],\n"
        "\"__edfs_loop\": function() {\n"
            "if (this.__edfs_private_pending.length === 0)\n"
                "return;\n"
            "var __new_edfs_private_pending = [ ];\n"
            "for (var i = 0; i < this.__edfs_private_pending.length; i ++) {\n"
                "try {\n"
                    "var __run = this.__edfs_private_pending[i];\n"
                    "if (!__run())\n"
                        "__new_edfs_private_pending.push(__run);\n"
                "} catch (e) {\n"
                    "console.error(e.toString());\n"
                "}\n"
            "}\n"
            "if (__new_edfs_private_pending.length !== this.__edfs_private_pending.length)\n"
                "this.__edfs_private_pending = __new_edfs_private_pending;\n"
        "}\n"
    "};\n"
    "var console = {\n"
        "\"log\": __edfs_private_log,\n"
        "\"warn\": __edfs_private_warn,\n"
        "\"error\": __edfs_private_error,\n"
        "\"trace\": __edfs_private_trace,\n"
        "\"info\": __edfs_private_info,\n"
        "\"debug\": __edfs_private_debug\n"
    "};\n";

static void __edfs_private_get_key_id(duk_context *js, char *buf) {
    if (buf)
        buf[0] = 0;
    if ((!js) || (!buf))
        return;

    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return;

    edfs_key_id(key, buf);
}

static void __edfs_private_get_fmt(duk_context *js, char *fmt_buf, int size) {
    int n = duk_get_top(js);
    int i;
    duk_size_t printsize;
    for (i = 0; i < n; i++) {
        if (i) {
            printsize = snprintf(fmt_buf, size, "\t");
            fmt_buf += printsize;
            size -= printsize;
            if (size <= 0)
                break;
        }
        switch (duk_get_type(js, i)) {
            case DUK_TYPE_NUMBER:
                printsize = snprintf(fmt_buf, size, "%f", duk_get_number(js, i));
                fmt_buf += printsize;
                size -= printsize;
                break;
            case DUK_TYPE_STRING: 
                {
                    const char *str = duk_get_lstring(js, i, &printsize);
                    if (printsize > 0) {
                        if (printsize > size - 1)
                            printsize = size - 1;
                        memcpy(fmt_buf, str, printsize);
                        fmt_buf += printsize;
                        size -= printsize;
                        fmt_buf[0] = 0;
                    }
                }
                break;
            case DUK_TYPE_BUFFER:
                {
                    void *ptr;

                    ptr = duk_get_buffer_data(js, i, &printsize);
                    if (printsize > 0) {
                        if (printsize > size - 1)
                            printsize = size - 1;
                        memcpy(fmt_buf, ptr, printsize);
                        fmt_buf += printsize;
                        size -= printsize;
                        fmt_buf[0] = 0;
                    }
                }
                break;
            case DUK_TYPE_BOOLEAN:
                if (duk_get_boolean(js, i))
                    printsize = snprintf(fmt_buf, size, "true");
                else
                    printsize = snprintf(fmt_buf, size, "false");
                fmt_buf += printsize;
                size -= printsize;
                break;
            case DUK_TYPE_OBJECT:
                if (duk_is_buffer_data(js, i)) {
                    printsize = snprintf(fmt_buf, size, "[ArrayBuffer]");
                } else
                if (duk_is_array(js, i)) {
                    printsize = snprintf(fmt_buf, size, "[Array]");
                } else
                if (duk_is_function(js, i)) {
                    printsize = snprintf(fmt_buf, size, "[ArrayBuffer]");
                } else
                if (duk_is_object(js, i)) {
                    printsize = snprintf(fmt_buf, size, "[Object object]");
                } else
                    printsize = snprintf(fmt_buf, size, "[Unknown]");
                fmt_buf += printsize;
                size -= printsize;
                break;
        }
        if (size <= 0)
            break;
    }
}

static int __edfs_private_log(duk_context *js) {
    char str[8192];
    __edfs_private_get_fmt(js, str, sizeof(str));
    log_info("%s", str);
    return 0;
}

static int __edfs_private_warn(duk_context *js) {
    char str[8192];
    __edfs_private_get_fmt(js, str, sizeof(str));
    log_warn("%s", str);
    return 0;
}

static int __edfs_private_error(duk_context *js) {
    char str[8192];
    __edfs_private_get_fmt(js, str, sizeof(str));
    log_error("%s", str);
    return 0;
}

static int __edfs_private_trace(duk_context *js) {
    char str[8192];
    __edfs_private_get_fmt(js, str, sizeof(str));
    log_trace("%s", str);
    return 0;
}

static int __edfs_private_info(duk_context *js) {
    __edfs_private_log(js);
    return 0;
}

static int __edfs_private_debug(duk_context *js) {
    char str[8192];
    __edfs_private_get_fmt(js, str, sizeof(str));
    log_debug("%s", str);
    return 0;
}

static int __edfs_private_request(duk_context *js) {
    return 0;
}

static int __edfs_private_disconnect(duk_context *js) {
    return 0;
}

static int __edfs_private_connected(duk_context *js) {
    duk_push_false(js);
    return 1;
}

static int alert(duk_context *js) {
    char str[8192];
    char title[0x100];
    __edfs_private_get_fmt(js, str, sizeof(str));
    __edfs_private_get_key_id(js, title);
    log_warn("%s: %s", title, str, 0);
#ifdef EDFS_UI
    ui_message(title, str, 0);
#endif
    return 0;
}

static int input(duk_context *js) {
    char str[8192];
    char input_data[0x100];
    char title[0x100];
    __edfs_private_get_fmt(js, str, sizeof(str));
    __edfs_private_get_key_id(js, title);
    log_debug("%s: %s", title, str, 0);
#ifdef EDFS_UI
    int ok = ui_input(title, str,  input_data, sizeof(input_data), 1);
    if (ok) {
        duk_push_string(js, input_data);
        return 1;
    }
#endif
    return 0;
}

static int confirm(duk_context *js) {
    char str[8192];
    char title[0x100];
    __edfs_private_get_fmt(js, str, sizeof(str));
    __edfs_private_get_key_id(js, title);
    log_debug("%s: %s", title, str, 0);
#ifdef EDFS_UI
    int ok = ui_question(title, str,  0);
    duk_push_boolean(js, ok);
    return 1;
#endif
    return 0;
}

static int __edfs_private_notify(duk_context *js) {
    char str[8192];
    char title[0x100];
    __edfs_private_get_fmt(js, str, sizeof(str));
    __edfs_private_get_key_id(js, title);
    log_info("%s: %s", title, str, 0);

#ifdef EDFS_UI
    ui_app_tray_icon(title, str, title, edfs_tray_notify);
#endif
    return 0;
}

static int __edfs_private_readfile(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        duk_size_t printsize = 0;
        const char *str = duk_get_lstring(js, 0, &printsize);
        if (str) {
            int file_size = 0;
            char *buffer = edfs_lazy_read_file((struct edfs *)key->edfs_context, key, str, &file_size);
            if ((n > 1) && (duk_get_type(js, 1) == DUK_TYPE_BOOLEAN) && (duk_get_boolean(js, 1))) {
                if (buffer) {
                    duk_push_string(js, buffer);
                    free(buffer);
                    return 1;
                } else
                if (file_size == 0) {
                    duk_push_string(js, "");
                    return 1;
                }
            } else {
                if ((buffer) && (file_size > 0)) {
                    void *arraybuffer = duk_push_fixed_buffer(js, file_size);
                    if (arraybuffer)
                        memcpy(arraybuffer, buffer, file_size);
                    free(buffer);
                    return 1;
                } else
                if (file_size == 0) {
                    duk_push_fixed_buffer(js, 0);
                    return 1;
                }
            }
        }
    }
    return 0;
}

static void edfs_js_register(duk_context *js, duk_c_function c_js_function, const char *name) {
    duk_push_global_object(js);
    duk_push_c_function(js, c_js_function, DUK_VARARGS);
    duk_put_prop_string(js, -2, name);
    duk_pop(js);
}

int edfs_js_register_all(duk_context *js) {
    if (!js)
        return -1;

    JS_REGISTER(js, __edfs_private_log);
    JS_REGISTER(js, __edfs_private_warn);
    JS_REGISTER(js, __edfs_private_error);
    JS_REGISTER(js, __edfs_private_trace);
    JS_REGISTER(js, __edfs_private_info);
    JS_REGISTER(js, __edfs_private_debug);

    JS_REGISTER(js, __edfs_private_request);
    JS_REGISTER(js, __edfs_private_disconnect);
    JS_REGISTER(js, __edfs_private_connected);

    JS_REGISTER(js, alert);
    JS_REGISTER(js, input);
    JS_REGISTER(js, confirm); 
    JS_REGISTER(js, __edfs_private_notify);

    JS_REGISTER(js, __edfs_private_readfile);

    char api_buf[8192];
    char key_id[256];
    char public_key[256];
    char private_key[256];

    key_id[0] = 0;
    public_key[0] = 0;
    private_key[0] = 0;

    __edfs_private_get_key_id(js, key_id);

    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (key) {
        edfs_public_key(key, public_key);
        edfs_private_key(key, private_key);
    }

    snprintf(api_buf, sizeof(api_buf), EDFS_JS_API, key_id, public_key, private_key);

    duk_eval_string(js, api_buf);
    duk_pop(js);

    return 0;
}
