#include "edfs_js.h"
#include "log.h"
#include "edfs_key_data.h"
#include "edfs_core.h"

#if defined(_WIN32) || defined(__APPLE__)
    #define EDFS_UI

    #include "ui/htmlwindow.h"

    void edfs_tray_notify(void *menuwindow);
#endif

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
            "},\n"
            "\"readDir\": function(path, callback) {\n"
                "return __edfs_private_readdir(path, callback);"
            "},\n"
            "\"readSignature\": function(path, signature_index) {\n"
                "return __edfs_private_readsignature(path, signature_index);"
            "}\n"
        "},\n"
        "\"require\": function(path) {\n"
            "var obj = this.__edfs_private_modules[path];"
            "if (obj)"
                "return obj;"
            "var data = this.__edfs_private_readfile(path, true);"
            "if ((data) && (data.length)) {"
                "obj = eval(data);"
                "this.__edfs_private_modules[path] = obj;"
            "}"
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
        "\"__edfs_private_modules\": { },\n"
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
                    printsize = snprintf(fmt_buf, size, "[object ArrayBuffer]");
                } else
                if (duk_is_array(js, i)) {
                    printsize = snprintf(fmt_buf, size, "[object Array]");
                } else
                if (duk_is_function(js, i)) {
                    printsize = snprintf(fmt_buf, size, "[object Function]");
                } else
                if (duk_is_object(js, i)) {
                    printsize = snprintf(fmt_buf, size, "[object Object]");
                } else
                    printsize = snprintf(fmt_buf, size, "[object Unknown]");
                fmt_buf += printsize;
                size -= printsize;
                break;
            case DUK_TYPE_NULL:
                printsize = snprintf(fmt_buf, size, "(null)");
                fmt_buf += printsize;
                size -= printsize;
                break;
            case DUK_TYPE_NONE:
                printsize = snprintf(fmt_buf, size, "(none)");
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

static int exitApplication(duk_context *js) {
    alert(js);
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (key)
        key->js_exit = 1;
    return 0;
}

int edfs_js_error(duk_context *js, const char *msg) {
#ifdef EDFS_UI
    char title[0x100];
    __edfs_private_get_key_id(js, title);
    ui_message(title, msg, 2);
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
        const char *str = duk_get_string(js, 0);
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

static unsigned int edfs_js_add_directory(const char *name, uint64_t ino, int type, int64_t size, time_t created, time_t modified, time_t timestamp, void *jsptr) {
    if ((name) && (jsptr)) {
        duk_context *js = (duk_context *)jsptr;

        duk_dup(js, 1);
        duk_push_string(js, name);
        if (type & S_IFDIR)
            duk_push_true(js);
        else
            duk_push_false(js);

        duk_push_int(js, type);
        duk_push_number(js, (double)size);
        duk_push_number(js, (double)created);
        duk_push_number(js, (double)modified);
        duk_push_number(js, (double)timestamp);

        struct edfs_key_data *key = edfs_key_data_get_from_js(js);
        unsigned char old_js_lock = key->no_js_lock;
        key->no_js_lock = 1;
        duk_call(js, 7);
        key->no_js_lock = old_js_lock;

        int ret_val = 0;
        if (duk_get_type(js, -1))
            ret_val = duk_get_boolean(js, -1);

        duk_pop(js);

        // stop reading directory
        if (ret_val == 1)
            return 0x10000000;
    }
    return 1;
}

static int __edfs_private_readdir(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 1) && (duk_get_type(js, 0) == DUK_TYPE_STRING) && (duk_get_type(js, 1) == DUK_TYPE_OBJECT) && (duk_is_function(js, 1))) {
        const char *path = duk_get_string(js, 0);
        if (path) {
            uint64_t inode = edfs_pathtoinode_key(key, path, NULL, NULL);
            struct dirbuf *dbuf = edfs_opendir_key((struct edfs *)key->edfs_context, key, inode);
            if (!dbuf)
                return 0;
            
            int err = edfs_readdir((struct edfs *)key->edfs_context, inode, 0xFFFFFFF, 0, dbuf, edfs_js_add_directory, js);
            if (err)
                return 0;

            edfs_releasedir(dbuf);

            duk_push_boolean(js, 1);
            return 1;
        }
    }
    return 0;
}

static int __edfs_private_readsignature(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n >= 1) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        int sig_index = 0;
        if ((n > 1) && (duk_get_type(js, 1) == DUK_TYPE_NUMBER))
            sig_index = (int)duk_get_number(js, 1);

        const char *path = duk_get_string(js, 0);
        if (path) {
            uint64_t inode = edfs_pathtoinode_key(key, path, NULL, NULL);
            char *sig = edfs_smartcard_get_signature((struct edfs *)key->edfs_context, key, inode, sig_index);
            if (sig) {
                duk_push_string(js, sig);
                free(sig);
                return 1;
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
    JS_REGISTER(js, exitApplication);

    JS_REGISTER(js, __edfs_private_readfile);
    JS_REGISTER(js, __edfs_private_readdir);
    JS_REGISTER(js, __edfs_private_readsignature);

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

    duk_eval_string_noresult(js, api_buf);

    return 0;
}
