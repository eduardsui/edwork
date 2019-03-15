#include <errno.h>
#include <fcntl.h>

#include "edfs_js.h"
#include "log.h"
#include "edfs_key_data.h"
#include "edfs_core.h"

#if defined(_WIN32) || defined(__APPLE__)
    #define EDFS_UI

    #include "ui/htmlwindow.h"

    void edfs_tray_notify(void *menuwindow);
#endif

char *edfs_lazy_read_file(struct edfs *edfs_context, struct edfs_key_data *key, const char *filename, int *file_size, uint64_t offset, int max_size);

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
            "\"notify\": __edfs_private_notify,\n"
            "\"window\": __edfs_private_window,\n"
            "\"close\": __edfs_private_close,\n"
            "\"restore\": __edfs_private_restore,\n"
            "\"top\": __edfs_private_top,\n"
            "\"maximize\": __edfs_private_maximize,\n"
            "\"minimize\": __edfs_private_minimize,\n"
            "\"js\": __edfs_private_execute,\n"
            "\"call\": function(method, arg, callback) { var self = this; this.__windowcallback = function(str) { callback(str); delete self.__windowcallback; }; return __edfs_private_call(method, (typeof arg === \"string\") ? arg : JSON.stringify(arg)); },\n"
            "\"isVisible\": __edfs_private_is_visible\n"
        "},\n"
        "\"fs\": {\n"
            "\"readFile\": function(filename, encoding, callback, offset, max_size) {\n"
                "if (callback) {\n"
                    "var buffer = __edfs_private_readfile(filename, encoding ? true : false, offset, max_size);\n"
                    "callback(buffer);\n"
                    "return;\n"
                "}\n"
                "return __edfs_private_readfile(filename, encoding ? true : false, offset, max_size);\n"
            "},\n"
            "\"writeFile\": function(filename, data, offset) {\n"
                "return __edfs_private_writefile(filename, data, offset);\n"
            "},\n"
            "\"truncate\": function(filename, offset) {\n"
                "return __edfs_private_truncate(filename, offset);\n"
            "},\n"
            "\"exists\": function(filename) {\n"
                "return __edfs_private_exists(filename);\n"
            "},\n"
            "\"isDirectory\": function(filename) {\n"
                "return __edfs_private_is_directory(filename);\n"
            "},\n"
            "\"readDir\": function(path, callback) {\n"
                "return __edfs_private_readdir(path, callback);"
            "},\n"
            "\"readSignature\": function(path, signature_index) {\n"
                "return __edfs_private_readsignature(path, signature_index);"
            "}\n,"
            "\"mkdir\": function(path) {\n"
                "return __edfs_private_mkdir(path);\n"
            "},\n"
            "\"rmdir\": function(path) {\n"
                "return __edfs_private_rmdir(path);\n"
            "},\n"
            "\"unlink\": function(path) {\n"
                "return __edfs_private_unlink(path);\n"
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
        "},\n"
        "\"setTimeout\": function(callback, ms) {\n"
            "var when = (new Date()).getTime() + ms;\n"
            "this.queue(function() {\n"
                "if ((new Date()).getTime() >= when) {\n"
                    "callback();\n"
                    "return true;\n"
                "}\n"
            "});\n"
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

struct edfs_private_ui_data {
    struct edfs_key_data *key;
    union {
        char *buffer;
        int int_val;
    } buffer0;
    union {
        char *buffer;
        int int_val;
    } buffer1;
    char *argv;
};

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

#ifdef EDFS_UI
static void __edfs_private_ui_window_create_or_set_content(void *data) {
    if (!data)
        return;

    struct edfs_private_ui_data *ui_context = (struct edfs_private_ui_data *)data;
    if (ui_context->key->js_window)
        ui_window_set_content(ui_context->key->js_window, ui_context->buffer1.buffer);
    else
        ui_context->key->js_window = ui_window(ui_context->buffer0.buffer, ui_context->buffer1.buffer);
    ui_window_restore(ui_context->key->js_window);
    ui_window_top(ui_context->key->js_window);

    free(ui_context->buffer0.buffer);
    free(ui_context->buffer1.buffer);
    free(ui_context);
}

static void __edfs_private_ui_window_action(void *data) {
    if (!data)
        return;

    struct edfs_private_ui_data *ui_context = (struct edfs_private_ui_data *)data;
    if (ui_context->key->js_window) {
        switch (ui_context->buffer0.int_val) {
            case 1:
                log_debug("close window");
                ui_window_close(ui_context->key->js_window);
                ui_context->key->js_window = NULL;
                break;
            case 2:
                log_debug("restore window");
                ui_window_restore(ui_context->key->js_window);
                break;
            case 3:
                log_debug("bring window to top");
                ui_window_top(ui_context->key->js_window);
                break;
            case 4:
                log_debug("maximize window");
                ui_window_maximize(ui_context->key->js_window);
                break;
            case 5:
                log_debug("minimize window");
                ui_window_minimize(ui_context->key->js_window);
                break;
            case 6:
                log_debug("executing UI JS code: %s", ui_context->buffer1.buffer);
                ui_js(ui_context->key->js_window, ui_context->buffer1.buffer);
                free(ui_context->buffer1.buffer);
                free(ui_context->argv);
                break;
            case 7:
                {
                    const char *argv[2];
                    argv[0] = ui_context->argv;
                    argv[1] = NULL;

                    char *val = ui_call(ui_context->key->js_window, ui_context->buffer1.buffer, argv);
                    log_debug("UI JS function call: %s = %s(%s)", val, ui_context->buffer1.buffer, argv);
                    if (ui_context->key->js)
                        edfs_key_js_call_safe(ui_context->key, "edwork.ui.__windowcallback", val, NULL);
                    if (val)
                        ui_free_string(val);

                    free(ui_context->buffer1.buffer);
                    free(ui_context->argv);
                }
                break;
            default:
                log_error("unknown command %i", (int)ui_context->buffer0.int_val);
        }
    } else
        log_warn("no window");
    free(ui_context);
}
#endif

static int __edfs_private_window(duk_context *js) {
    char title[0x100];
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;
    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        const char *str_title = NULL;
        if ((n > 1) && (duk_get_type(js, 1) == DUK_TYPE_STRING))
            str_title = duk_get_string(js, 1);
        if ((!str_title) || (!str_title[0])) {
            __edfs_private_get_key_id(js, title);
            str_title = title;
        }
        log_info("[====== %s ======]:\n%s", str_title, str);
#ifdef EDFS_UI
        struct edfs_private_ui_data *ui_context = malloc(sizeof(struct edfs_private_ui_data));
        if (ui_context) {
            ui_context->key = key;
            ui_context->buffer0.buffer = strdup(str_title ? str_title : "");
            ui_context->buffer1.buffer = strdup(str ? str : "");
            ui_app_run_schedule_once(__edfs_private_ui_window_create_or_set_content, ui_context);
            duk_push_boolean(js, 1);
            return 1;
        }
#endif
    }
    duk_push_boolean(js, 0);
    return 1;
}

static int __edfs_private_action(duk_context *js, int action, const char *buffer, int get_values) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;
#ifdef EDFS_UI
    if (key->js_window) {
        struct edfs_private_ui_data *ui_context = malloc(sizeof(struct edfs_private_ui_data));
        if (ui_context) {
            ui_context->key = key;
            ui_context->buffer0.int_val = action;
            ui_context->buffer1.buffer = buffer ? strdup(buffer) : NULL;
            ui_context->argv = NULL;
            if (get_values > 0) {
                int n = duk_get_top(js);
                if ((n > 1) && (duk_get_type(js, 1) == DUK_TYPE_STRING)) {
                    const char *str = duk_get_string(js, 1);
                    ui_context->argv = strdup(str ? str : "");
                }
            }
            ui_app_run_schedule_once(__edfs_private_ui_window_action, ui_context);
            duk_push_boolean(js, 1);
            return 1;
        }
    }
#endif
    duk_push_boolean(js, 0);
    return 1;
}

static int __edfs_private_close(duk_context *js) {
    return __edfs_private_action(js, 1, NULL, 0);
}

static int __edfs_private_restore(duk_context *js) {
    return __edfs_private_action(js, 2, NULL, 0);
}

static int __edfs_private_top(duk_context *js) {
    return __edfs_private_action(js, 3, NULL, 0);
}

static int __edfs_private_maximize(duk_context *js) {
    return __edfs_private_action(js, 4, NULL, 0);
}

static int __edfs_private_minimize(duk_context *js) {
    return __edfs_private_action(js, 5, NULL, 0);
}

static int __edfs_private_execute(duk_context *js) {
    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING))
        return __edfs_private_action(js, 6, duk_get_string(js, 0), 0);
    return 0;
}

static int __edfs_private_call(duk_context *js) {
    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING))
        return __edfs_private_action(js, 7, duk_get_string(js, 0), 1);
    return 0;
}

static int __edfs_private_is_visible(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;
#ifdef EDFS_UI
    if (key->js_window) {
        duk_push_boolean(js, 1);
        return 1;
    }
#endif
    duk_push_boolean(js, 0);
    return 1;
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
            uint64_t offset = 0;
            int max_size = 0;
            if ((n > 2) && (duk_get_type(js, 2) == DUK_TYPE_NUMBER)) {
                double offset_as_double = duk_get_number(js, 2);
                if (offset_as_double > 0)
                    offset = (uint64_t)offset_as_double;
            }
            if ((n > 3) && (duk_get_type(js, 3) == DUK_TYPE_NUMBER)) {
                max_size = duk_get_int(js, 3);
                if (max_size < 0)
                    max_size = 0;
            }
            char *buffer = edfs_lazy_read_file((struct edfs *)key->edfs_context, key, str, &file_size, offset, max_size);
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

static int __edfs_private_writefile(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 1) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        if (str) {
            uint64_t offset = 0;
            int max_size = 0;
            uint64_t parentinode = 0;
            const char *name = NULL;
            uint64_t inode = edfs_pathtoinode_key(key, str, &parentinode, &name);
            if ((n > 2) && (duk_get_type(js, 2) == DUK_TYPE_NUMBER)) {
                double offset_as_double = duk_get_number(js, 2);
                if (offset_as_double > 0) {
                    offset = (uint64_t)offset_as_double;
                } else
                if (offset_as_double < 0) {
                    edfs_stat stbuf;
                    if (!edfs_getattr_key((struct edfs *)key->edfs_context, key, inode, &stbuf))
                        offset = stbuf.st_size;
                }
            }

            int type = duk_get_type(js, 1);
            if ((type != DUK_TYPE_BUFFER) && (type != DUK_TYPE_STRING))
                return 0;

            struct filewritebuf *fbuf;
            int err = edfs_open_key((struct edfs *)key->edfs_context, key, inode, O_RDWR, &fbuf);
            if (err == -EACCES)
                err = edfs_create_with_key((struct edfs *)key->edfs_context, key, parentinode, name, 0644, &inode, &fbuf);
            
            if (err) {
                duk_push_int(js, err);
                return 1;
            }

            const char *buf = NULL;
            duk_size_t buf_size = 0;

            if (type == DUK_TYPE_STRING)
                buf = duk_get_lstring(js, 1, &buf_size);
            else
                buf = (const char *)duk_get_buffer_data(js, 1, &buf_size);

            int written = edfs_write((struct edfs *)key->edfs_context, inode, buf, buf_size, (int64_t)offset, fbuf);
            edfs_close((struct edfs *)key->edfs_context, fbuf);

            duk_push_int(js, written);
            return 1;
        }
    }
    return 0;
}

static int __edfs_private_truncate(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        if (str) {
            uint64_t offset = 0;
            if ((n > 1) && (duk_get_type(js, 1) == DUK_TYPE_NUMBER)) {
                double offset_as_double = duk_get_number(js, 1);
                if (offset_as_double > 0)
                    offset = (uint64_t)offset_as_double;
            }
            uint64_t inode = edfs_pathtoinode_key(key, str, NULL, NULL);
            duk_push_int(js, edfs_set_size_key((struct edfs *)key->edfs_context, key, inode, offset));
            return 1;
        }
    }
    return 0;
}

static int __edfs_private_exists(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        if (str) {
            uint64_t inode = edfs_pathtoinode_key(key, str, NULL, NULL);
            edfs_stat stbuf;
            int err = edfs_getattr_key((struct edfs *)key->edfs_context, key, inode, &stbuf);
            if (!err) {
                duk_push_true(js);
                return 1;
            }
        }
    }
    return 0;
}

static int __edfs_private_is_directory(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        if (str) {
            uint64_t inode = edfs_pathtoinode_key(key, str, NULL, NULL);
            edfs_stat stbuf;
            int err = edfs_getattr_key((struct edfs *)key->edfs_context, key, inode, &stbuf);
            if (!err) {
                if (stbuf.st_mode & S_IFDIR)
                    duk_push_true(js);
                else
                    duk_push_false(js);
                return 1;
            }
        }
    }
    return 0;
}

static int __edfs_private_mkdir(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        if (str) {
            uint64_t parentinode = 0;
            const char *name = NULL;
            edfs_pathtoinode_key(key, str, &parentinode, &name);
            int err = edfs_mkdir_key((struct edfs *)key->edfs_context, key, parentinode, name, 0755);
            if (err > 0)
                err = 0;
            duk_push_int(js, err);
            return 1;
        }
    }
    return 0;
}

static int __edfs_private_rmdir(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        if (str) {
            uint64_t parentinode = 0;
            uint64_t inode = edfs_pathtoinode_key(key, str, &parentinode, NULL);
            duk_push_int(js, edfs_rmdir_inode_key((struct edfs *)key->edfs_context, key, parentinode, inode));
            return 1;
        }
    }
    return 0;
}

static int __edfs_private_unlink(duk_context *js) {
    struct edfs_key_data *key = edfs_key_data_get_from_js(js);
    if (!key)
        return 0;

    int n = duk_get_top(js);
    if ((n > 0) && (duk_get_type(js, 0) == DUK_TYPE_STRING)) {
        const char *str = duk_get_string(js, 0);
        if (str) {
            uint64_t parentinode = 0;
            uint64_t inode = edfs_pathtoinode_key(key, str, &parentinode, NULL);
            duk_push_int(js, edfs_unlink_inode_key((struct edfs *)key->edfs_context, key, parentinode, inode));
            return 1;
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
    JS_REGISTER(js, __edfs_private_window);
    JS_REGISTER(js, __edfs_private_close);
    JS_REGISTER(js, __edfs_private_restore);
    JS_REGISTER(js, __edfs_private_top);
    JS_REGISTER(js, __edfs_private_maximize);
    JS_REGISTER(js, __edfs_private_minimize);
    JS_REGISTER(js, __edfs_private_execute);
    JS_REGISTER(js, __edfs_private_call);
    JS_REGISTER(js, __edfs_private_is_visible);

    JS_REGISTER(js, exitApplication);

    JS_REGISTER(js, __edfs_private_readfile);
    JS_REGISTER(js, __edfs_private_writefile);
    JS_REGISTER(js, __edfs_private_truncate);
    JS_REGISTER(js, __edfs_private_exists);
    JS_REGISTER(js, __edfs_private_is_directory);
    JS_REGISTER(js, __edfs_private_mkdir);
    JS_REGISTER(js, __edfs_private_rmdir);
    JS_REGISTER(js, __edfs_private_unlink);

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
