#include <CoreFoundation/CoreFoundation.h>
#include <objc/objc.h>
#include <objc/objc-runtime.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <objc/NSObjCRuntime.h>
#include "htmlwindow.h"

int NSRunAlertPanel(CFStringRef strTitle, CFStringRef strMsg, CFStringRef strButton1, CFStringRef strButton2, CFStringRef strButton3, ...);

static id pool;
static id app;

Class AppDelClass;
Class WebViewClass;

static ui_idle_event idle_event = NULL;
static void *idle_userdata = NULL;
static ui_trigger_event callback_event = NULL;
static int window_count = 0;
static int content_set = 0;

enum {
    NSBorderlessWindowMask      = 0,
    NSTitledWindowMask          = 1 << 0,
    NSClosableWindowMask        = 1 << 1,
    NSMiniaturizableWindowMask  = 1 << 2,
    NSResizableWindowMask       = 1 << 3,
};

typedef struct CMPoint {
    double x;
    double y;
} CMPoint;

typedef struct CMSize {
    double width;
    double height;
} CMSize;

typedef struct CMRect {
    CMPoint origin;
    CMSize size;
} CMRect;

typedef struct AppDel {
    Class isa;    
    id window;
} AppDelegate;

void *ui_window(const char *title, const char *body) {
    id window = objc_msgSend((id)objc_getClass("NSWindow"), sel_getUid("alloc"));
    window = objc_msgSend(window, sel_getUid("initWithContentRect:styleMask:backing:defer:"), (CMRect){0,0,800,600}, (NSTitledWindowMask | NSClosableWindowMask | NSResizableWindowMask | NSMiniaturizableWindowMask), 0, false);
    objc_msgSend(window, sel_getUid("center"));

    if (title) {
        CFStringRef title_str = CFStringCreateWithCString(NULL, title, kCFStringEncodingMacRoman);
        objc_msgSend(window, sel_getUid("setTitle:"), title_str);
        if (title_str)
            CFRelease(title_str);
    }
    objc_msgSend(window, sel_getUid("setDelegate:"), objc_msgSend(app, sel_getUid("delegate")));
    
    id view = objc_msgSend(objc_msgSend((id)objc_getClass("WKWebView"), sel_getUid("alloc")), sel_getUid("init"));

    objc_msgSend(view, sel_getUid("setNavigationDelegate:"), objc_msgSend(app, sel_getUid("delegate")));

    if (body) {
        CFStringRef body_str = CFStringCreateWithCString(NULL, body, kCFStringEncodingMacRoman);

        objc_msgSend(view, sel_getUid("loadHTMLString:baseURL:"), body_str, NULL);
        content_set ++;
        if (body_str)
            CFRelease(body_str);
    }
    objc_msgSend(window, sel_getUid("setContentView:"), view);
    objc_msgSend(window, sel_getUid("becomeFirstResponder"));
    objc_msgSend(window, sel_getUid("makeKeyAndOrderFront:"), objc_msgSend(app, sel_getUid("delegate")));

    window_count ++;
    return window;
}

void ui_window_set_content(void *window, const char *body) {
    CFStringRef body_str = CFStringCreateWithCString(NULL, body ? body : "", kCFStringEncodingMacRoman);

    objc_msgSend(objc_msgSend(objc_msgSend(window, sel_getUid("contentView")), sel_getUid("mainFrame")), sel_getUid("loadHTMLString:baseURL:"), body_str, NULL);
    content_set ++;
    if (body_str)
        CFRelease(body_str);
}

void ui_window_close(void *window) {
    if (!window)
        return;
    objc_msgSend(window, sel_getUid("close"));
}

BOOL AppDel_applicationDidUpdate(AppDelegate *self, SEL _cmd, id notification) {
    if (idle_event)
        idle_event(idle_userdata);
    return YES;
}

BOOL AppDel_didFinishLaunching(AppDelegate *self, SEL _cmd, id notification) {
    return YES;
}

void windowWillClose(id self, SEL _sel, id notification) {
    window_count --;
    if (window_count <= 0)
        ui_app_quit();
}

char *CFStringCopyUTF8String(CFStringRef aString) {
    if (aString == NULL)
        return NULL;

    CFIndex length = CFStringGetLength(aString);
    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    char *buffer = (char *)malloc(maxSize);
    if (CFStringGetCString(aString, buffer, maxSize, kCFStringEncodingUTF8))
        return buffer;
    free(buffer); // If we failed
    return NULL;
}

void WebView_decidePolicyFor(id self, SEL _cmd, id webView, id response, void (^decisionHandler)(int)) {
    char *url = CFStringCopyUTF8String((CFStringRef)objc_msgSend(objc_msgSend(objc_msgSend(response, sel_getUid("request")), sel_getUid("URL")), sel_getUid("scheme")));
    
    if ((url) && (!strcmp(url, "ui"))) {
        if (callback_event)
            callback_event(NULL);
        decisionHandler(0);
        ui_free_string(url);
        return;
    }

    ui_free_string(url);
    decisionHandler(1);
}

static void CreateAppDelegate() {
    AppDelClass = objc_allocateClassPair((Class)objc_getClass("NSObject"), "AppDelegate", 0);
    class_addMethod(AppDelClass, sel_getUid("applicationDidFinishLaunching:"), (IMP)AppDel_didFinishLaunching, "i@:@");
    class_addMethod(AppDelClass, sel_getUid("applicationDidUpdate:"), (IMP)AppDel_applicationDidUpdate, "i@:@");
    Protocol *protocol = objc_getProtocol("WKNavigationDelegate");
    assert(protocol);
    class_addProtocol(AppDelClass, protocol);
    class_addProtocol(AppDelClass, objc_getProtocol("NSApplicationDelegate"));
    class_addProtocol(AppDelClass, objc_getProtocol("NSWindowDelegate"));
    class_addMethod(AppDelClass, sel_getUid("webView:decidePolicyForNavigationAction:decisionHandler:"), (IMP)WebView_decidePolicyFor, "v@:@@?");
    
    class_addMethod(AppDelClass, sel_getUid("windowWillClose:"), (IMP)windowWillClose,  "v@:@");
    
    objc_registerClassPair(AppDelClass);
}

void RunApplication() {
    if (app == NULL) {
        fprintf(stderr,"Failed to initialized NSApplication\n");
        return;
    }
    
    objc_msgSend(app, sel_getUid("run"));
}

int ui_app_init(ui_trigger_event event_handler) {
    id pool = (id)objc_getClass("NSAutoreleasePool");
    if (!pool)
        return 0;

    pool = objc_msgSend(pool, sel_registerName("alloc"));
    if (!pool)
        return 0;

    pool = objc_msgSend(pool, sel_registerName("init"));
    
    app = objc_msgSend((id)objc_getClass("NSApplication"), sel_registerName("sharedApplication"));

    CreateAppDelegate();
    
    id appDelObj = objc_msgSend((id)objc_getClass("AppDelegate"), sel_getUid("alloc"));
    appDelObj = objc_msgSend(appDelObj, sel_getUid("init"));
    
    objc_msgSend(app, sel_getUid("setDelegate:"), appDelObj);

    callback_event = event_handler;
    return 1;
}

int ui_app_done() {
    if (pool) {
        objc_msgSend(pool, sel_registerName("release"));
        return 1;
    }
    return 0;
}

void ui_message(const char *title, const char *body, int level) {
    CFStringRef title_str = CFStringCreateWithCString(NULL, title, kCFStringEncodingMacRoman);

    NSRunAlertPanel(title_str, CFSTR("%s"), CFSTR("OK"), NULL, NULL, body);

    if (title_str)    
        CFRelease(title_str);
}

int ui_question(const char *title, const char *body, int level) {
    CFStringRef title_str = CFStringCreateWithCString(NULL, title, kCFStringEncodingMacRoman);

    int yes_no = NSRunAlertPanel(title_str, CFSTR("%s"), CFSTR("Yes"), CFSTR("No"), NULL, body);

    if (title_str)    
        CFRelease(title_str);
        
    if (yes_no < 0)
        yes_no = 0;
    return yes_no;
}

void ui_app_quit() {
    if (app)
        objc_msgSend(app, sel_getUid("terminate:"), NULL);
}

 void ui_app_run_with_notify(ui_idle_event event_idle, void *userdata) {
    idle_event = event_idle;
    idle_userdata = userdata;
}

void ui_app_run() {
    RunApplication();
}

void ui_js(void *window, const char *js) {
    if ((!window) || (!js))
        return;
    CFStringRef js_str = CFStringCreateWithCString(NULL, js, kCFStringEncodingMacRoman);
    CFStringRef str = (CFStringRef)objc_msgSend(objc_msgSend(window, sel_getUid("contentView")), sel_getUid("stringByEvaluatingJavaScriptFromString:"), js_str, NULL);
    if (str)
        CFRelease(str);
    if (js_str)
        CFRelease(js_str);
}

char *ui_call(void *window, const char *js, const char *arguments[]) {
    if ((!window) || (!js))
        return NULL;
    char *data = NULL;
    char buffer[8192];
    char arg_str[8192];
    arg_str[0] = 0;
    char *arg = arg_str;
    int arg_size = sizeof(arg_str);
    while ((arguments) && (*arguments)) {
        if (arg != arg_str) {
            arg[0] = ',';
            arg ++;
            arg_size --;
        }
        int written = snprintf(arg, arg_size, "'%s'", *arguments);
        arguments ++;
        if (written > 0) {
            arg += written;
            arg_size -= written;
            if (arg_size <= 1)
                break;
        } else
            break;
    }
    snprintf(buffer, sizeof(buffer), "%s(%s)", js, arg_str);
    CFStringRef js_str = CFStringCreateWithCString(NULL, buffer, kCFStringEncodingMacRoman);
    CFStringRef str = (CFStringRef)objc_msgSend(objc_msgSend(window, sel_getUid("contentView")), sel_getUid("stringByEvaluatingJavaScriptFromString:"), js_str, NULL);
    if (str) {
        data = CFStringCopyUTF8String(str);
        CFRelease(str);
    }
    if (js_str)
        CFRelease(js_str);

    return data;
}

void ui_app_tray_icon(const char *tooltip, char *notification_title, char *notification_text, ui_tray_event event_tray) {
    // not implemented
}

void ui_app_tray_remove() {
    // not implemented
}

void ui_free_string(void *ptr) {
    if (ptr)
        free(ptr);
}

int ui_window_count() {
    return window_count;
}
