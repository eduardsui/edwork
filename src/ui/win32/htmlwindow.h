#ifndef __HTMLWINDOW_H
#define __HTMLWINDOW_H

typedef void (*ui_trigger_event)(void *window);

int ui_app_init(ui_trigger_event event_handler);
void ui_app_run();
int ui_app_done();

void ui_message(const char *title, const char *body, int level);
void ui_js(void *wnd, const char *js);
char *ui_call(void *wnd, const char *function, const char *arguments[]);
void ui_free_string(void *ptr);
void *ui_window(void *hInstance, const char *title, const char *body);

#endif

