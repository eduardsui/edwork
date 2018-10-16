#ifndef __HTMLWINDOW_H
#define __HTMLWINDOW_H

typedef void (*ui_trigger_event)(void *window);
typedef void (*ui_idle_event)(void *userdata);
typedef void (*ui_tray_event)(void *window);

int ui_app_init(ui_trigger_event event_handler);
void ui_app_tray_icon(const char *tooltip, ui_tray_event event_tray);
void ui_app_tray_remove();
void ui_app_run_with_notify(ui_idle_event event_idle, void *userdata);
void ui_app_run();
int ui_app_done();
void ui_app_quit();


void ui_message(const char *title, const char *body, int level);
int ui_question(const char *title, const char *body, int level);
void ui_js(void *wnd, const char *js);
char *ui_call(void *wnd, const char *function, const char *arguments[]);
void ui_free_string(void *ptr);
void *ui_window(const char *title, const char *body);
void ui_window_close(void *wnd);
void ui_window_set_content(void *wnd, const char *body);
int ui_window_count();

#endif
