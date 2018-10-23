#import <Cocoa/Cocoa.h>
#import <WebKit/WKNavigationDelegate.h>

Protocol *_reference_all() {
    Protocol *dummy = @protocol(WKNavigationDelegate);
    Protocol *dummy2 = @protocol(NSWindowDelegate);
    Protocol *dummy3 = @protocol(NSApplicationDelegate);
    return dummy;
}
