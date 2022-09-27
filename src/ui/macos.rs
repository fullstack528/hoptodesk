#[cfg(target_os = "macos")]
use cocoa::{
    appkit::{NSApp, NSApplication, NSApplicationActivationPolicy::*, NSMenu, NSMenuItem},
    base::{id, nil, YES},
    foundation::{NSAutoreleasePool, NSString},
};
use objc::{
    class,
    declare::ClassDecl,
    msg_send,
    runtime::{Object, Sel, BOOL},
    sel, sel_impl,
};
use sciter::{make_args, Host};
use std::{ffi::c_void, rc::Rc};

static APP_HANDLER_IVAR: &str = "GoDeskAppHandler";

const TERMINATE_TAG: u32 = 0;
const SHOW_ABOUT_TAG: u32 = 1;
const SHOW_SETTINGS_TAG: u32 = 2;
const RUN_ME_TAG: u32 = 3;
const AWAKE: u32 = 4;

trait AppHandler {
    fn command(&mut self, cmd: u32);
}

struct DelegateState {
    handler: Option<Box<dyn AppHandler>>,
}

impl DelegateState {
    fn command(&mut self, command: u32) {
        if command == TERMINATE_TAG {
            unsafe {
                let () = msg_send!(NSApp(), terminate: nil);
            }
        } else if let Some(inner) = self.handler.as_mut() {
            inner.command(command)
        }
    }
}

static mut LAUCHED: bool = false;

impl AppHandler for Rc<Host> {
    fn command(&mut self, cmd: u32) {
        if cmd == SHOW_ABOUT_TAG {
            let _ = self.call_function("awake", &make_args![]);
            let _ = self.call_function("showAbout", &make_args![]);
        } else if cmd == SHOW_SETTINGS_TAG {
            let _ = self.call_function("awake", &make_args![]);
            let _ = self.call_function("showSettings", &make_args![]);
        } else if cmd == AWAKE {
            let _ = self.call_function("awake", &make_args![]);
        }
    }
}

// https://github.com/xi-editor/druid/blob/master/druid-shell/src/platform/mac/application.rs
unsafe fn set_delegate(handler: Option<Box<dyn AppHandler>>) {
    let mut decl =
        ClassDecl::new("AppDelegate", class!(NSObject)).expect("App Delegate definition failed");
    decl.add_ivar::<*mut c_void>(APP_HANDLER_IVAR);

    decl.add_method(
        sel!(applicationDidFinishLaunching:),
        application_did_finish_launching as extern "C" fn(&mut Object, Sel, id),
    );

    decl.add_method(
        sel!(applicationShouldOpenUntitledFile:),
        application_should_handle_open_untitled_file as extern "C" fn(&mut Object, Sel, id) -> BOOL,
    );

    decl.add_method(
        sel!(applicationDidBecomeActive:),
        application_did_become_active as extern "C" fn(&mut Object, Sel, id) -> BOOL,
    );

    decl.add_method(
        sel!(applicationDidUnhide:),
        application_did_become_unhide as extern "C" fn(&mut Object, Sel, id) -> BOOL,
    );

    decl.add_method(
        sel!(applicationShouldHandleReopen:),
        application_should_handle_reopen as extern "C" fn(&mut Object, Sel, id) -> BOOL,
    );

    decl.add_method(
        sel!(applicationWillTerminate:),
        application_will_terminate as extern "C" fn(&mut Object, Sel, id) -> BOOL,
    );

    decl.add_method(
        sel!(handleMenuItem:),
        handle_menu_item as extern "C" fn(&mut Object, Sel, id),
    );
    let decl = decl.register();
    let delegate: id = msg_send![decl, alloc];
    let () = msg_send![delegate, init];
    let state = DelegateState { handler };
    let handler_ptr = Box::into_raw(Box::new(state));
    (*delegate).set_ivar(APP_HANDLER_IVAR, handler_ptr as *mut c_void);
    let () = msg_send![NSApp(), setDelegate: delegate];
}

extern "C" fn application_did_finish_launching(_this: &mut Object, _: Sel, _notification: id) {
    unsafe {
        LAUCHED = true;
    }
    unsafe {
        let () = msg_send![NSApp(), activateIgnoringOtherApps: YES];
    }
}

extern "C" fn application_should_handle_open_untitled_file(
    this: &mut Object,
    _: Sel,
    _sender: id,
) -> BOOL {
    unsafe {
        if !LAUCHED {
            return YES;
        }
        hbb_common::log::debug!("icon clicked on finder");
        if std::env::args().nth(1) == Some("--server".to_owned()) {
            check_main_window();
        }
        let inner: *mut c_void = *this.get_ivar(APP_HANDLER_IVAR);
        let inner = &mut *(inner as *mut DelegateState);
        (*inner).command(AWAKE);
    }
    YES
}

extern "C" fn application_should_handle_reopen(_this: &mut Object, _: Sel, _sender: id) -> BOOL {
    YES
}

extern "C" fn application_did_become_active(_this: &mut Object, _: Sel, _sender: id) -> BOOL {
    YES
}

extern "C" fn application_did_become_unhide(_this: &mut Object, _: Sel, _sender: id) -> BOOL {
    YES
}

extern "C" fn application_will_terminate(_this: &mut Object, _: Sel, _sender: id) -> BOOL {
    YES
}

/// This handles menu items in the case that all windows are closed.
extern "C" fn handle_menu_item(this: &mut Object, _: Sel, item: id) {
    unsafe {
        let tag: isize = msg_send![item, tag];
        let tag = tag as u32;
        if tag == RUN_ME_TAG {
            crate::run_me(Vec::<String>::new()).ok();
        } else {
            let inner: *mut c_void = *this.get_ivar(APP_HANDLER_IVAR);
            let inner = &mut *(inner as *mut DelegateState);
            (*inner).command(tag as u32);
        }
    }
}

unsafe fn make_menu_item(title: &str, key: &str, tag: u32) -> *mut Object {
    let title = NSString::alloc(nil).init_str(title);
    let action = sel!(handleMenuItem:);
    let key = NSString::alloc(nil).init_str(key);
    let object = NSMenuItem::alloc(nil)
        .initWithTitle_action_keyEquivalent_(title, action, key)
        .autorelease();
    let () = msg_send![object, setTag: tag];
    object
}

pub fn make_menubar(host: Rc<Host>, is_index: bool) {
    unsafe {
        let _pool = NSAutoreleasePool::new(nil);
        set_delegate(Some(Box::new(host)));
        let menubar = NSMenu::new(nil).autorelease();
        let app_menu_item = NSMenuItem::new(nil).autorelease();
        menubar.addItem_(app_menu_item);
        let app_menu = NSMenu::new(nil).autorelease();

        if !is_index {
            let new_item = make_menu_item("New Window", "n", RUN_ME_TAG);
            app_menu.addItem_(new_item);
        } else {
            // When app launched without argument, is the main panel.
            let about_item = make_menu_item("About", "a", SHOW_ABOUT_TAG);
            app_menu.addItem_(about_item);
            let separator = NSMenuItem::separatorItem(nil).autorelease();
            app_menu.addItem_(separator);
            let settings_item = make_menu_item("Settings", "s", SHOW_SETTINGS_TAG);
            app_menu.addItem_(settings_item);
        }
        let separator = NSMenuItem::separatorItem(nil).autorelease();
        app_menu.addItem_(separator);
        let quit_item = make_menu_item(
            &format!("Quit {}", crate::get_app_name()),
            "q",
            TERMINATE_TAG,
        );
        app_menu_item.setSubmenu_(app_menu);
        /*
        if !enabled {
            let () = msg_send![quit_item, setEnabled: NO];
        }

        if selected {
            let () = msg_send![quit_item, setState: 1_isize];
        }
        let () = msg_send![item, setTag: id as isize];
        */
        app_menu.addItem_(quit_item);
        NSApp().setMainMenu_(menubar);
    }
}

pub fn show_dock() {
    unsafe {
        NSApp().setActivationPolicy_(NSApplicationActivationPolicyRegular);
    }
}

pub fn make_tray() {
    unsafe {
        set_delegate(None);
    }
    use tray_item::TrayItem;
    if let Ok(mut tray) = TrayItem::new(&crate::get_app_name(), "mac-tray.png") {
        tray.add_label(&format!(
            "{} {}",
            crate::get_app_name(),
            crate::lang::translate("Service is running".to_owned())
        ))
        .ok();

        let inner = tray.inner_mut();
        inner.add_quit_item(&crate::lang::translate("Quit".to_owned()));
        inner.display();
    } else {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }
}

pub fn check_main_window() {
    use sysinfo::{ProcessExt, System, SystemExt};
    let mut sys = System::new();
    sys.refresh_processes();
    let app = format!("/Applications/{}.app", crate::get_app_name());
    let my_uid = sys
        .process((std::process::id() as i32).into())
        .map(|x| x.user_id())
        .unwrap_or_default();
    for (_, p) in sys.processes().iter() {
        if p.cmd().len() == 1 && p.user_id() == my_uid && p.cmd()[0].contains(&app) {
            return;
        }
    }
    std::process::Command::new("open")
        .args(["-n", &app])
        .status()
        .ok();
}
