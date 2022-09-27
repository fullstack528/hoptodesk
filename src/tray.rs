use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use trayicon::{MenuBuilder, TrayIconBuilder};
use winit::{
    event::Event,
    event_loop::{ControlFlow, EventLoop},
};

#[derive(Clone, Eq, PartialEq, Debug)]
enum Events {
    DoubleClickTrayIcon,
    StopService,
    StartService,
    Restore,
    Quit,
}

pub fn start_tray(options: Arc<Mutex<HashMap<String, String>>>) {
    let event_loop = EventLoop::<Events>::with_user_event();
    let proxy = event_loop.create_proxy();
    let icon = include_bytes!("./tray-icon.ico");
    let mut tray_icon = TrayIconBuilder::new()
        .sender_winit(proxy)
        .icon_from_buffer(icon)
        .tooltip("HopToDesk")
		.on_click(Events::DoubleClickTrayIcon)
        .on_double_click(Events::DoubleClickTrayIcon)
        .build()
        .unwrap();
    let old_state = Arc::new(Mutex::new(0));
    event_loop.run(move |event, _, control_flow| {
        if options.lock().unwrap().get("ipc-closed").is_some() {
            *control_flow = ControlFlow::Exit;
            return;
        } else {
            *control_flow = ControlFlow::Wait;
        }
        let stopped = if let Some(v) = options.lock().unwrap().get("stop-service") {
            !v.is_empty()
        } else {
            false
        };
        let stopped = if stopped { 2 } else { 1 };
        let old = *old_state.lock().unwrap();
        if stopped != old {
            hbb_common::log::info!("State changed");
            let mut m = MenuBuilder::new();
            if stopped == 2 {
                m = m.item(
                    &crate::client::translate("Start service".to_owned()),
                    Events::StartService,
                );
            } else {
                m = m.item(
                    &crate::client::translate("Stop service".to_owned()),
                    Events::StopService,
                );
            }
            m = m
                .separator()
                .item(
                    &crate::client::translate("Restore".to_owned()),
                    Events::Restore,
                )
                .item(&crate::client::translate("Quit".to_owned()), Events::Quit);
            tray_icon.set_menu(&m).ok();
            *old_state.lock().unwrap() = stopped;
        }

        match event {
            Event::UserEvent(e) => match e {
                Events::DoubleClickTrayIcon | Events::Restore => {
                    crate::run_me(Vec::<&str>::new()).ok();

                    // Prevent following Click/DoubleClick events
                    std::process::exit(0);
                }
                Events::StopService => {
                    crate::ipc::set_option("stop-service", "Y");
                }
                Events::StartService => {
                    crate::ipc::set_option("stop-service", "");
                }
                Events::Quit => {
                    *control_flow = ControlFlow::Exit;
                }
            },
            _ => (),
        }
    });
}
