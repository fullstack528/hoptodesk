#[cfg(windows)]
fn build_windows() {
    cc::Build::new().file("src/windows.cc").compile("windows");
    println!("cargo:rustc-link-lib=WtsApi32");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=windows.cc");
}

#[cfg(all(windows, feature = "packui"))]
fn build_manifest() {
    use std::io::Write;
    if std::env::var("PROFILE").unwrap() == "release" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico")
            .set_language(winapi::um::winnt::MAKELANGID(
                winapi::um::winnt::LANG_ENGLISH,
                winapi::um::winnt::SUBLANG_ENGLISH_US,
            ))
            .set_manifest_file("manifest.xml");
        match res.compile() {
            Err(e) => {
                write!(std::io::stderr(), "{}", e).unwrap();
                std::process::exit(1);
            }
            Ok(_) => {}
        }
    }
}

#[cfg(all(windows, feature = "with_rc"))]
fn build_rc_source() {
    use simple_rc::{generate_with_conf, Config, ConfigItem};
    generate_with_conf(&Config {
        outfile: "src/rc.rs".to_owned(),
        confs: vec![ConfigItem {
            inc: "resources".to_owned(),
            exc: vec![],
            suppressed_front: "resources".to_owned(),
        }],
    })
    .unwrap();
}

fn install_oboe() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "android" {
        return;
    }
    let mut target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch == "x86_64" {
        target_arch = "x64".to_owned();
    } else if target_arch == "aarch64" {
        target_arch = "arm64".to_owned();
    } else {
        target_arch = "arm".to_owned();
    }
    let target = format!("{}-android", target_arch);
    let vcpkg_root = std::env::var("VCPKG_ROOT").unwrap();
    let mut path: std::path::PathBuf = vcpkg_root.into();
    path.push("installed");
    path.push(target);
    println!(
        "{}",
        format!(
            "cargo:rustc-link-search={}",
            path.join("lib").to_str().unwrap()
        )
    );
    println!("cargo:rustc-link-lib=oboe");
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:rustc-link-lib=OpenSLES");
    // I always got some strange link error with oboe, so as workaround, put oboe.cc into oboe src: src/common/AudioStreamBuilder.cpp
    // also to avoid libc++_shared not found issue, cp ndk's libc++_shared.so to jniLibs, e.g.
    // ./flutter_hbb/android/app/src/main/jniLibs/arm64-v8a/libc++_shared.so
    // let include = path.join("include");
    //cc::Build::new().file("oboe.cc").include(include).compile("oboe_wrapper");
}

fn gen_flutter_rust_bridge() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=src/mobile_ffi.rs");
    // settings for fbr_codegen
    let opts = lib_flutter_rust_bridge_codegen::Opts {
        // Path of input Rust code
        rust_input: "src/mobile_ffi.rs".to_string(),
        // Path of output generated Dart code
        dart_output: "flutter/lib/generated_bridge.dart".to_string(),
        // Path of output C files.
        c_output: Some(vec!["flutter/ios/Runner/generated_bridge.h".to_string()]),
        // for other options lets use default
        ..Default::default()
    };
    // run fbr_codegen
    lib_flutter_rust_bridge_codegen::frb_codegen(opts).unwrap();
}

use std::path::PathBuf;
use std::process::Command;

fn wget(path: &str, output: &str) {
    let command = if cfg!(target_os = "windows") {
        "wget.exe"
    } else {
        "wget"
    };
    Command::new(command)
        .args([path, "-O", output])
        .output()
        .expect("wget packfolder failed");
}

fn main() {
    hbb_common::gen_version();
    install_oboe();
    // there is problem with cfg(target_os) in build.rs, so use our workaround
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "android" || target_os == "ios" {
        gen_flutter_rust_bridge();
        return;
    }
    #[cfg(all(windows, feature = "with_rc"))]
    build_rc_source();
    
    #[cfg(feature = "packui")]
    {
        fn chmod(path: &str) {
            if cfg!(target_os = "windows") {
                Command::new("csc")
                    .args([path])
                    .output()
                    .expect("csc failed");
            } else {
                Command::new("chmod")
                    .args(["+x", path])
                    .output()
                    .expect("chmod failed");
            }
        }

        // Download packfolder if it doesn't exist
        let packfolder = if cfg!(target_os = "windows") {
            "https://github.com/c-smile/sciter-sdk/blob/9f1724a45f5a53c4d513b02ed01cdbdab08fa0e5/bin.win/packfolder.exe"
        } else if cfg!(target_os = "macos") {
            "https://github.com/c-smile/sciter-sdk/raw/9f1724a45f5a53c4d513b02ed01cdbdab08fa0e5/bin.osx/packfolder"
        } else {
            "https://github.com/c-smile/sciter-sdk/raw/9f1724a45f5a53c4d513b02ed01cdbdab08fa0e5/bin.lnx/packfolder"
        };
        let output = "target/packfolder";
        let path = PathBuf::from(output);
        if !path.exists() {
            wget(packfolder, output);
            chmod(output);
        }

        // Run packfolder to create target/resources.rc
        Command::new(path)
            .args([
                "src/ui",
                "target/resources.rc",
                "-i",
                "*.html;*.css;*.tis;*.ttf",
                "-v",
                "resources",
                "-binary",
            ])
            .output()
            .expect("packfolder failed!");
    }

    // Download libsciter.gtk if it doesn't exist
    #[cfg(target_os = "linux")]
    {
        let output = "target/debug/libsciter-gtk.so";
        let path = PathBuf::from(output);
        if !path.exists() {
            wget("https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.lnx/x64/libsciter-gtk.so", output);
        }
    }

    #[cfg(all(windows, feature = "packui"))]
    build_manifest();
	#[cfg(windows)]
	static_vcruntime::metabuild();
    #[cfg(windows)]
    build_windows();
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=framework=ApplicationServices");
}
