mod extract_files;

extern crate winapi;

use std::{env, fs, io};
use std::{ffi::OsStr, process::Command};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::winuser::{FindWindowW, ShowWindow, SW_MINIMIZE,UnhookWindowsHookEx, SetWindowsHookExA, WH_KEYBOARD_LL};
use check_elevation::is_elevated;
use winreg::enums::HKEY_LOCAL_MACHINE;
use std::thread::sleep;
use std::time::Duration;
use std::thread;
use winapi::shared::minwindef::FALSE;
use winapi::um::libloaderapi::GetModuleHandleA;
use winreg::RegKey;

fn to_wstring(str: &str) -> Vec<u16> {
    OsStr::new(str).encode_wide().chain(once(0)).collect()
}

fn minimize_window(window_title: &str) -> Result<(), String> {
    let window_title = to_wstring(window_title);
    let hwnd = unsafe { 
        FindWindowW(null_mut(), window_title.as_ptr())
    };
    if hwnd.is_null() {
        return Err("Window not found".to_string());
    }
    let result = unsafe { 
        ShowWindow(hwnd, SW_MINIMIZE) 
    };
    if result == 0 {
        return Err("Failed to minimize window".to_string());
    }
    Ok(())
}

fn run_killer(name: String,rename: String){
    if name == "pskill"{
        let _run = Command::new(rename)
        .args(vec!["-t","-nobanner","StudentMain.exe"])
        .output()
        .expect("Err");
    }
    else if name == "pssuspend" {
        let _run = Command::new(rename)
        .args(vec!["-nobanner","StudentMain.exe"])
        .output()
        .expect("Err");
    }
    else if name == "ntsd" {
        let _run = Command::new(rename)
        .args(vec!["-c","q","-pn","StudentMain.exe"])
        .output()
        .expect("Err");
    }
}

unsafe extern "system" fn hook_proc(_code: i32, _w_param: winapi::shared::minwindef::WPARAM, _l_param: winapi::shared::minwindef::LPARAM) -> winapi::shared::minwindef::LRESULT {
    return FALSE.try_into().unwrap();
}

fn fk_jiyu_keyboardhook() -> Result<(), String>{  // 除了 ctrl+alt+del
    // https://blog.csdn.net/weixin_42112038/article/details/126228989
    unsafe {
        let module_handle = GetModuleHandleA(null_mut());
        let hook = SetWindowsHookExA(WH_KEYBOARD_LL, Some(hook_proc), module_handle, 0);
        if hook.is_null() {
            println!("");
            return Err("Failed to set hook!".to_string());
        }
        println!("Keyboard hook set successfully!");
        sleep(Duration::from_secs_f64(12.0));
        UnhookWindowsHookEx(hook);
        println!("Keyboard hook removed successfully!");
        Ok(())
    }
}

fn get_jiyu_path() -> io::Result<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut t1 = hklm.open_subkey(r"SOFTWARE\WOW6432Node\TopDomain\e-Learning Class V6.0"); // jiyu
    match t1 {
        Ok(_) => {}
        Err(_) => {
            t1 = hklm.open_subkey(r"SOFTWARE\TopDomain\e-Learning Class Standard\1.00"); // nanruan
            match t1 {
                Ok(_) => {}
                Err(e) => {
                    println!("Fail to get jiyu path");
                    return Err(e);
                }
            }
        }
    }
    let jiyu_path: String = t1.as_ref().unwrap().get_value("TargetDirectory")?;
    let t3 = t1.as_ref().unwrap().set_value("SetupType", &"Teacher");
    let t4 = t1.unwrap().delete_value("SetupType");
    match t3 {
        Ok(_) => {
            println!("ok to change reg");
        }
        Err(e) => {
            println!("error to change reg {}",e);
        } 
    }
    match t4 {
        Ok(_) => {
            println!("ok to del reg");
        }
        Err(e) => {
            println!("error to del reg {}",e);
        } 
    }
    println!("{}",jiyu_path);
    return Ok(jiyu_path);
}

fn rename_exchange20_dll(jiyu_path: &String){
    match fs::rename(jiyu_path.to_owned()+&"eXchange20.dll".to_string(), jiyu_path.to_owned()+&"eXchange20.dll.1".to_string()){
        Ok(_) => {
            println!("ok to rename eXchange20.dll");
        }
        Err(e) => {
            println!("Err to rename eXchange20.dll: {}",e);
        }
    }
}
fn main() {
    let now_path_exe = env::current_exe().unwrap().display().to_string();
    let now_dir = env::current_dir().unwrap().display().to_string();
    println!("{} {}",now_path_exe,now_dir);
    if !is_elevated().expect("Failed to get elevation status."){
        println!("本程序需要管理员权限运行,请在接下来弹出的窗口中点击是");
        sleep(Duration::from_secs(2));
        let _status = runas::Command::new(now_path_exe)
        .status()
        .unwrap();
        return;
    }
    sleep(Duration::from_secs(2));
    let minimize_screen1: thread::JoinHandle<()> = thread::spawn(||{
        loop {
            let run_minimize_screen1 = minimize_window("屏幕广播");
            match run_minimize_screen1 {
                Ok(_) => {
                    println!("Success-1");
                }
                Err(e) => {
                    println!("Err!{}-1",e);
                }
            }
            sleep(Duration::from_secs(2));
        }
    });
    let minimize_screen2: thread::JoinHandle<()> = thread::spawn(||{
        loop {
            let run_minimize_screen2 = minimize_window("BlackScreen Window");
            match run_minimize_screen2 {
                Ok(_) => {
                    println!("Success-2");
                }
                Err(e) => {
                    println!("Err!{}-2",e);
                }
            }
            sleep(Duration::from_secs(2));
        }
    });
    let fkkbhook: thread::JoinHandle<()> = thread::spawn(||{
        loop {
            let run_fkkbhook = fk_jiyu_keyboardhook();
            match run_fkkbhook {
                Ok(_) => {
                    println!("Success to hook");
                }
                Err(e) => {
                    println!("Err!{}-hook",e);
                }
            }
        }
    });
    let jiyu_path_1 = get_jiyu_path();
    let mut jiyu_path = String::new();
    match jiyu_path_1 {
        Ok(o) => {
            jiyu_path = o;
        }
        Err(e) => {
            println!("Err {}",e);
            jiyu_path = r"c:\Program Files (x86)\Mythware\极域课堂管理系统软件V6.0 2016 豪华版\".to_string(); // 默认
        }
    }
    rename_exchange20_dll(&jiyu_path);
    minimize_screen1.join().unwrap();
    minimize_screen2.join().unwrap();
    fkkbhook.join().unwrap();
}
