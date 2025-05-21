use crate::{common::do_check_software_update, hbbs_http::create_http_client};
use hbb_common::{bail, config, log, ResultType};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

static CONTROLLING_SESSION_COUNT: AtomicUsize = AtomicUsize::new(0);
const DUR_ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);

// 禁用所有升级相关函数
pub fn update_controlling_session_count(count: usize) {
    CONTROLLING_SESSION_COUNT.store(count, Ordering::SeqCst);
}

pub fn start_auto_update() {
    log::info!("Auto update is disabled.");
}

#[allow(dead_code)]
pub fn manually_check_update() -> ResultType<()> {
    log::info!("Manual update check is disabled.");
    Ok(())
}

#[allow(dead_code)]
pub fn stop_auto_update() {
    log::info!("Auto update is already disabled.");
}

// 保留非升级相关函数（如连接状态检查）
#[inline]
fn has_no_active_conns() -> bool {
    let conns = crate::Connection::alive_conns();
    conns.is_empty() && has_no_controlling_conns()
}

#[cfg(any(not(target_os = "windows"), feature = "flutter"))]
fn has_no_controlling_conns() -> bool {
    CONTROLLING_SESSION_COUNT.load(Ordering::SeqCst) == 0
}

#[cfg(not(any(not(target_os = "windows"), feature = "flutter")))]
fn has_no_controlling_conns() -> bool {
    let app_exe = format!("{}.exe", crate::get_app_name().to_lowercase());
    for arg in [
        "--connect",
        "--play",
        "--file-transfer",
        "--view-camera",
        "--port-forward",
        "--rdp",
    ] {
        if !crate::platform::get_pids_of_process_with_first_arg(&app_exe, arg).is_empty() {
            return false;
        }
    }
    true
}

// 移除所有升级相关的线程、消息系统和下载逻辑
// 删除了 UpdateMsg 枚举、TX_MSG 静态变量、start_auto_update_check 等函数

// 保留文件路径生成函数（非升级核心功能）
pub fn get_download_file_from_url(url: &str) -> Option<PathBuf> {
    let filename = url.split('/').last()?;
    Some(std::env::temp_dir().join(filename))
}