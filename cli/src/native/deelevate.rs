//! Windows self-de-elevation.
//!
//! The agent-browser daemon is normally inherited from whichever shell ran
//! the CLI. If that shell was elevated via UAC, the daemon ends up with
//! `TokenElevationTypeFull` — and Chrome (M138+), when launched from such
//! a process, tries to relaunch *itself* unelevated through Explorer's
//! medium-integrity token. The original Chrome process exits cleanly while
//! the daemon is still waiting for `DevToolsActivePort`, surfacing as
//! "Chrome exited early (exit code: 0)".
//!
//! Rather than fight Chrome's auto-de-elevation at the spawn site, this
//! module performs the same handoff one frame earlier: when the daemon
//! starts and detects it's running unnecessarily elevated, it relaunches
//! itself with Explorer's primary token (`CreateProcessWithTokenW`),
//! waits until the unelevated copy is reachable on its IPC socket, then
//! exits cleanly. Downstream code spawns Chrome via the normal
//! `Command::spawn` path and the bug never has a chance to occur.
//!
//! Mirrors Chromium's `base::win::RunDeElevated` in `base/win/elevation_util.cc`.

#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HWND};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevationType,
    TokenElevationTypeFull, TokenPrimary, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcess, OpenProcess, OpenProcessToken,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

/// True when the current process is running with `TokenElevationTypeFull`,
/// the same condition Chromium's `UserAccountIsUnnecessarilyElevated` checks.
/// False for the always-on built-in Administrator account
/// (`TokenElevationTypeDefault`) and for ordinary unelevated users
/// (`TokenElevationTypeLimited`).
pub fn is_unnecessarily_elevated() -> bool {
    let mut token: HANDLE = 0;
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token == 0 {
        return false;
    }

    let mut elevation_type: i32 = 0;
    let mut returned: u32 = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevationType,
            &mut elevation_type as *mut i32 as *mut _,
            std::mem::size_of::<i32>() as u32,
            &mut returned,
        )
    };
    unsafe { CloseHandle(token) };

    ok != 0 && elevation_type == TokenElevationTypeFull
}

/// Spawn `program` with `args` and the current process's environment using
/// Explorer's primary token. Returns the spawned process's PID. The new
/// process inherits Explorer's medium-integrity token, so it runs
/// unelevated as the standard user.
///
/// Caller is responsible for not waiting on the returned PID (we don't
/// keep a handle around — the spawned daemon detaches itself).
pub fn spawn_self_unelevated(program: &Path, args: &[String]) -> std::io::Result<u32> {
    // 1. Find Explorer's PID via the shell window
    let shell_hwnd: HWND = unsafe { GetShellWindow() };
    if shell_hwnd == 0 {
        return Err(io_err("GetShellWindow returned NULL (no Explorer running?)"));
    }
    let mut shell_pid: u32 = 0;
    let _ = unsafe { GetWindowThreadProcessId(shell_hwnd, &mut shell_pid) };
    if shell_pid == 0 {
        return Err(io_err("GetWindowThreadProcessId for shell window failed"));
    }

    // 2. Open Explorer's process and its token
    let shell_proc = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, shell_pid) };
    if shell_proc == 0 {
        return Err(last_error("OpenProcess(Explorer)"));
    }
    let _shell_proc_guard = HandleGuard(shell_proc);

    let mut shell_tok: HANDLE = 0;
    if unsafe { OpenProcessToken(shell_proc, TOKEN_DUPLICATE, &mut shell_tok) } == 0 {
        return Err(last_error("OpenProcessToken(Explorer)"));
    }
    let _shell_tok_guard = HandleGuard(shell_tok);

    // 3. Duplicate as a primary token suitable for CreateProcessWithTokenW
    let dup_rights = TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_DUPLICATE
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID;
    let mut primary_tok: HANDLE = 0;
    if unsafe {
        DuplicateTokenEx(
            shell_tok,
            dup_rights,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_tok,
        )
    } == 0
    {
        return Err(last_error("DuplicateTokenEx"));
    }
    let _primary_tok_guard = HandleGuard(primary_tok);

    // 4. Build a quoted command line and spawn
    let cmd_line = build_command_line(program, args);
    let app_w = to_wide(program.as_os_str());
    let mut cmd_w = to_wide(OsStr::new(&cmd_line));

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessWithTokenW(
            primary_tok,
            0,
            app_w.as_ptr(),
            cmd_w.as_mut_ptr(),
            CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateProcessWithTokenW"));
    }

    // We don't keep handles to the spawned process — we want it to outlive
    // us. Close ours now.
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    Ok(pi.dwProcessId)
}

/// Block, polling `is_ready` every 100ms, until it returns true or
/// `timeout` elapses. Used by the elevated daemon to confirm its
/// unelevated successor is up before exiting (so the parent CLI's
/// `daemon_ready` poll doesn't fail in the gap).
pub fn wait_until<F: Fn() -> bool>(is_ready: F, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let interval = Duration::from_millis(100);
    while std::time::Instant::now() <= deadline {
        if is_ready() {
            return true;
        }
        std::thread::sleep(interval);
    }
    is_ready()
}

fn to_wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Build a quoted Windows command line for `CreateProcessWithTokenW`.
///
/// Wrap a token in double quotes if it contains whitespace or is empty;
/// escape embedded double quotes by preceding them with a backslash, and
/// double up backslashes that precede an escaped quote. Same rules the C
/// runtime uses to parse `argv`.
fn build_command_line(program: &Path, args: &[String]) -> String {
    let mut s = String::new();
    quote(&mut s, &program.to_string_lossy());
    for a in args {
        s.push(' ');
        quote(&mut s, a);
    }
    s
}

fn quote(out: &mut String, arg: &str) {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\x0b' || c == '"');
    if !needs_quotes {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        if c == '\\' {
            backslashes += 1;
            continue;
        }
        if c == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
            continue;
        }
        for _ in 0..backslashes {
            out.push('\\');
        }
        backslashes = 0;
        out.push(c);
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
}

fn last_error(ctx: &str) -> std::io::Error {
    let code = unsafe { GetLastError() };
    std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("{} failed: GetLastError={}", ctx, code),
    )
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg.to_string())
}

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_simple() {
        let mut s = String::new();
        quote(&mut s, "hello");
        assert_eq!(s, "hello");
    }

    #[test]
    fn quote_with_spaces() {
        let mut s = String::new();
        quote(&mut s, "hello world");
        assert_eq!(s, "\"hello world\"");
    }

    #[test]
    fn quote_with_quote() {
        let mut s = String::new();
        quote(&mut s, "say \"hi\"");
        assert_eq!(s, "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn quote_trailing_backslash() {
        let mut s = String::new();
        quote(&mut s, "C:\\path with space\\");
        assert_eq!(s, "\"C:\\path with space\\\\\"");
    }

    #[test]
    fn build_command_line_basic() {
        let cl = build_command_line(
            Path::new("C:\\Program Files\\app.exe"),
            &["--foo".to_string(), "--bar=hello world".to_string()],
        );
        assert_eq!(
            cl,
            "\"C:\\Program Files\\app.exe\" --foo \"--bar=hello world\""
        );
    }

    #[test]
    fn is_unnecessarily_elevated_does_not_panic() {
        let _ = is_unnecessarily_elevated();
    }
}
