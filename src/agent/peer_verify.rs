//! Peer process verification.
//!
//! - macOS: getsockopt(LOCAL_PEERPID) + proc_pidpath + SecStaticCodeCheckValidity
//! - Linux: /proc/PID/exe path verification

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    /// Get the PID of the peer process from a Unix domain socket.
    pub fn get_peer_pid(stream: &tokio::net::UnixStream) -> io::Result<libc::pid_t> {
        let fd = stream.as_raw_fd();
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;

        // LOCAL_PEERPID = 0x002 on macOS
        const LOCAL_PEERPID: libc::c_int = 0x002;

        // SAFETY: fd is a valid socket file descriptor.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                0, // SOL_LOCAL
                LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(pid)
    }

    /// Get the executable path of a process by PID using libproc.
    pub fn get_pid_path(pid: libc::pid_t) -> io::Result<PathBuf> {
        libproc::libproc::proc_pid::pidpath(pid)
            .map(PathBuf::from)
            .map_err(io::Error::other)
    }

    /// Verify code signature of the binary at the given path.
    /// Uses /usr/bin/codesign to prevent PATH poisoning.
    pub fn verify_code_signature(path: &std::path::Path) -> io::Result<bool> {
        let output = std::process::Command::new("/usr/bin/codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(path)
            .output()?;

        Ok(output.status.success())
    }

    /// Verify the peer process: get PID, resolve path, check code signature,
    /// and verify the binary matches our own executable.
    pub fn verify_peer(stream: &tokio::net::UnixStream) -> io::Result<bool> {
        let peer_pid = get_peer_pid(stream)?;
        let peer_path = get_pid_path(peer_pid)?;

        let my_path = std::env::current_exe()?;

        // Check that the peer is running the same binary.
        if peer_path != my_path {
            eprintln!(
                "agent: peer binary mismatch: expected {:?}, got {:?}",
                my_path, peer_path
            );
            return Ok(false);
        }

        // Verify code signature of the peer binary.
        if !verify_code_signature(&peer_path)? {
            eprintln!("agent: peer binary code signature verification failed");
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::unix::io::AsRawFd;

    /// Get the PID of the peer process from a Unix domain socket.
    pub fn get_peer_pid(stream: &tokio::net::UnixStream) -> io::Result<libc::pid_t> {
        let fd = stream.as_raw_fd();
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

        // SAFETY: fd is a valid socket file descriptor.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut ucred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ucred.pid)
    }

    /// Verify the peer process by checking /proc/PID/exe matches our own executable.
    pub fn verify_peer(stream: &tokio::net::UnixStream) -> io::Result<bool> {
        let peer_pid = get_peer_pid(stream)?;
        let peer_path = std::fs::read_link(format!("/proc/{}/exe", peer_pid))?;
        let my_path = std::env::current_exe()?;

        if peer_path != my_path {
            eprintln!(
                "agent: peer binary mismatch: expected {:?}, got {:?}",
                my_path, peer_path
            );
            return Ok(false);
        }

        Ok(true)
    }
}

/// Platform-agnostic peer verification.
#[cfg(target_os = "macos")]
pub use macos::verify_peer;

#[cfg(target_os = "linux")]
pub use linux::verify_peer;

/// Get the UID of the peer process.
#[cfg(unix)]
pub fn get_peer_uid(stream: &tokio::net::UnixStream) -> std::io::Result<u32> {
    let ucred = stream.peer_cred()?;
    Ok(ucred.uid())
}
