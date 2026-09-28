//! TUN interface abstraction.
//!
//! Everywhere except macOS this is a re-export of [`tokio_tun`]. macOS's `utun(4)`
//! driver is not a character device but a kernel control socket, so it gets its own
//! implementation here. Both expose the same API for the [`Stack`](crate::Stack).

#[cfg(not(target_os = "macos"))]
mod platform {
    pub use tokio_tun::{Tun, TunBuilder};
}

#[cfg(target_os = "macos")]
mod platform {
    use std::io;
    use std::mem;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::process::Command;
    use tokio::io::unix::AsyncFd;

    /// `_IOWR('N', 3, struct ctl_info)`, from `<sys/kern_control.h>`.
    const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;

    /// `UTUN_OPT_IFNAME` and the kernel control it belongs to, from `<net/if_utun.h>`.
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

    /// A macOS `utun(4)` interface.
    ///
    /// Unlike Linux's Tun this is a socket, and every packet read from or written to
    /// it is prefixed with a 4 byte address family in network byte order. That prefix
    /// is handled here so that callers only ever deal in bare IP packets.
    pub struct Tun {
        name: String,
        io: AsyncFd<OwnedFd>,
    }

    impl Tun {
        /// Receives a packet from the utun interface.
        pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.io.readable().await?;
                match guard.try_io(|inner| recv_packet(inner.as_raw_fd(), buf)) {
                    Ok(res) => return res,
                    Err(_) => continue,
                }
            }
        }

        /// Sends a packet to the utun interface.
        pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.io.writable().await?;
                match guard.try_io(|inner| send_packet(inner.as_raw_fd(), buf)) {
                    Ok(res) => return res,
                    Err(_) => continue,
                }
            }
        }

        /// Tries to send a packet to the utun interface.
        ///
        /// When the interface queue is full, `Err(io::ErrorKind::WouldBlock)` is returned.
        pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
            send_packet(self.io.as_raw_fd(), buf)
        }

        /// Returns the name of the utun interface, for example `utun4`.
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    /// Builds a [`Tun`], mirroring the subset of `tokio_tun::TunBuilder` that Phantun uses.
    #[derive(Default)]
    pub struct TunBuilder {
        name: String,
        address: Option<Ipv4Addr>,
        destination: Option<Ipv4Addr>,
        up: bool,
    }

    impl TunBuilder {
        pub fn new() -> Self {
            Self::default()
        }

        /// Sets the name of device, if it is empty, then the device name is set by the kernel.
        pub fn name(mut self, name: &str) -> Self {
            self.name = name.into();
            self
        }

        /// Sets the IPv4 address of the device.
        pub fn address(mut self, address: Ipv4Addr) -> Self {
            self.address = Some(address);
            self
        }

        /// Sets the IPv4 destination (peer) address of the device.
        pub fn destination(mut self, destination: Ipv4Addr) -> Self {
            self.destination = Some(destination);
            self
        }

        /// Sets up the device.
        pub fn up(mut self) -> Self {
            self.up = true;
            self
        }

        /// Accepted for compatibility with `tokio_tun::TunBuilder`, utun is single queue
        /// so a single [`Tun`] is always built.
        pub fn queues(self, _queues: usize) -> Self {
            self
        }

        /// Builds a new instance of [`Tun`].
        pub fn build(self) -> io::Result<Vec<Tun>> {
            let (fd, name) = open_utun(&self.name)?;

            // Sets the addresses and brings the interface up, the equivalent of what
            // tokio-tun does with netlink on Linux. ifconfig(8) is used instead of the
            // SIOCSIFADDR family of ioctls to keep the unsafe surface down to the utun
            // socket itself.
            let mut ifconfig = Command::new("/sbin/ifconfig");
            ifconfig.arg(&name);
            match (self.address, self.destination) {
                // Netmask has to be explicit, otherwise ifconfig picks one from the
                // address class and installs a route for the whole subnet.
                (Some(address), Some(destination)) => {
                    ifconfig
                        .arg(address.to_string())
                        .arg(destination.to_string())
                        .args(["netmask", "255.255.255.255"]);
                }
                (Some(address), None) => {
                    ifconfig.arg(address.to_string());
                }
                (None, _) => {}
            }
            if self.up {
                ifconfig.arg("up");
            }
            let output = ifconfig.output()?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "unable to configure {}: {}",
                    name,
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }

            Ok(vec![Tun {
                name,
                io: AsyncFd::new(fd)?,
            }])
        }
    }

    /// Creates a utun interface and returns its file descriptor and kernel assigned name.
    ///
    /// Creating a utun interface requires root.
    fn open_utun(name: &str) -> io::Result<(OwnedFd, String)> {
        // an empty name lets the kernel pick the first free interface. Control units are
        // numbered from 1 while interface units are numbered from 0, hence the + 1.
        let unit = if name.is_empty() {
            0
        } else {
            match name
                .strip_prefix("utun")
                .and_then(|unit| unit.parse::<u32>().ok())
            {
                Some(unit) => unit + 1,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{name} is not a valid utun interface name"),
                    ));
                }
            }
        };

        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut info: libc::ctl_info = unsafe { mem::zeroed() };
        for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
            *dst = *src as libc::c_char;
        }
        if unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = libc::sockaddr_ctl {
            sc_len: mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar,
            sc_family: libc::AF_SYSTEM as libc::c_uchar,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };
        let sockaddr = std::ptr::from_ref(&addr).cast::<libc::sockaddr>();
        if unsafe {
            libc::connect(
                fd.as_raw_fd(),
                sockaddr,
                mem::size_of_val(&addr) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut name = [0u8; libc::IF_NAMESIZE];
        let mut len = name.len() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // the returned length includes the terminating NUL
        let name = String::from_utf8_lossy(&name[..len.saturating_sub(1) as usize]).into_owned();

        // AsyncFd requires a non-blocking file descriptor
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok((fd, name))
    }

    /// Reads a single packet, dropping the utun address family prefix.
    fn recv_packet(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let mut af = [0u8; 4];
        let mut iov = [
            libc::iovec {
                iov_base: af.as_mut_ptr().cast(),
                iov_len: af.len(),
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
        ];
        let size = unsafe { libc::readv(fd, iov.as_mut_ptr(), iov.len() as libc::c_int) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if (size as usize) < af.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated utun packet",
            ));
        }

        Ok(size as usize - af.len())
    }

    /// Writes a single packet, prefixing it with the utun address family header.
    fn send_packet(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
        let af = match buf.first().map(|version| version >> 4) {
            Some(4) => libc::AF_INET,
            Some(6) => libc::AF_INET6,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not an IP packet",
                ));
            }
        }
        .to_be_bytes();
        let iov = [
            libc::iovec {
                iov_base: af.as_ptr() as *mut libc::c_void,
                iov_len: af.len(),
            },
            libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            },
        ];
        let size = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(size as usize - af.len())
    }
}

pub use platform::{Tun, TunBuilder};
