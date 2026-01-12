use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub fn bind_to_device(socket: &Socket, interface: &str) -> io::Result<()> {
    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(target_os = "macos")]
pub fn bind_to_device(socket: &Socket, interface: &str) -> io::Result<()> {
    let index = unsafe {
        let name = std::ffi::CString::new(interface)?;
        libc::if_nametoindex(name.as_ptr())
    };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {} not found", interface),
        ));
    }
    let index = std::num::NonZeroU32::new(index).unwrap();
    match socket.bind_device_by_index_v4(Some(index)) {
        Ok(()) => Ok(()),
        Err(e4) => socket.bind_device_by_index_v6(Some(index)).map_err(|_| e4),
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos"
)))]
fn bind_to_device(_socket: &Socket, _interface: &str) -> io::Result<()> {
    tracing::warn!("bind_device not supported on this platform");
    Ok(())
}

pub async fn bind_udp(addr: SocketAddr, interface: Option<&str>) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    if let Some(iface) = interface {
        bind_to_device(&socket, iface)?;
    }

    let _ = socket.set_reuse_address(true);

    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

pub async fn connect_tcp(
    addr: SocketAddr,
    interface: Option<&str>,
    bind_addr: Option<SocketAddr>,
) -> io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if let Some(iface) = interface {
        bind_to_device(&socket, iface)?;
    }

    if let Some(bind) = bind_addr {
        let _ = socket.set_reuse_address(true);
        socket.bind(&bind.into())?;
    }

    socket.set_nonblocking(true)?;

    match socket.connect(&addr.into()) {
        Ok(_) => {}
        Err(ref e)
            if e.kind() == io::ErrorKind::WouldBlock
                || e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }

    let stream = TcpStream::from_std(socket.into())?;

    stream.writable().await?;

    if let Some(e) = stream.take_error()? {
        return Err(e);
    }

    Ok(stream)
}
