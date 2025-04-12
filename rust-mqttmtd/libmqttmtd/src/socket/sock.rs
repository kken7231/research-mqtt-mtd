use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

pub fn sock_listen(
    addr: impl ToSocketAddrs,
    deadline: Option<Duration>,
    handler: fn(TcpStream),
) -> Result<(), io::Error> {
    if deadline == Some(Duration::ZERO) {
        return Err(io::Error::other("listening with zero duration"));
    }
    let listener: TcpListener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;

    let deadline = match deadline {
        Some(dur) => Instant::now() + dur,
        None => Instant::now() + Duration::from_secs(24 * 60 * 60), // 24 hours
    };

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("New connection from {:?}", addr);
                stream.set_nonblocking(false)?;
                handler(stream);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No connection yet, check for timeout
                if Instant::now() > deadline {
                    println!("Deadline reached, no connections received.");
                    return Err(io::Error::other("socket deadline reached"));
                }
                // Sleep a bit before retrying
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                // Unexpected error
                eprintln!("Failed to accept connection: {}", e);
                return Err(e);
            }
        }
    }
}

pub fn sock_conn(addr: &str) -> Result<TcpStream, io::Error> {
    match TcpStream::connect(addr) {
        Err(e) => {
            return Err(e);
        }
        Ok(s) => {
            return Ok(s);
        }
    }
}

pub fn sock_read(
    mut stream: TcpStream,
    buf: &mut [u8],
    timeout: Option<Duration>,
) -> Result<(), io::Error> {
    stream.set_read_timeout(timeout)?;
    stream.read(buf)?;
    Ok(())
}

pub fn sock_write(
    mut stream: TcpStream,
    buf: &[u8],
    timeout: Option<Duration>,
) -> Result<(), io::Error> {
    stream.set_write_timeout(timeout)?;
    stream.write(buf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::thread::{self, sleep};

    use super::*;

    #[test]
    fn listen_conn_pass() {
        const ADDR: &str = "localhost:3000";
        let _ = thread::spawn(|| sock_listen(ADDR, Some(Duration::from_secs(1)), |_| {}));
        sleep(Duration::from_millis(100));
        let stream = sock_conn(ADDR);
        assert!(stream.is_ok());
    }

    #[test]
    fn listen_conn_zero_duration() {
        const ADDR: &str = "localhost:3001";

        // Try listening
        assert!(sock_listen(ADDR, Some(Duration::from_secs(0)), |_| {}).is_err());
    }

    #[test]
    fn listen_conn_none_duration() {
        const ADDR: &str = "localhost:3002";
        let _ = thread::spawn(|| sock_listen(ADDR, None, |_| {}));
        sleep(Duration::from_millis(100));

        // Try connecting
        assert!(sock_conn(ADDR).is_ok());
    }

    #[test]
    fn listen_conn_not_listening() {
        const ADDR: &str = "localhost:3003";

        // Try connecting
        assert!(sock_conn(ADDR).is_err());
    }

    #[test]
    fn listen_conn_after_deadline() {
        const ADDR: &str = "localhost:3004";

        // Socket server
        let _ = thread::spawn(|| sock_listen(ADDR, Some(Duration::from_secs(1)), |_| {}));

        // Wait for the listener to set up and get timed out
        sleep(Duration::from_millis(1100));

        // Try connecting
        assert!(sock_conn(ADDR).is_err());
    }

    #[test]
    fn send_recv_pass() {
        const ADDR: &str = "localhost:3005";
        const MESSAGE: &str = "hello, socket!";

        // Message sender (socket server)
        let _ = thread::spawn(|| {
            sock_listen(ADDR, Some(Duration::from_secs(1)), |s| {
                assert!(
                    sock_write(s, MESSAGE.as_bytes(), Some(Duration::from_millis(500)),).is_ok()
                );
            })
        });

        // Wait for the listener to set up
        sleep(Duration::from_millis(100));

        // Message receiver (socket client)
        let stream = sock_conn(ADDR).unwrap(); // already checked above
        let mut buf: [u8; 1024] = [0; 1024];
        assert!(sock_read(stream, &mut buf[..], Some(Duration::from_millis(500))).is_ok());

        // Check message
        assert_eq!(
            std::str::from_utf8(&buf[..MESSAGE.as_bytes().len()]).unwrap(),
            MESSAGE
        );
        assert_eq!(buf[MESSAGE.as_bytes().len()], 0);
    }

    #[test]
    fn send_recv_send_timeout() {
        const ADDR: &str = "localhost:3006";
        const MESSAGE: &str = "hello, socket!";

        // Message sender (socket server)
        let _ = sock_listen(ADDR, Some(Duration::from_secs(1)), |s| {
            let res = sock_write(s, MESSAGE.as_bytes(), Some(Duration::from_nanos(1)));
            assert!(res.is_err());
            let res = res.err().unwrap().kind();
            assert!((res == io::ErrorKind::WouldBlock) || (res == io::ErrorKind::InvalidInput));
        });
    }

    #[test]
    fn send_recv_recv_timeout() {
        const ADDR: &str = "localhost:3007";
        const MESSAGE: &str = "hello, socket!";

        // Message sender (socket server)
        let _ = thread::spawn(|| {
            sock_listen(ADDR, Some(Duration::from_secs(1)), |s| {
                assert!(
                    sock_write(s, MESSAGE.as_bytes(), Some(Duration::from_millis(500)),).is_ok()
                );
            })
        });

        // Wait for the listener to set up
        sleep(Duration::from_millis(100));

        // Message receiver (socket client)
        let stream = sock_conn(ADDR).unwrap(); // already checked above
        let mut buf: [u8; 1024] = [0; 1024];

        let res = sock_read(stream, &mut buf[..], Some(Duration::from_nanos(1)));
        assert!(res.is_err());
        let res = res.err().unwrap().kind();
        assert!((res == io::ErrorKind::WouldBlock) || (res == io::ErrorKind::InvalidInput));
    }
}
