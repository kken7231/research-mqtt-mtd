pub mod client;
pub mod server;
pub mod stream;
pub mod tcp;
#[cfg(unix)]
pub mod unix;

#[cfg(test)]
mod tests {
    use crate::{
        localhost_v4,
        socket::{
            error::SocketError,
            plain::{client::PlainClient, server::PlainServer, tcp::TcpServerType::LOCAL},
        },
    };
    use std::{fs, io::ErrorKind, sync::LazyLock, time::Duration};
    use tokio::{sync::RwLock, time::timeout};

    static UNUSED_PORT: LazyLock<RwLock<u16>> = LazyLock::new(|| RwLock::new(3000));

    async fn get_port() -> u16 {
        let mut port = UNUSED_PORT.write().await;
        let cur_port = *port;
        *port += 1;
        cur_port
    }

    #[tokio::test]
    async fn tcp_spawn_serv_cli_pass() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        let port = get_port().await;

        // Spawn server
        let _ = PlainServer::new_tcp(port, TO_SERVER, LOCAL)
            .unwrap()
            .spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client and connect
        let cli_sock = PlainClient::new_tcp(localhost_v4!(port).as_str(), TO_CLIENT)
            .unwrap()
            .connect()
            .await;
        assert!(cli_sock.is_ok());
    }

    #[tokio::test]
    async fn tcp_spawn_serv_zero_duration() {
        const TO_SERVER: Duration = Duration::ZERO;

        let port = get_port().await;

        match timeout(
            Duration::from_secs(1),
            PlainServer::new_tcp(port, TO_SERVER, LOCAL)
                .unwrap()
                .spawn(|_, _| async {}),
        )
        .await
        {
            Ok(Ok(Err(SocketError::InvalidTimeoutError(e)))) => assert_eq!(e, TO_SERVER),
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn tcp_spawn_cli_none_duration() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Option<Duration> = None;

        let port = get_port().await;

        // Spawn server
        let _ = PlainServer::new_tcp(port, TO_SERVER, LOCAL)
            .unwrap()
            .spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client
        match timeout(
            Duration::from_secs(1),
            PlainClient::new_tcp(localhost_v4!(port).as_str(), TO_CLIENT)
                .unwrap()
                .connect(),
        )
        .await
        {
            Ok(Ok(_)) => {}
            _ => panic!(),
        };
    }

    #[tokio::test]
    async fn tcp_listen_conn_not_listening() {
        const TO_CLIENT: Duration = Duration::from_secs(1);

        let port = get_port().await;

        // Try connecting
        match timeout(
            Duration::from_secs(2),
            PlainClient::new_tcp(localhost_v4!(port).as_str(), TO_CLIENT)
                .unwrap()
                .connect(),
        )
        .await
        {
            Ok(Err(SocketError::ConnectError(e))) => {
                assert_eq!(e.kind(), ErrorKind::ConnectionRefused)
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    async fn tcp_listen_conn_after_deadline() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        let port = get_port().await;

        // Spawn server
        let _ = PlainServer::new_tcp(port, TO_SERVER, LOCAL)
            .unwrap()
            .spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(TO_SERVER + Duration::from_secs(1)).await;

        // Spawn client and connect
        assert!(
            match PlainClient::new_tcp(localhost_v4!(port).as_str(), TO_CLIENT)
                .unwrap()
                .connect()
                .await
            {
                Err(SocketError::ConnectError(e)) => e.kind() == ErrorKind::ConnectionRefused,
                _ => false,
            }
        );
    }

    static UNUSED_PATH_SEED: LazyLock<RwLock<u16>> = LazyLock::new(|| RwLock::new(1));

    async fn get_path() -> String {
        let mut seed = UNUSED_PATH_SEED.write().await;
        let cur_seed = *seed;
        *seed += 1;
        format!("/tmp/testing{}.sock", cur_seed)
    }

    #[tokio::test]
    async fn unix_spawn_serv_cli_pass() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        let path = get_path().await;

        // Spawn server
        let _ = PlainServer::new_unix(path.as_str(), TO_SERVER).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client and connect
        let cli_sock = PlainClient::new_unix(path.as_str(), TO_CLIENT)
            .connect()
            .await;
        assert!(cli_sock.is_ok());
        assert!(fs::remove_file(path).is_ok());
    }

    #[tokio::test]
    async fn unix_spawn_serv_zero_duration() {
        const TO_SERVER: Duration = Duration::ZERO;

        let path = get_path().await;

        match timeout(
            Duration::from_secs(1),
            PlainServer::new_unix(path.as_str(), TO_SERVER).spawn(|_, _| async {}),
        )
        .await
        {
            Ok(Ok(Err(SocketError::InvalidTimeoutError(e)))) => {
                assert!(fs::remove_file(path).is_ok());
                assert_eq!(e, TO_SERVER)
            }
            _ => {
                assert!(fs::remove_file(path).is_ok());
                panic!()
            }
        }
    }

    #[tokio::test]
    async fn unix_spawn_cli_none_duration() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Option<Duration> = None;

        let path = get_path().await;

        // Spawn server
        let _ = PlainServer::new_unix(path.as_str(), TO_SERVER).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client
        match timeout(
            Duration::from_secs(1),
            PlainClient::new_unix(path.as_str(), TO_CLIENT).connect(),
        )
        .await
        {
            Ok(Ok(_)) => {
                assert!(fs::remove_file(path).is_ok());
            }
            _ => {
                assert!(fs::remove_file(path).is_ok());
                panic!()
            }
        };
    }

    #[tokio::test]
    async fn unix_listen_conn_not_listening() {
        const TO_CLIENT: Duration = Duration::from_secs(1);

        let path = get_path().await;

        // Try connecting
        match timeout(
            Duration::from_secs(2),
            PlainClient::new_unix(path.as_str(), TO_CLIENT).connect(),
        )
        .await
        {
            Ok(Err(SocketError::ConnectError(e))) => {
                assert_eq!(e.kind(), ErrorKind::NotFound)
            }
            _ => {
                panic!()
            }
        };
    }

    #[tokio::test]
    async fn unix_listen_conn_after_deadline() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        let path = get_path().await;

        // Spawn server
        let _ = PlainServer::new_unix(path.as_str(), TO_SERVER).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(TO_SERVER + Duration::from_secs(1)).await;

        // Spawn client and connect
        match PlainClient::new_unix(path.as_str(), TO_CLIENT)
            .connect()
            .await
        {
            Err(SocketError::ConnectError(e)) => {
                assert!(fs::remove_file(path).is_ok());
                assert_eq!(e.kind(), ErrorKind::ConnectionRefused)
            }
            _ => {
                assert!(fs::remove_file(path).is_ok());
                panic!()
            }
        };
    }
}
