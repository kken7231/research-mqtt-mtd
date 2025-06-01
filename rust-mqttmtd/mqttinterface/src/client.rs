// Import necessary crates
use bytes::{Buf, BytesMut};
use mqttbytes::v5::{self, Packet, Publish, Subscribe};

use crate::{
    publish::unfreeze_publish,
    subscribe::{freeze_subscribed_publish, unfreeze_subscribe, ClientSubscriptionInfo},
};
use libmqttmtd::consts::UNIX_SOCK_MQTT_BROKER;
use libmqttmtd::socket::plain::client::PlainClient;
use libmqttmtd::socket::plain::stream::PlainStream;
use std::fmt::write;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

const BUF_SIZE: usize = 4096;

/// Intermediates an external client and an internal broker.
pub async fn handler(
    broker_port: u16,
    verifier_addr_str: String,
    enable_unix_sock: bool,
    client_stream: PlainStream,
    cli_addr_str: String,
) {
    let verifier_addr = verifier_addr_str.as_str();
    let cli_addr = cli_addr_str.as_str();

    // Make an address
    let broker_addr_str: String;
    let broker_addr = if enable_unix_sock {
        UNIX_SOCK_MQTT_BROKER
    } else {
        broker_addr_str = format!("localhost:{}", broker_port);
        broker_addr_str.as_str()
    };

    // Connect to the actual MQTT broker
    let broker_stream = if enable_unix_sock {
        #[cfg(unix)]
        PlainClient::new_unix(broker_addr, None).connect().await
    } else {
        match PlainClient::new_tcp(broker_addr, None) {
            Ok(client) => client.connect().await,
            Err(e) => Err(e),
        }
    };
    if let Err(e) = broker_stream {
        eprintln!(
            "couldn't make a connection to a broker {}: {}",
            broker_addr, e
        );
        return;
    }
    let broker_stream = broker_stream.unwrap();

    println!("Connected to broker at {}", broker_addr);

    // Split the streams for concurrent reading and writing
    let (mut brk_r, mut brk_w) = broker_stream.split();
    let (mut cli_r, mut cli_w) = client_stream.split();

    let subinfo_cli2serv = Arc::new(RwLock::new(ClientSubscriptionInfo::new()));
    let subinfo_serv2cli = subinfo_cli2serv.clone();

    let client_to_broker = new_mediator(
        &mut cli_r,
        cli_addr,
        &mut brk_w,
        "Broker",
        move |publish| async move {
            println!("Intercepted PUBLISH packet from {}.", cli_addr);
            let unfrozen = unfreeze_publish(verifier_addr, enable_unix_sock, publish).await;
            match &unfrozen {
                Ok(Some(_)) => println!(
                    "verification succeeded on PUBLISH packet from {}.",
                    cli_addr
                ),
                Ok(_) => eprintln!("verification failed on PUBLISH packet from {}.", cli_addr),
                Err(e) => eprintln!(
                    "error on unfreezing PUBLISH packet from {}: {}",
                    cli_addr, e
                ),
            };
            unfrozen
        },
        move |subscribe| {
            let info_cloned = subinfo_cli2serv.clone();
            async move {
                println!("Intercepted SUBSCRIBE packet from {}.", cli_addr);
                let unfrozen =
                    unfreeze_subscribe(&info_cloned, verifier_addr, enable_unix_sock, subscribe)
                        .await;
                match &unfrozen {
                    Ok(Some(_)) => println!(
                        "verification succeeded on SUBSCRIBE packet from {}.",
                        cli_addr
                    ),
                    Ok(_) => {
                        eprintln!("verification failed on SUBSCRIBE packet from {}.", cli_addr)
                    }
                    Err(e) => eprintln!(
                        "error on unfreezing SUBSCRIBE packet from {}: {}",
                        cli_addr, e
                    ),
                };
                unfrozen
            }
        },
    );

    let broker_to_client = new_mediator(
        &mut brk_r,
        "Broker",
        &mut cli_w,
        cli_addr,
        move |publish| {
            let info_cloned = subinfo_serv2cli.clone();
            async move {
                println!("Intercepted SUBSCRIBE packet to {}", cli_addr);
                let frozen = freeze_subscribed_publish(&info_cloned, publish).await;
                match &frozen {
                    Ok(Some(_)) => {
                        println!("PUBLISH packet to client {} successfully encoded", cli_addr)
                    }
                    Ok(_) => eprintln!("PUBLISH packet to client {} failed to encode", cli_addr),
                    Err(e) => eprintln!(
                        "error on freezing subscription PUBLISH packet to {}: {}",
                        cli_addr, e
                    ),
                };
                frozen
            }
        },
        |_| async {
            // Just ignore
            eprintln!(
                "broker subscription to client {} is not yet implemented",
                cli_addr
            );
            let res: Result<Option<Subscribe>, std::io::Error> = Ok(None);
            res
        },
    );

    // Run both tasks concurrently and wait for one to finish (which implies the
    // connection is closing)
    tokio::select! {
        Err(e) = client_to_broker => eprintln!("[client->broker] Error observed: {}", e),
        Err(e) = broker_to_client => eprintln!("[broker->client] Error observed: {}", e),
    }
}

enum MediatorError {
    /// Wraps a [std::io::Error] on socket -> buf.
    BufferReadError(std::io::Error),

    /// Wraps a [mqttbytes::Error] on buf -> packet.
    PacketReadError(mqttbytes::Error),

    /// Wraps a [mqttbytes::Error] on packet -> buf.
    PacketWriteError(mqttbytes::Error),

    /// Wraps a [std::io::Error] on buf -> socket.
    BufferWriteError(std::io::Error),

    OnPublishUnexpectedError(String),
    OnSubscribeUnexpectedError(String),
    DestinationDisconnectError,
}

impl std::fmt::Display for MediatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MediatorError::BufferReadError(e) => write!(f, "Error reading from socket: {}", e),
            MediatorError::PacketReadError(e) => {
                write!(f, "Error reading from buffer into a packet: {}", e)
            }
            MediatorError::PacketWriteError(e) => {
                write!(f, "Error writing a packet into a buffer: {}", e)
            }
            MediatorError::BufferWriteError(e) => write!(f, "Error writing to socket: {}", e),
            MediatorError::OnPublishUnexpectedError(e) => {
                write!(f, "Unexpected error on on_publish: {}", e)
            }
            MediatorError::OnSubscribeUnexpectedError(e) => {
                write!(f, "Unexpected error on on_subscribe: {}", e)
            }
            MediatorError::DestinationDisconnectError => {
                write(f, format_args!("Destination disconnected"))
            }
        }
    }
}
fn new_mediator<S, D, EP, FutP, FP, ES, FutS, FS>(
    mut src: S,
    src_name: &str,
    mut dest: D,
    dest_name: &str,
    on_publish: FP,
    on_subscribe: FS,
) -> impl Future<Output = Result<(), MediatorError>>
where
    S: AsyncRead + Unpin,
    D: AsyncWrite + Unpin,
    EP: std::error::Error,
    FutP: Future<Output = Result<Option<Publish>, EP>>,
    FP: Fn(Publish) -> FutP,
    ES: std::error::Error,
    FutS: Future<Output = Result<Option<Subscribe>, ES>>,
    FS: Fn(Subscribe) -> FutS,
{
    async move {
        let mut buf = BytesMut::with_capacity(BUF_SIZE);
        loop {
            // Read data from the source
            match src.read_buf(&mut buf).await {
                Err(e) => return Err(MediatorError::BufferReadError(e)),
                Ok(s) if s == 0 => return Err(MediatorError::DestinationDisconnectError),
                _ => (),
            };

            // Attempt to decode packets from the buffer
            while buf.has_remaining() {
                // Read packet
                let packet =
                    v5::read(&mut buf, BUF_SIZE).map_err(|e| MediatorError::PacketReadError(e))?;
                println!(
                    "({}=>{}) Packet received: {:?}",
                    src_name, dest_name, packet
                );

                // Buf that to be sent out
                let mut encoded_packet = BytesMut::new();

                match packet {
                    Packet::Connect(connect) => connect.write(&mut encoded_packet),
                    Packet::ConnAck(connack) => connack.write(&mut encoded_packet),
                    Packet::Publish(publish) => match on_publish(publish).await {
                        Ok(Some(processed)) => processed.write(&mut encoded_packet),
                        Ok(None) => {
                            println!(
                                "({}=>{}) on_publish failed (expected cause).",
                                src_name, dest_name
                            );
                            continue;
                        }
                        Err(e) => {
                            return Err(MediatorError::OnPublishUnexpectedError(e.to_string()));
                        }
                    },
                    Packet::PubAck(puback) => puback.write(&mut encoded_packet),
                    Packet::PubRec(pubrec) => pubrec.write(&mut encoded_packet),
                    Packet::PubRel(pubrel) => pubrel.write(&mut encoded_packet),
                    Packet::PubComp(pubcomp) => pubcomp.write(&mut encoded_packet),
                    Packet::Subscribe(subscribe) => match on_subscribe(subscribe).await {
                        Ok(Some(processed)) => processed.write(&mut encoded_packet),
                        Ok(None) => {
                            println!(
                                "({}=>{}) on_subscribe failed (expected cause).",
                                src_name, dest_name
                            );
                            continue;
                        }
                        Err(e) => {
                            return Err(MediatorError::OnSubscribeUnexpectedError(e.to_string()));
                        }
                    },
                    Packet::SubAck(suback) => suback.write(&mut encoded_packet),
                    Packet::Unsubscribe(unsub) => unsub.write(&mut encoded_packet),
                    Packet::UnsubAck(unsuback) => unsuback.write(&mut encoded_packet),
                    Packet::PingReq => v5::PingReq {}.write(&mut encoded_packet),
                    Packet::PingResp => v5::PingResp {}.write(&mut encoded_packet),
                    Packet::Disconnect(disconnect) => disconnect.write(&mut encoded_packet),
                }
                .map_err(|e| MediatorError::PacketWriteError(e))?;

                // Write the encoded packet to the broker
                dest.write_all(&encoded_packet)
                    .await
                    .map_err(|e| MediatorError::BufferWriteError(e))?;
                println!("({}=>{}) Packet forwarded.", src_name, dest_name);
            }
        }
    }
}
