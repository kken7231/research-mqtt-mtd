// Import necessary crates
use bytes::{Buf, BytesMut};
use mqttbytes::v5::{self, Packet, Publish, Subscribe};

use crate::{
    mqttinterface_eprintln, mqttinterface_println,
    publish::{PublishUnfreezeError, unfreeze_publish},
    subscribe::{
        ClientSubscriptionInfo, SubscribeUnfreezeError, SubscribedPublishFreezeError,
        freeze_subscribed_publish, unfreeze_subscribe,
    },
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
};

const BUF_SIZE: usize = 4096;

/// Intermediates an external client and an internal broker.
pub async fn handler(
    broker_port: u16,
    verifier_port: u16,
    mut client_stream: TcpStream,
    addr: SocketAddr,
) {
    let broker_addr = format!("localhost:{}", broker_port);
    let broker_addr = broker_addr.as_str();

    let client_sub_info: Arc<RwLock<ClientSubscriptionInfo>> =
        Arc::new(RwLock::new(ClientSubscriptionInfo::new()));
    let client_sub_info2 = client_sub_info.clone();

    // Connect to the actual MQTT broker
    let mut broker_stream = match TcpStream::connect(broker_addr).await {
        Err(e) => {
            mqttinterface_eprintln!(
                "couldn't make a connection to a broker {}: {}",
                broker_addr,
                e
            );
            return;
        }
        Ok(s) => s,
    };
    mqttinterface_println!("Connected to broker at {}", broker_addr);

    // Split the streams for concurrent reading and writing
    let (mut client_reader, mut client_writer) = client_stream.split();
    let (mut broker_reader, mut broker_writer) = broker_stream.split();

    // Buffers for incoming data
    let mut client_buf = BytesMut::with_capacity(BUF_SIZE);
    let mut broker_buf = BytesMut::with_capacity(BUF_SIZE);

    // Task to handle data flow from client to broker
    let client_to_broker = async move {
        loop {
            // Read data from the client
            if match client_reader.read_buf(&mut client_buf).await {
                Err(e) => {
                    mqttinterface_eprintln!(
                        "couldn't read a buffer in connection with a client {}: {}",
                        addr,
                        e
                    );
                    return;
                }
                Ok(s) => s,
            } == 0
            {
                mqttinterface_eprintln!("client {} disconnected", addr);
                break;
            }

            // Attempt to decode packets from the buffer
            // mqttbytes::mqtt_bytes returns Result<Option<Packet>, Error>
            while client_buf.has_remaining() {
                match v5::read(&mut client_buf, BUF_SIZE) {
                    Ok(packet) => {
                        mqttinterface_println!("Received packet from {}: {:?}", addr, packet);

                        let mut encoded_packet = BytesMut::new();
                        if let Err(e) = match packet {
                            Packet::Connect(connect) => connect.write(&mut encoded_packet),
                            Packet::ConnAck(connack) => connack.write(&mut encoded_packet),
                            Packet::Publish(publish) => {
                                match intercept_cli2serv_publish(publish, addr, verifier_port).await
                                {
                                    Ok(Some(unfreezed)) => unfreezed.write(&mut encoded_packet),
                                    Ok(None) => continue,
                                    Err(_) => return,
                                }
                            }
                            Packet::PubAck(puback) => puback.write(&mut encoded_packet),
                            Packet::PubRec(pubrec) => pubrec.write(&mut encoded_packet),
                            Packet::PubRel(pubrel) => pubrel.write(&mut encoded_packet),
                            Packet::PubComp(pubcomp) => pubcomp.write(&mut encoded_packet),
                            Packet::Subscribe(subscribe) => {
                                match intercept_cli2serv_subscribe(
                                    &client_sub_info,
                                    subscribe,
                                    addr,
                                    verifier_port,
                                )
                                .await
                                {
                                    Ok(Some(unfreezed)) => unfreezed.write(&mut encoded_packet),
                                    Ok(None) => continue,
                                    Err(_) => return,
                                }
                            }
                            Packet::SubAck(suback) => suback.write(&mut encoded_packet),
                            Packet::Unsubscribe(unsub) => unsub.write(&mut encoded_packet),
                            Packet::UnsubAck(unsuback) => unsuback.write(&mut encoded_packet),
                            Packet::PingReq => v5::PingReq {}.write(&mut encoded_packet),
                            Packet::PingResp => v5::PingResp {}.write(&mut encoded_packet),
                            Packet::Disconnect(disconnect) => disconnect.write(&mut encoded_packet),
                        } {
                            mqttinterface_eprintln!(
                                "couldn't write a packet to a buffer for Broker {}: {}",
                                broker_addr,
                                e
                            );
                            return;
                        }

                        // Write the encoded packet to the broker
                        match broker_writer.write_all(&encoded_packet).await {
                            Err(e) => {
                                mqttinterface_eprintln!(
                                    "couldn't read a buffer in connection with a client {}: {}",
                                    addr,
                                    e
                                );
                                return;
                            }
                            Ok(s) => s,
                        }
                        mqttinterface_println!("Forwarded packet to broker.");
                    }
                    Err(e) => {
                        // Decoding error
                        mqttinterface_eprintln!("Decoding error from {}: {}", addr, e);
                        return;
                    }
                }
            }
        }
    };

    // Task to handle data flow from broker to client (e.g., CONNACK, SUBACK, etc.)
    let broker_to_client = async move {
        loop {
            // Read data from the client
            if match broker_reader.read_buf(&mut broker_buf).await {
                Err(e) => {
                    mqttinterface_eprintln!(
                        "couldn't read a buffer in connection with Broker {}: {}",
                        broker_addr,
                        e
                    );
                    return;
                }
                Ok(s) => s,
            } == 0
            {
                mqttinterface_eprintln!("broker {} disconnected", addr);
                break;
            }

            // Attempt to decode packets from the buffer
            while broker_buf.has_remaining() {
                match v5::read(&mut broker_buf, BUF_SIZE) {
                    Ok(packet) => {
                        mqttinterface_println!(
                            "Received packet from Broker {}: {:?}",
                            broker_addr,
                            packet
                        );

                        let mut encoded_packet = BytesMut::new();
                        if let Err(e) = match packet {
                            Packet::ConnAck(connack) => connack.write(&mut encoded_packet),
                            Packet::Publish(publish) => {
                                match intercept_serv2cli_publish(&client_sub_info2, publish, addr)
                                    .await
                                {
                                    Ok(Some(freezed)) => freezed.write(&mut encoded_packet),
                                    Ok(None) => continue,
                                    Err(_) => return,
                                }
                            }
                            Packet::PubAck(puback) => puback.write(&mut encoded_packet),
                            Packet::PubRec(pubrec) => pubrec.write(&mut encoded_packet),
                            Packet::PubRel(pubrel) => pubrel.write(&mut encoded_packet),
                            Packet::PubComp(pubcomp) => pubcomp.write(&mut encoded_packet),
                            Packet::SubAck(suback) => suback.write(&mut encoded_packet),
                            Packet::UnsubAck(unsuback) => unsuback.write(&mut encoded_packet),
                            Packet::PingReq => v5::PingReq {}.write(&mut encoded_packet),
                            Packet::PingResp => v5::PingResp {}.write(&mut encoded_packet),
                            Packet::Disconnect(disconnect) => disconnect.write(&mut encoded_packet),
                            other => {
                                mqttinterface_println!(
                                    "received outgoing {:?}, but it's blocked",
                                    other
                                );
                                continue;
                            }
                        } {
                            mqttinterface_eprintln!(
                                "couldn't write a packet to a buffer for Client {}: {}",
                                broker_addr,
                                e
                            );
                            return;
                        }

                        // Write the encoded packet to the broker
                        match client_writer.write_all(&encoded_packet).await {
                            Err(e) => {
                                mqttinterface_eprintln!(
                                    "couldn't read a buffer in connection with Broker {}: {}",
                                    broker_addr,
                                    e
                                );
                                return;
                            }
                            Ok(s) => s,
                        }
                        mqttinterface_println!("Forwarded packet to client.");
                    }
                    Err(e) => {
                        // Decoding error
                        mqttinterface_eprintln!("Decoding error from {}: {}", addr, e);
                        return;
                    }
                }
            }
        }
    };

    // Run both tasks concurrently and wait for one to finish (which implies the
    // connection is closing)
    tokio::select! {
        _ = client_to_broker => (),
        _ = broker_to_client => (),
    }
}

async fn intercept_cli2serv_publish(
    publish: Publish,
    from_addr: SocketAddr,
    verifier_port: u16,
) -> Result<Option<Publish>, PublishUnfreezeError> {
    mqttinterface_println!("Intercepted PUBLISH packet from {}.", from_addr);
    match unfreeze_publish(verifier_port, publish).await {
        Ok(Some(modified)) => {
            mqttinterface_println!(
                "verification succeeded on PUBLISH packet from {}.",
                from_addr
            );
            Ok(Some(modified))
        }
        Ok(_) => {
            mqttinterface_eprintln!("verification failed on PUBLISH packet from {}.", from_addr);
            Ok(None)
        }
        Err(e) => {
            mqttinterface_eprintln!(
                "error on unfreezing PUBLISH packet from {}: {}",
                from_addr,
                e
            );
            Err(e)
        }
    }
}

async fn intercept_cli2serv_subscribe(
    subscription_info: &Arc<RwLock<ClientSubscriptionInfo>>,
    subscribe: Subscribe,
    from_addr: SocketAddr,
    verifier_port: u16,
) -> Result<Option<Subscribe>, SubscribeUnfreezeError> {
    mqttinterface_println!("Intercepted SUBSCRIBE packet from {}.", from_addr);
    match unfreeze_subscribe(subscription_info, verifier_port, subscribe).await {
        Ok(Some(unfreezed)) => {
            mqttinterface_println!(
                "verification succeeded on SUBSCRIBE packet from {}.",
                from_addr
            );
            Ok(Some(unfreezed))
        }
        Ok(_) => {
            mqttinterface_eprintln!(
                "verification failed on SUBSCRIBE packet from {}.",
                from_addr
            );
            Ok(None)
        }
        Err(e) => {
            mqttinterface_eprintln!(
                "error on unfreezing SUBSCRIBE packet from {}: {}",
                from_addr,
                e
            );
            Err(e)
        }
    }
}

async fn intercept_serv2cli_publish(
    subscription_info: &Arc<RwLock<ClientSubscriptionInfo>>,
    publish: Publish,
    cli_addr: SocketAddr,
) -> Result<Option<Publish>, SubscribedPublishFreezeError> {
    mqttinterface_println!("Intercepted SUBSCRIBE packet to {}", cli_addr);
    match freeze_subscribed_publish(subscription_info, publish).await {
        Ok(Some(freezed)) => {
            mqttinterface_println!("PUBLISH packet to client {} successfully encoded", cli_addr);
            Ok(Some(freezed))
        }
        Ok(_) => {
            mqttinterface_println!("PUBLISH packet to client {} failed to encode", cli_addr);
            Ok(None)
        }
        Err(e) => {
            mqttinterface_println!(
                "error on freezing subscription PUBLISH packet to {}: {}",
                cli_addr,
                e
            );
            Err(e)
        }
    }
}
