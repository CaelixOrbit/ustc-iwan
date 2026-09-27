use super::IpTunnelDevice;
use crate::core::{crypto, protocol};
use anyhow::{Context, Result};
use smoltcp::wire::{IpAddress, Ipv4Packet, TcpPacket};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

pub(crate) const VPN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) const CONTROL_QUEUE_CAPACITY: usize = 64;

pub(crate) struct ControlPacket {
    bytes: Vec<u8>,
    is_keepalive: bool,
}

pub(crate) enum SendStatus {
    Sent,
    Blocked,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_vpn(
    sock: &UdpSocket,
    device: &mut IpTunnelDevice,
    xor_key: &[u8],
    sid: u16,
    token: u32,
    mtu: usize,
    encryption: u8,
    session_started: Instant,
    control_queue: &mut VecDeque<ControlPacket>,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        if !device.has_rx_capacity() || control_queue.len() >= CONTROL_QUEUE_CAPACITY {
            return Ok(());
        }
        match sock.recv(&mut buf) {
            Ok(n) if n >= 8 => {
                let packet_type = buf[0];
                let packet_sid = u16::from_be_bytes([buf[2], buf[3]]);
                let packet_token = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                if packet_sid != sid || packet_token != token {
                    continue;
                }
                if packet_type == protocol::PT_CLOSE {
                    anyhow::bail!(
                        "VPN server closed the session after {:?}: len={n} enc={} sid={:#06x} \
                         token={:#010x} payload={}",
                        session_started.elapsed(),
                        buf[1],
                        packet_sid,
                        packet_token,
                        crypto::hex(&buf[8..n])
                    );
                }
                if packet_type == protocol::PT_ECHO_REQ {
                    let header = protocol::pkhdr(protocol::PT_ECHO_RES, encryption, sid, token);
                    control_queue.push_back(ControlPacket {
                        bytes: protocol::ctrl_pkt(&header, &[]),
                        is_keepalive: false,
                    });
                    continue;
                }
                if packet_type != protocol::PT_DATA && packet_type != protocol::PT_DATA_ENC {
                    continue;
                }
                let mut packet = buf[8..n].to_vec();
                if packet_type == protocol::PT_DATA_ENC {
                    crypto::xor(&mut packet, xor_key);
                }
                if validate_inner_ipv4(&packet, mtu) {
                    log_tcp_packet("VPN RX", &packet);
                    device.push_rx_packet(packet);
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("receive VPN packet"),
        }
    }
}

pub(crate) fn enqueue_vpn_keepalive(
    sid: u16,
    token: u32,
    encryption: u8,
    last_keepalive: Instant,
    control_queue: &mut VecDeque<ControlPacket>,
) {
    if last_keepalive.elapsed() < VPN_KEEPALIVE_INTERVAL
        || control_queue.iter().any(|packet| packet.is_keepalive)
        || control_queue.len() == CONTROL_QUEUE_CAPACITY
    {
        return;
    }
    let header = protocol::pkhdr(protocol::PT_ECHO_REQ, encryption, sid, token);
    control_queue.push_back(ControlPacket {
        bytes: protocol::ctrl_pkt(&header, &[]),
        is_keepalive: true,
    });
}

pub(crate) fn send_vpn(
    sock: &UdpSocket,
    device: &mut IpTunnelDevice,
    xor_key: &[u8],
    sid: u16,
    token: u32,
    encryption: u8,
) -> Result<SendStatus> {
    loop {
        match send_next_vpn_packet(device, xor_key, sid, token, encryption, |packet| {
            sock.send(packet)
        })
        .context("send VPN packet")?
        {
            Some(SendStatus::Sent) => continue,
            Some(SendStatus::Blocked) => return Ok(SendStatus::Blocked),
            None => return Ok(SendStatus::Sent),
        }
    }
}

pub(crate) fn send_vpn_control(
    sock: &UdpSocket,
    control_queue: &mut VecDeque<ControlPacket>,
) -> Result<Option<bool>> {
    send_next_control_packet(control_queue, |packet| sock.send(packet))
        .context("send VPN control packet")
}

fn send_next_vpn_packet<F>(
    device: &mut IpTunnelDevice,
    xor_key: &[u8],
    sid: u16,
    token: u32,
    encryption: u8,
    send: F,
) -> Result<Option<SendStatus>>
where
    F: FnOnce(&[u8]) -> std::io::Result<usize>,
{
    let Some(packet) = device.peek_tx_packet() else {
        return Ok(None);
    };
    log_tcp_packet("VPN TX", packet);
    let mut payload = packet.to_vec();
    let packet_type = if encryption == 0 {
        protocol::PT_DATA
    } else {
        crypto::xor(&mut payload, xor_key);
        protocol::PT_DATA_ENC
    };
    let header = protocol::pkhdr(packet_type, encryption, sid, token);
    let wire_packet = protocol::data_pkt(&header, &payload);
    match send_datagram(&wire_packet, send)? {
        SendStatus::Sent => {
            let _ = device.pop_tx_packet();
            Ok(Some(SendStatus::Sent))
        }
        SendStatus::Blocked => Ok(Some(SendStatus::Blocked)),
    }
}

fn send_next_control_packet<F>(
    control_queue: &mut VecDeque<ControlPacket>,
    send: F,
) -> Result<Option<bool>>
where
    F: FnOnce(&[u8]) -> std::io::Result<usize>,
{
    let Some(packet) = control_queue.front() else {
        return Ok(Some(false));
    };
    if matches!(send_datagram(&packet.bytes, send)?, SendStatus::Blocked) {
        return Ok(None);
    }
    let is_keepalive = control_queue
        .pop_front()
        .expect("control packet disappeared during send")
        .is_keepalive;
    Ok(Some(is_keepalive))
}

fn send_datagram<F>(packet: &[u8], send: F) -> Result<SendStatus>
where
    F: FnOnce(&[u8]) -> std::io::Result<usize>,
{
    match send(packet) {
        Ok(n) if n == packet.len() => Ok(SendStatus::Sent),
        Ok(n) => anyhow::bail!("partial UDP datagram send: {n} of {} bytes", packet.len()),
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(SendStatus::Blocked),
        Err(e) => Err(e.into()),
    }
}

fn validate_inner_ipv4(packet: &[u8], mtu: usize) -> bool {
    !packet.is_empty() && packet.len() <= mtu && packet[0] >> 4 == 4 && packet.len() >= 20
}

fn log_tcp_packet(direction: &str, packet: &[u8]) {
    if !crate::core::util::debug_enabled() {
        return;
    }
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl + 20 {
        return;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    let flags = packet[ihl + 13];
    if flags & 0x07 == 0 {
        return;
    }

    let tcp_header_len = usize::from(packet[ihl + 12] >> 4) * 4;
    let options = if tcp_header_len >= 20 && packet.len() >= ihl + tcp_header_len {
        crypto::hex(&packet[ihl + 20..ihl + tcp_header_len])
    } else {
        "<invalid>".to_string()
    };
    let ip_ok = Ipv4Packet::new_unchecked(packet).verify_checksum();
    let tcp_ok = TcpPacket::new_unchecked(&packet[ihl..])
        .verify_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
    let seq = u32::from_be_bytes([
        packet[ihl + 4],
        packet[ihl + 5],
        packet[ihl + 6],
        packet[ihl + 7],
    ]);
    let ack = u32::from_be_bytes([
        packet[ihl + 8],
        packet[ihl + 9],
        packet[ihl + 10],
        packet[ihl + 11],
    ]);
    eprintln!(
        "[{direction}] {src}:{src_port} -> {dst}:{dst_port} flags={}{}{}{} len={} \
         seq={seq:#010x} ack={ack:#010x} checksum=ip:{ip_ok}/tcp:{tcp_ok} \
         tcp_hlen={tcp_header_len} options={options} raw={}",
        if flags & 0x02 != 0 { "S" } else { "" },
        if flags & 0x10 != 0 { "A" } else { "" },
        if flags & 0x04 != 0 { "R" } else { "" },
        if flags & 0x01 != 0 { "F" } else { "" },
        packet.len(),
        crypto::hex(packet)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_ipv4_packets_within_mtu() {
        let mut ipv4 = vec![0; 20];
        ipv4[0] = 0x45;
        assert!(validate_inner_ipv4(&ipv4, 1380));
        assert!(!validate_inner_ipv4(&ipv4, 19));

        let mut ipv6 = vec![0; 40];
        ipv6[0] = 0x60;
        assert!(!validate_inner_ipv4(&ipv6, 1380));
        assert!(!validate_inner_ipv4(&[0x10; 20], 1380));
    }

    #[test]
    fn retries_would_block_without_reencrypting_or_dropping_packet() {
        let mut device = IpTunnelDevice::new(1380);
        let original = vec![0x45, 0, 1, 2, 3];
        device.push_tx_packet(original.clone());
        let key = [0xa5, 0x5a];
        let blocked = send_next_vpn_packet(&mut device, &key, 1, 2, 1, |_| {
            Err(std::io::Error::from(ErrorKind::WouldBlock))
        })
        .unwrap();
        assert!(matches!(blocked, Some(SendStatus::Blocked)));
        assert_eq!(device.peek_tx_packet(), Some(original.as_slice()));

        let mut retried = Vec::new();
        let sent = send_next_vpn_packet(&mut device, &key, 1, 2, 1, |packet| {
            retried.extend_from_slice(packet);
            Ok(packet.len())
        })
        .unwrap();
        assert!(matches!(sent, Some(SendStatus::Sent)));
        assert_eq!(device.peek_tx_packet(), None);
        let mut expected_payload = original;
        crypto::xor(&mut expected_payload, &key);
        let header = protocol::pkhdr(protocol::PT_DATA_ENC, 1, 1, 2);
        assert_eq!(retried, protocol::data_pkt(&header, &expected_payload));
    }

    #[test]
    fn keeps_queued_keepalive_after_would_block() {
        let mut queue = VecDeque::new();
        enqueue_vpn_keepalive(1, 2, 0, Instant::now() - VPN_KEEPALIVE_INTERVAL, &mut queue);
        enqueue_vpn_keepalive(1, 2, 0, Instant::now() - VPN_KEEPALIVE_INTERVAL, &mut queue);
        assert_eq!(queue.len(), 1);
        assert_eq!(
            send_next_control_packet(&mut queue, |_| Err(std::io::Error::from(
                ErrorKind::WouldBlock
            )))
            .unwrap(),
            None
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(
            send_next_control_packet(&mut queue, |packet| Ok(packet.len())).unwrap(),
            Some(true)
        );
        assert!(queue.is_empty());
    }
}
