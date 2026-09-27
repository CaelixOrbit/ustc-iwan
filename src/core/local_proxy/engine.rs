use anyhow::{Context, Result};
use smoltcp::iface::{Config, Interface};
use smoltcp::time::Instant;
use smoltcp::wire::HardwareAddress;
use std::collections::VecDeque;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use super::connections::Connections;
use super::ProxyConfig;
use crate::core::netstack::{
    enqueue_vpn_keepalive, receive_vpn, send_vpn, send_vpn_control, ControlPacket, IpTunnelDevice,
    SendStatus, VPN_KEEPALIVE_INTERVAL,
};
use crate::core::protocol;

const DEFAULT_POLL: Duration = Duration::from_millis(10);
const SEND_BACKOFF: Duration = Duration::from_millis(10);

/// The VPN session runtime: keeps the tunnel socket, the userspace device
/// and the session keys, and pumps packets between them and the server.
pub(super) struct Engine<'a> {
    sock: &'a UdpSocket,
    device: IpTunnelDevice,
    connections: Connections<'a>,
    xor_key: &'a [u8],
    sid: u16,
    token: u32,
    encryption: u8,
    mtu: usize,
    session_started: StdInstant,
    last_keepalive: StdInstant,
    control_queue: VecDeque<ControlPacket>,
    next_send_at: StdInstant,
}

impl<'a> Engine<'a> {
    pub(super) fn new(
        listener: TcpListener,
        sock: &'a UdpSocket,
        config: &ProxyConfig<'a>,
    ) -> Result<Self> {
        let mut device = IpTunnelDevice::new(config.mtu);
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = random_seed();
        let iface = Interface::new(iface_config, &mut device, now());

        let session_started = StdInstant::now();
        let last_keepalive = session_started
            .checked_sub(VPN_KEEPALIVE_INTERVAL)
            .unwrap_or(session_started);

        Ok(Self {
            sock,
            device,
            connections: Connections::new(listener, iface, config)?,
            xor_key: config.xor_key,
            sid: config.sid,
            token: config.token,
            encryption: config.encryption,
            mtu: config.mtu,
            session_started,
            last_keepalive,
            control_queue: VecDeque::new(),
            next_send_at: session_started,
        })
    }

    pub(super) fn run(&mut self) -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let stop = running.clone();
        ctrlc::set_handler(move || stop.store(false, Ordering::Relaxed))
            .context("set SIGINT handler")?;

        while running.load(Ordering::Relaxed) {
            self.tick()?;
            let poll_delay = self
                .connections
                .poll_delay(now())
                .unwrap_or(DEFAULT_POLL)
                .min(DEFAULT_POLL);
            let send_delay = self
                .next_send_at
                .saturating_duration_since(StdInstant::now());
            let delay = if send_delay.is_zero() {
                poll_delay
            } else {
                send_delay
            };
            std::thread::sleep(delay);
        }

        self.connections.abort_all();
        self.connections.poll(&mut self.device, now());
        let _ = self.send_to_server();
        let close = protocol::pkhdr(protocol::PT_CLOSE, self.encryption, self.sid, self.token);
        let _ = self.sock.send(&protocol::ctrl_pkt(&close, &[]));
        Ok(())
    }

    fn tick(&mut self) -> Result<()> {
        enqueue_vpn_keepalive(
            self.sid,
            self.token,
            self.encryption,
            self.last_keepalive,
            &mut self.control_queue,
        );
        self.connections.accept()?;
        receive_vpn(
            self.sock,
            &mut self.device,
            self.xor_key,
            self.sid,
            self.token,
            self.mtu,
            self.encryption,
            self.session_started,
            &mut self.control_queue,
        )?;
        self.connections.service_inputs();
        self.connections.handle_dns();
        self.connections.poll(&mut self.device, now());
        self.connections.update_states();
        self.connections.service_outputs();
        let mut send_blocked = self.flush_control_frames()?;
        if !send_blocked && self.control_queue.is_empty() && StdInstant::now() >= self.next_send_at
        {
            send_blocked = matches!(self.send_to_server()?, SendStatus::Blocked);
        }
        if send_blocked {
            self.next_send_at = StdInstant::now() + SEND_BACKOFF;
        }
        self.connections.reap();
        Ok(())
    }

    fn flush_control_frames(&mut self) -> Result<bool> {
        if StdInstant::now() < self.next_send_at {
            return Ok(false);
        }
        while !self.control_queue.is_empty() {
            match send_vpn_control(self.sock, &mut self.control_queue)? {
                Some(true) => self.last_keepalive = StdInstant::now(),
                Some(false) => {}
                None => return Ok(true),
            }
        }
        Ok(false)
    }

    fn send_to_server(&mut self) -> Result<SendStatus> {
        if StdInstant::now() < self.next_send_at {
            return Ok(SendStatus::Blocked);
        }
        send_vpn(
            self.sock,
            &mut self.device,
            self.xor_key,
            self.sid,
            self.token,
            self.encryption,
        )
    }
}

fn now() -> Instant {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64;
    Instant::from_millis(millis)
}

fn random_seed() -> u64 {
    use rand::RngCore;
    rand::thread_rng().next_u64()
}
