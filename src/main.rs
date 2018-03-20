extern crate fake_dns;
extern crate pnet;
extern crate pcap;
extern crate string_error;

use string_error::{static_err};

use pcap::{Device, Capture, Active};

use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;

use std::net::{UdpSocket, SocketAddr};
use std::error::Error;

fn main() {
    sniff().unwrap()
}

fn sniff() -> Result<(), Box<Error>> {
    let device_name = "en1";
    let mut cap = init_capture(device_name.to_string())?;
    loop {
        while let Ok(packet) = cap.next() {
            if let Ok(dns_message) = parse_dns(packet.data) {
                println!("{}", dns_message);
            }
        }
    }
}

fn parse_dns(data: &[u8]) -> Result<fake_dns::dns::message::DnsMessage, Box<Error>> {
    let eth_packet: EthernetPacket = EthernetPacket::new(&data).ok_or(static_err("Parse ethernet failed."))?;
    let ip_packet: Ipv4Packet = Ipv4Packet::new(eth_packet.payload()).ok_or(static_err("Parse ipv4 failed."))?;
    let udp_packet: UdpPacket = if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
        UdpPacket::new(ip_packet.payload()).ok_or(static_err("Parse udp failed."))?
    } else {
        return Err(static_err("Not udp packet."));
    };
    if !(udp_packet.get_destination() == 53 || udp_packet.get_source() == 53) {
        return Err(static_err("Not dns packet."));
    }
    let mut parser = fake_dns::dns::parser::Parser::new(udp_packet.payload().to_vec());
    let dns_message = parser.parse();

    Ok(dns_message)
}

fn init_capture(name: String) -> Result<Capture<Active>, Box<Error>> {
    let device = Device::list()?
                    .into_iter()
                    .find(|device| device.name == name)
                    .expect("Device not found.");
    let cap = Capture::from_device(device)?
                    .promisc(true)
                    .snaplen(5000)
                    .open()?;
    Ok(cap)
}
