extern crate dns_parser;
extern crate pnet;
extern crate pcap;
extern crate string_error;

use string_error::{static_err};

use dns_parser::{Builder, RRData, ResponseCode};
use dns_parser::{QueryType, QueryClass};

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
            if let Ok(_) = print_dns(packet.data) {
                // pass
            }
        }
    }
}

fn print_dns(data: &[u8]) -> Result<(), Box<Error>> {
    let eth_packet: EthernetPacket = EthernetPacket::new(&data).ok_or(static_err("Parse ethernet failed."))?;
    let ip_packet: Ipv4Packet = Ipv4Packet::new(eth_packet.payload()).ok_or(static_err("Parse ipv4 failed."))?;
    let udp_packet: UdpPacket = if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
        UdpPacket::new(ip_packet.payload()).ok_or(static_err("Parse udp failed."))?
    } else {
        return Err(static_err("Not udp packet."));
    };
    let dns_packet: dns_parser::Packet = dns_parser::Packet::parse(udp_packet.payload())?;

    println!("{:?}", dns_packet);

    Ok(())
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

fn resolve(name: String) -> Result<(), Box<Error>> {
    let mut builder = Builder::new_query(1, true);
    builder.add_question(&name, QueryType::A, QueryClass::IN);
    let packet = builder.build().map_err(|_| "truncated packet")?;
    let socket = UdpSocket::bind(SocketAddr::from(([0,0,0,0], 0))).expect("couldn't bind to address");
    let dest = SocketAddr::from(([8,8,4,4], 53));
    socket.send_to(&packet, dest).expect("couldn't send packet");
    let mut buf = vec![0u8; 4096];
    socket.recv(&mut buf)?;
    let pkt = dns_parser::Packet::parse(&buf)?;
    if pkt.header.response_code != ResponseCode::NoError {
        return Err(format!("{:?}", pkt.header.response_code).into());
    }
    if pkt.answers.len() == 0 {
        return Err("No records received".into());
    }
    for ans in pkt.answers {
        match ans.data {
            RRData::A(ip) => {
                println!("{}", ip);
            }
            _ => {} // ignore
        }
    }
    Ok(())
}