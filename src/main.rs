extern crate dns_parser;
extern crate pnet;

use dns_parser::{Builder, Packet, RRData, ResponseCode};
use dns_parser::{QueryType, QueryClass};

use pnet::transport::{TransportChannelType, transport_channel};
use pnet::packet::ip::IpNextHeaderProtocols;

use std::net::{UdpSocket, SocketAddr};
use std::error::Error;

fn main() {
}

fn sniff(device_name: String) -> Result<(), Box<Error>> {
    
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
    let pkt = Packet::parse(&buf)?;
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