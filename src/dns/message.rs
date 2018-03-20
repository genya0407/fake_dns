use std::fmt;
use std::slice::SliceConcatExt;
use hex_slice::AsHex;

#[derive(Debug)]
pub enum RData {
    Cname(Vec<String>),
    Ipv4(Vec<u8>),
    Unknown(Vec<u8>),
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &RData::Cname(ref labels) => {
                write!(f, "{}", labels.join("."))
            },
            &RData::Ipv4(ref sections) => {
                write!(f, "{}.{}.{}.{}", sections[0], sections[1], sections[2], sections[3])
            },
            &RData::Unknown(ref data) => {
                write!(f, "{:02x}", data.as_hex())
            }
        }
    }
}

#[derive(Debug)]
pub struct QuerySection {
    pub qname: Vec<String>,
    pub qtype: u16,
    pub qclass: u16
}

impl fmt::Display for QuerySection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: type {}, class {}", self.qname.join("."), self.qtype, self.qclass)
    }
}

#[derive(Debug)]
pub struct AnswerSection {
    pub aname: Vec<String>,
    pub atype: u16,
    pub aclass: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: RData
}

impl fmt::Display for AnswerSection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: type {}, class {}, rdata {}", self.aname.join("."), self.atype, self.aclass, self.rdata)
    }
}

#[derive(Debug)]
pub struct Message {
    pub id: u16,
    pub head: u16,
    pub query_sections: Vec<QuerySection>,
    pub answer_sections: Vec<AnswerSection>,
    pub authority_sections: Vec<AnswerSection>,
    pub additional_information_sections: Vec<AnswerSection>,
}

impl Message {
    pub fn is_query(&self) -> bool {
        (self.head & 0x80) == 0
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut string = String::from("");
        for section in &self.query_sections {
            string += &format!("Query      | {}\n", section);
        }
        for section in &self.answer_sections {
            string += &format!("Answer     | {}\n", section);
        }
        for section in &self.authority_sections {
            string += &format!("Authority  | {}\n", section);
        }
        for section in &self.additional_information_sections {
            string += &format!("Additi info| {}\n", section);
        }
        write!(f, "{}", string)
    }
}
