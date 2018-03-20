use dns::message;
use byteorder::{BE, WriteBytesExt};

pub struct Serializer {
    data: Vec<u8>
}

impl Serializer {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn serialize(mut self, msg: message::Message) -> Vec<u8> {
        self.write_u16(msg.id);
        self.write_u16(msg.head);
        self.write_u16(msg.query_sections.len() as u16);
        self.write_u16(msg.answer_sections.len() as u16);
        self.write_u16(msg.authority_sections.len() as u16);
        self.write_u16(msg.additional_information_sections.len() as u16);
        self.write_query_sections(msg.query_sections);
        self.write_answer_sections(msg.answer_sections);
        self.write_answer_sections(msg.authority_sections);
        self.write_answer_sections(msg.additional_information_sections);
        self.data
    }

    fn write_query_sections(&mut self, sections: Vec<message::QuerySection>) {
        for section in sections {
            self.write_query_section(section);
        }
    }

    fn write_answer_sections(&mut self, sections: Vec<message::AnswerSection>) {
        for section in sections {
            self.write_answer_section(section);
        }        
    }

    fn write_query_section(&mut self, section: message::QuerySection) {
        self.write_name(section.qname);
        self.write_u16(section.qtype);
        self.write_u16(section.qclass);
    }

    fn write_answer_section(&mut self, section: message::AnswerSection) {
        self.write_name(section.aname);
        self.write_u16(section.atype);
        self.write_u16(section.aclass);
        self.write_u32(section.ttl);
        self.write_u16(section.rdlength);
        self.write_rdata(section.rdata);
    }

    fn write_name(&mut self, labels: Vec<String>) {
        for label in labels {
            self.write_u8(label.len() as u8);
            for c in label.as_bytes() {
                self.write_u8(*c)
            }
        }
        self.write_u8(0x00)
    }

    fn write_rdata(&mut self, rdata: message::RData) {
        match rdata {
            message::RData::Cname(name) => self.write_name(name),
            message::RData::Ipv4(bytes) |
            message::RData::Unknown(bytes) => self.write_bytes(bytes),
        }
    }

    fn write_bytes(&mut self, values: Vec<u8>) {
        self.data.extend(values.into_iter())
    }

    fn write_u32(&mut self, value: u32) {
        self.data.write_u32::<BE>(value).unwrap();
    }

    fn write_u16(&mut self, value: u16) {
        self.data.write_u16::<BE>(value).unwrap();
    }

    fn write_u8(&mut self, value: u8) {
        self.data.write_u8(value).unwrap();
    }
}