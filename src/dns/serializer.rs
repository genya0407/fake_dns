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

        let rdata_bytes = self.generate_rdata_bytes(section.rdata);
        self.write_u16(rdata_bytes.len() as u16);
        self.write_bytes(rdata_bytes);
    }

    fn write_name(&mut self, labels: Vec<String>) {
        let bytes = self.generate_name_bytes(labels);
        self.write_bytes(bytes);
    }

    fn generate_name_bytes(&mut self, labels: Vec<String>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in labels {
            bytes.write_u8(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.write_u8(0x00);

        return bytes;
    }

    fn generate_rdata_bytes(&mut self, rdata: message::RData) -> Vec<u8> {
        match rdata {
            message::RData::Cname(name) => self.generate_name_bytes(name),
            message::RData::Ipv4(bytes) |
            message::RData::Unknown(bytes) => bytes,
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