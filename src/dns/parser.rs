use dns::message;
use byteorder::{BE, ReadBytesExt};

pub struct Parser {
    data: Vec<u8>,
    peak: usize,
}

impl Parser {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data: data, peak: 0 }
    }

    pub fn parse(&mut self) -> message::Message {
        let id = self.read_u16();
        let head = self.read_u16();
        let qd_count = self.read_u16() as usize;
        let an_count = self.read_u16() as usize;
        let ns_count = self.read_u16() as usize;
        let ar_count = self.read_u16() as usize;

        let query_sections = self.parse_query_sections(qd_count);
        let answer_sections = self.parse_answer_sections(an_count);
        let authority_sections = self.parse_answer_sections(ns_count);
        let additional_information_sections = self.parse_answer_sections(ar_count);

        return message::Message {
            id: id,
            head: head,
            query_sections: query_sections,
            answer_sections: answer_sections,
            authority_sections: authority_sections,
            additional_information_sections: additional_information_sections,
        }
    }

    fn parse_query_sections(&mut self, count: usize) -> Vec<message::QuerySection> {
        let mut query_sections = vec![];
        for _ in 0..count {
            let qname = self.parse_name();
            let qtype = self.read_u16();
            let qclass = self.read_u16();

            let query_section = message::QuerySection {
                qname: qname, qtype: qtype, qclass: qclass
            };

            query_sections.push(query_section);
        }

        return query_sections;
    }

    fn parse_answer_sections(&mut self, count: usize) -> Vec<message::AnswerSection> {
        let mut answer_sections = vec![];

        for _ in 0..count {
            let answer_section = self.parse_answer_section();
            answer_sections.push(answer_section);
        }

        return answer_sections;
    }

    fn parse_answer_section(&mut self) -> message::AnswerSection {
        let aname = self.parse_name();
        let atype = self.read_u16();
        let aclass = self.read_u16();
        let ttl = self.read_u32();
        let rdlength = self.read_u16();
        let rdata = if atype == 5 {
            message::RData::Cname(self.parse_name())
        } else {
            let rdata_raw = self.read_peak_slice(rdlength.clone() as usize).to_vec();

            if atype == 1 {
                message::RData::Ipv4(rdata_raw)
            } else {
                message::RData::Unknown(rdata_raw)
            }
        };

        return message::AnswerSection {
            aname: aname,
            atype: atype,
            aclass: aclass,
            ttl: ttl,
            rdlength: rdlength,
            rdata: rdata,
        };
    }

    fn parse_name(&mut self) -> Vec<String> {
        if self.read_peak_static() == 0x00 {
            self.peak_proceed();

            return vec![];
        } else {
            if self.name_compressed() {
                let name_pointer = self.read_u16() & 0x3fff;
                let original_peak = self.peak;
                self.peak = name_pointer as usize;
                let pointed_name = self.parse_name();
                self.peak = original_peak;
                return pointed_name;
            } else {
                let label_length = self.read_peak();
                let label = self.read_peak_slice(label_length as usize).into_iter()
                                .map(|b| *b as char)
                                .collect::<String>();
                let mut name: Vec<String> = vec![ label ];
                let mut rest = self.parse_name();
                name.append(&mut rest);
                return name;
            }
        }
    }

    fn name_compressed(&self) -> bool {
        return (self.read_peak_static() & 0b1100_0000) == 0b1100_0000;
    }

    fn read_peak_slice(&mut self, len: usize) -> &[u8] {
        let result = &self.data[self.peak..=(self.peak+len-1)];
        self.peak += len;
        return result;
    }

    fn read_peak(&mut self) -> u8 {
        let result = self.data[self.peak];
        self.peak += 1;
        return result;
    }

    fn read_peak_static(&self) -> u8 {
        return self.data[self.peak];
    }

    fn peak_proceed(&mut self) {
        self.peak += 1;
    }

    fn read_u16(&mut self) -> u16 {
        self.read_peak_slice(2).read_u16::<BE>().expect("Failed to read u16.")
    }

    fn read_u32(&mut self) -> u32 {
        self.read_peak_slice(4).read_u32::<BE>().expect("Failed to read u32.")
    }
}