extern crate bincode;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use std::env;
use std::net::UdpSocket;
use std::convert::TryInto;

#[derive(Serialize, Deserialize)]
struct DNSMessage {
    header: Vec<u8>,
    payload: Vec<u8>,
    answers_pr: u32,
    authority_rr: u32,
    additional_pr: u32,
}

#[derive(Serialize, Deserialize)]
struct HeaderSection {
    id: u16,
    codes: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

fn main() {
    if env::args().len() != 3 {
        println!("Invalid arguments!");
    } else {
        if let Some(hostname) = env::args().nth(1) {
            if let Some(dns_server) = env::args().nth(2) {
                get_ip(hostname, dns_server);
            }
        }
    }
}

fn get_ip(cname: String, dns_server: String) {
    let socket = UdpSocket::bind("0.0.0.0:34254").expect("couldn't bind to address");


    // ID for the dns transaction.
    let id = (0x00, 0x01);

    // Combined flags on two flags.
    // 16bits in order: 1 QR, 4 OPCode, 1 AA, 1 TC, 1 RD, 1 RA, 1 Z, 1 AD, 1 CD, 4 RCode
    // We have only recursion desired activated.
    let codes = (0x01, 0x00);

    // Two bytes for query quantity, we do 1 only.
    let question_qtd = (0x00, 0x01);

    // Type 1 for A query, looking for host address
    let qtype = (0x00, 0x01);

    // Type 1 for Internet
    let qclass = (0x00, 0x01);

    // Join all headers in a vector of bytes to be sent via UDP.
    let mut bytes = vec![id.0, id.1 , codes.0,codes.1, question_qtd.0, question_qtd.1];

    bytes.push(qtype.0);
    bytes.push(qtype.0);
    bytes.push(qtype.0);
    bytes.push(qtype.0);
    bytes.push(qtype.0);
    bytes.push(qtype.0);

    // After all headers we need to insert the name being searched.
    let mut cname_bytes = transform_cname(cname);
    bytes.append(&mut cname_bytes);
    
    bytes.push(qtype.0);
    bytes.push(qtype.1);
    bytes.push(qclass.0);
    bytes.push(qclass.1);

    socket
        .send_to(&mut bytes, dns_server)
        .expect("couldn't send data");
    let mut buf = [0; 1024];
    match socket.recv(&mut buf) {
        Ok(received) => {
            let tmp_buff = &buf[..received];
            let answer_type_pos = bytes.len() + 3;
            let answer_type = (tmp_buff[answer_type_pos], tmp_buff[answer_type_pos+1]);

            if answer_type.0 + answer_type.1 == 1 {
                let answer_pos = answer_type_pos + 9;
                let answer = (
                    tmp_buff[answer_pos],
                    tmp_buff[answer_pos + 1],
                    tmp_buff[answer_pos + 2],
                    tmp_buff[answer_pos + 3]
                );
               
                println!("{}.{}.{}.{}", answer.0, answer.1, answer.2, answer.3);
            }

        },
        Err(e) => println!("recv function failed: {:?}", e),
    }
}

fn transform_cname(cname: String) -> Vec<u8> {
    let split = cname.split(".");
    let mut bytes = vec![];

    for s in split {
        let size = s.len().try_into().unwrap();

        bytes.push(size);
        bytes.append(&mut String::from(s.clone()).into_bytes());
    }
    // The final byte for the cname should be a 0.
    bytes.push(0b00000000);
    return bytes;
}
