extern crate bincode;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use std::env;
use std::net::UdpSocket;

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

    // for argument in env::args(){
    //     println!("{}", argument);
    // }
}

fn get_ip(cname: String, dns_server: String) {
    let socket = UdpSocket::bind("0.0.0.0:34254").expect("couldn't bind to address");
    // socket.connect(dns_server+":5005").expect("couldn't connect to address");
    // let message = build_message(cname);
    let id = (0b00000000, 0b00000001);
    let codes = (0b00000001, 0b00000000);
    let question_qtd = (0b00000000, 0b00000001);
    let mut bytes = vec![id.0, id.1 , codes.0,codes.1, question_qtd.0, question_qtd.1];

    let labels = transform_cname(cname);

    let one_flag: u16 = 0x0001;
    let mut cname_bytes = bincode::serialize(&labels).unwrap();
    let mut qtype_bytes = bincode::serialize(&one_flag).unwrap();
    let mut qclass_bytes = bincode::serialize(&one_flag).unwrap();

    let mut questions_bytes = vec![0; cname_bytes.len() + 4];

    questions_bytes.append(&mut cname_bytes);
    questions_bytes.append(&mut qtype_bytes);
    questions_bytes.append(&mut qclass_bytes);

    bytes.append(&mut questions_bytes);
    // let bytes:Vec<u8> = bincode::serialize(&message).unwrap();
   
    socket
        .send_to(&mut bytes, dns_server)
        .expect("couldn't send data");
    let mut buf = [0; 1024];
    match socket.recv(&mut buf) {
        Ok(received) => println!("received {} bytes {:?}", received, &buf[..received]),
        Err(e) => println!("recv function failed: {:?}", e),
    }
}

fn build_message(cname: String) -> DNSMessage {
    // 0 0000 0 0 0 0 0000
    let id: u16 = 0b0000000000000001;
    let codes: u16 = 0b0000000100000000;
    let qdcount: u16 = 0b0000000000000001;
    let ancount: u16 = 0b0000000000000000;
    let nscount: u16 = 0b0000000000000000;
    let arcount: u16 = 0b0000000000000000;

    let header = HeaderSection {
        id: id,
        codes: codes,
        qdcount: qdcount,
        ancount: ancount,
        nscount: nscount,
        arcount: arcount,
    };

    let header_bytes = bincode::serialize(&header).unwrap();
    let labels = transform_cname(cname);
    println!("{}", labels);
    // let question_bytes = transform_to_bytes(labels)
    let one_flag: u16 = 0x0001;
    let mut cname_bytes = bincode::serialize(&labels).unwrap();
    let mut qtype_bytes = bincode::serialize(&one_flag).unwrap();
    let mut qclass_bytes = bincode::serialize(&one_flag).unwrap();

    let mut questions_bytes = vec![0; cname_bytes.len() + 4];

    questions_bytes.append(&mut cname_bytes);
    questions_bytes.append(&mut qtype_bytes);
    questions_bytes.append(&mut qclass_bytes);

    // let mut message: Vec<u8> = vec![0; header_bytes.len() + questions_bytes.len()];
    // message.append(&mut header_bytes);
    // message.append(&mut questions_bytes);

    let message = DNSMessage {
        header: header_bytes,
        payload: questions_bytes,
        answers_pr: 0,
        authority_rr: 0,
        additional_pr: 0,
    };

    message
}

fn transform_cname(cname: String) -> String {
    let split = cname.split(".");
    let mut labels: String = "".to_owned();
    for s in split {
        labels.push_str(&s.len().to_string());
        labels.push_str(&s);
    }
    labels.push_str(&String::from("0"));
    labels
}
