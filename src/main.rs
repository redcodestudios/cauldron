use std::env;
use std::net::UdpSocket;
use std::convert::TryInto;

// sizes in bytes
const HEADER_SECTION_SIZE: usize = 12;
const ID_SIZE: usize = 2;
const FLAGS_SIZE: usize = 2;
const QDCOUNT_SIZE: usize = 2;
const QTYPE_SIZE: usize = 2; 
const QCLASS_SIZE: usize = 2;
const NAME_SIZE: usize = 2;
const TYPE_SIZE: usize = 2;
const CLASS_SIZE: usize = 2;
const TTL_SIZE: usize = 4;
const DATA_LENGTH_SIZE: usize = 2;


fn main() {
    /* Program args should be like
       ./cauldron <cname> <dns_server>
       ./cauldron fga.unb.br 8.8.8.8
    */
    if env::args().len() != 3 {
        println!("Invalid arguments!");
    } else {
        if let Some(hostname) = env::args().nth(1) {
            if let Some(dns_server) = env::args().nth(2) {
                send_query(hostname, dns_server, 53);
            }
        }
    }
}


fn send_query(hostname: String, dns_ip:String, port:u16){
    let dns = format!("{}:{}", dns_ip, port);
    let query: Vec<u8> = build_query(hostname);

    let socket = UdpSocket::bind("0.0.0.0:34254").expect("couldn't bind to address");
    socket
        .send_to(&query, dns)
        .expect("couldn't send data");


    let mut buf = [0; 1024];
    match socket.recv(&mut buf) {
        Ok(received) => {
            let tmp_buff = &buf[..received];
                println!("{}", deserialize_dns_answer(tmp_buff.to_vec()))
        },
        Err(e) => println!("recv function failed: {:?}", e),
    }
}

fn build_query(cname: String) -> Vec<u8> {

    // Join all headers in a vector of bytes to be sent via UDP.
    let mut bytes = vec![];

    // ID for the dns transaction. arbitrarily set to 1.
    let id = vec![0x00, 0x01];
    bytes.append(&mut id.clone());

    // Combined flags on two bytes.
    // 16bits in order: 1 QR, 4 OPCode, 1 AA, 1 TC, 1 RD, 1 RA, 1 Z, 1 AD, 1 CD, 4 RCode
    // We have only recursion desired (RD) activated.
    let codes = vec![0x01, 0x00];
    bytes.append(&mut codes.clone());

    // Two bytes for query quantity, we do 1 query at a time only.
    let question_qtd = vec![0x00, 0x01];
    bytes.append(&mut question_qtd.clone());

    // NULL flags to be used in answers by the dns response.
    let answer_flags = vec![0x00,0x00];
    // Answer RRs count
    bytes.append(&mut answer_flags.clone());
    // Authority RRs count
    bytes.append(&mut answer_flags.clone());
    // Adicional RRs count
    bytes.append(&mut answer_flags.clone());

    // After all headers we need to insert the name being searched.
    let cname_bytes = transform_cname_for_query(cname);
    bytes.append(&mut cname_bytes.clone());
    
    // Type 1 for A query, looking for host address.
    let qtype = vec![0x00, 0x01];
    bytes.append(&mut qtype.clone());

    // Type 1 for Internet query.
    let qclass = vec![0x00, 0x01];
    bytes.append(&mut qclass.clone());

    return bytes;
}

fn transform_cname_for_query(cname: String) -> Vec<u8> {
    /* We should break the cname into labels and especify the length of each part
       ['www', 'google', 'com']
       should be a vector of bytes like:
       [3, 'www', 6, 'google', 3, 'com', 0]
    */
    let split = cname.split(".");
    
    let mut bytes = vec![];

    for s in split {        
        let size = s.len().try_into().unwrap();

        // push the size of the label. ex: 'www', size 3.
        bytes.push(size);

        // push the label: 'www'.
        bytes.append(&mut String::from(s.clone()).into_bytes());
    }

    // insert the terminator 0 to the converted cname.
    bytes.push(0x00);
    return bytes;
}

fn deserialize_dns_answer(bytes: Vec<u8>) -> String {
    let mut pos = ID_SIZE + FLAGS_SIZE + QDCOUNT_SIZE;
    let answers_count = bytes[pos] + bytes[pos+1];
   
    pos = HEADER_SECTION_SIZE;
    let mut b = bytes[pos]; 
    
    while b !=0 || pos < HEADER_SECTION_SIZE {
        pos+=1;
        b = bytes[pos];
    }
    pos += 1; //skip null cname terminator
    pos += QTYPE_SIZE + QCLASS_SIZE; //jump to answer section

    let mut result = String::from("");

    // DNS can have multiple answers for a query, we must find the ip
    for _ in 0..answers_count {
        pos += NAME_SIZE;
        let answer_type = bytes[pos] + bytes[pos+1];
        
        // 1 = type A
        if answer_type == 1 {
            pos += TYPE_SIZE + CLASS_SIZE + TTL_SIZE;
            
            let data_length: usize = (bytes[pos] + bytes[pos+1]).try_into().unwrap();
            pos += DATA_LENGTH_SIZE;
            
            let answer = (bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]);
            result.push_str(
                format!(
                    "{}.{}.{}.{}\n",
                    answer.0,
                    answer.1,
                    answer.2,
                    answer.3
                ).as_str()
            );
            pos += data_length;
        } else { 
            // just skip bytes
            pos += TYPE_SIZE + CLASS_SIZE + TTL_SIZE;
            let data_length: usize = (bytes[pos]+ bytes[pos+1]).try_into().unwrap();
            pos += DATA_LENGTH_SIZE + data_length;
        }
    }
    result
}

