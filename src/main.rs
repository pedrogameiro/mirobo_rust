#[macro_use]
extern crate clap;
#[macro_use]
extern crate serde;
extern crate serde_json;
extern crate bincode;
extern crate hex;
extern crate crypto;
extern crate rand;

use clap::App;
use std::net::UdpSocket;
use std::borrow::Borrow;
use miio::header::MiioHeader;
use serde::{Deserialize, Serialize};
use rand::Rng;

mod miio;

struct Device {
    stamp: u32,
    did: u32,
    token: Vec<u8>,
    coder: bincode::Config,
    socket: UdpSocket,
}

impl Device {

    fn find (token: &str, ip: &str, port: &str) -> std::result::Result<Device, String> {
        let token = hex::decode(token).unwrap();
        let url = format!("{}:{}", ip, port);
        let bind_addr = "0.0.0.0:0";

        let socket = UdpSocket::bind(bind_addr).unwrap();
        socket.set_write_timeout(Some(std::time::Duration::new(5, 0))).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::new(5, 0))).unwrap();

        let coder = {
            let mut b = bincode::config();
            b.big_endian();
            b
        };

        let encoded= coder.serialize(&MiioHeader::hello()).unwrap();

        socket.connect(url).unwrap();
        socket.send(encoded.borrow()).unwrap();

        let mut msg_buffer= [0u8; 32];
        let size = socket.recv(&mut msg_buffer).unwrap();

        if size != 32 {
            panic!("Received truncated message");
        }


        let header: MiioHeader = coder.deserialize(&msg_buffer).unwrap();

        Ok(Device {socket, coder, token, stamp: header.stamp, did: header.did})
    }

}

#[derive(Serialize, Deserialize)]
struct JsonPayload {
    id: u32,
    method: String,
    params: Vec<String>,
}

#[test]
fn aes_decrypt() {

    let token = "7349703062627746696e756b726d6675";
    let data = "213100600000000004f0c5ff00008663f1dd7f30a1a918f8b2076db412cf67e710585f8508d669ae32a440edfe19174fd5f3c0088b6dfc3b45b546a71b645db00233c92807b4589b8987ac8faf92d22ae0142045d0e8d7710193e94b2b323a2f";

    println!("token: {}", token);
    println!("data: {}", data);

    let token = &hex::decode(token).unwrap()[..];
    let example = &hex::decode(data).unwrap()[0x20..];

    let miio::protocol::AesKeys { key, iv } = miio::protocol::gen_aes_keys(token);
    println!("iv: {}", hex::encode(iv));
    println!("key: {}", hex::encode(key));

    let mut buffer = [0u8; 4096];
    let payload = miio::protocol::aes_decrypt(example, &mut buffer, &key, &iv);

    let payload = String::from_utf8(payload.to_vec()).unwrap();
    println!("decrypt: {}", &payload[.. payload.len() - 1]);

    let expected_result = String::from(r#"{"id": 9423, "method": "get_status", "params": []}"#) + "\0";
    assert_eq!(expected_result, payload);
}

#[test]
fn json_test() {

    let object = JsonPayload {id: 9423, method: String::from("get_status"), params: vec![]};
    let encoded = serde_json::to_string(&object).unwrap();
    assert!(r#"{"id":9423,"method":"get_status","params":[]}"# == encoded);

}

fn main() {

    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let addr = matches.value_of("ip").unwrap();
    let udp_port = matches.value_of("port").unwrap_or("54321");
    let token = matches.value_of("token").unwrap();
    let method = matches.value_of("method").unwrap();
    let token = matches.value_of("token").unwrap();

    let args;
    if let Some(values) = matches.values_of("arguments") {
        args = values.map(|s| s.to_owned()).collect();
    } else {
        args = vec![];
    }

    let mut rng = rand::thread_rng();
    let id = rng.gen();

    let status = JsonPayload {id: id, method: method.to_owned(), params: args};
    let status = serde_json::to_string(&status).unwrap();

    let mut dev = Device::find(token, addr, udp_port).unwrap();
    let miio::protocol::AesKeys { key, iv } = miio::protocol::gen_aes_keys(dev.token.borrow());

    let mut buffer = [0u8; 4096];
    let status_msg = miio::protocol::aes_encrypt(status.as_bytes(), &mut buffer, &key, &iv);

    let msg = {
        let mut msg : Vec<u8>;

        dev.stamp += 1;
        let header_msg = miio::header::MiioHeader::new(status_msg.len(), dev.did, dev.stamp,dev.token.borrow());
        msg = dev.coder.serialize(&header_msg).unwrap();
        msg.extend_from_slice(status_msg);

        let checksum = miio::protocol::md5sum(msg.borrow());
        let checksum_field = &mut msg[0x20 - 16 .. 0x20];
        checksum_field.copy_from_slice(&checksum);
        msg
    };

    dev.socket.send(msg.borrow()).expect("Unable to send message.");
    let len = dev.socket.recv(&mut buffer).unwrap();

    let header_msg = &buffer[..0x20];
    let header_msg : MiioHeader = dev.coder.deserialize(header_msg).unwrap();

    let mut decode_buffer = [0u8; 4096];
    let payload = &buffer[0x20..header_msg.length as usize];
    let recv_msg = miio::protocol::aes_decrypt(payload, &mut decode_buffer, &key, &iv);

    println!("{}", String::from_utf8(recv_msg.to_vec()).unwrap());

}
