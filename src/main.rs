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
use std::process::exit;

mod miio;


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

    let object : JsonPayload<String> = JsonPayload {id: 9423, method: String::from("get_status"), params: vec!["".to_owned()]};
    let encoded = serde_json::to_string(&object).unwrap();
    assert!(r#"{"id":9423,"method":"get_status","params":[]}"# == encoded);

}

struct Device {
    stamp: u32,
    did: u32,
    token: Vec<u8>,
    coder: bincode::Config,
    socket: UdpSocket,
    key: [u8; 16],
    iv: [u8; 16],
}

impl Device {

    fn find (token: &str, ip: &str, port: &str) -> std::result::Result<Device, String> {
        let token = hex::decode(token).unwrap();
        let url = format!("{}:{}", ip, port);
        let bind_addr = "0.0.0.0:0";

        let socket = UdpSocket::bind(bind_addr).unwrap();
        socket.set_write_timeout(Some(std::time::Duration::new(3, 0))).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::new(3, 0))).unwrap();

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

        if !header.check_header() {
            return Err("Corrupt message received.".to_owned())
        }

        let miio::protocol::AesKeys { key, iv } = miio::protocol::gen_aes_keys(token.borrow());
        Ok(Device { socket, coder, token, stamp: header.stamp, did: header.did, key, iv})

    }

    fn send <T> (&mut self, payload : JsonPayload<T>) -> std::io::Result<usize>
        where T : Serialize {

        let mut buffer = [0u8; 4096];
        let payload = serde_json::to_string(&payload).unwrap();
        println!("{}", payload);
        let payload = miio::protocol::aes_encrypt(payload.as_bytes(), &mut buffer, &self.key, &self.iv);

        let msg = {
            let mut msg : Vec<u8>;

            self.stamp += 1;
            let header_msg = MiioHeader::new(payload.len(), self.did, self.stamp, self.token.borrow());
            msg = self.coder.serialize(&header_msg).unwrap();
            msg.extend_from_slice(payload);

            MiioHeader::insert_checksum(&mut msg);

            msg
        };

        self.socket.send(msg.borrow())
    }

    fn recv (&self) -> String {
        let mut recv_buffer = [0u8; 4096];
        let mut decode_buffer = [0u8; 4096];

        let len = self.socket.recv(&mut recv_buffer).unwrap();

        let header_msg = &recv_buffer[..0x20];
        let header_msg: MiioHeader = self.coder.deserialize(header_msg).unwrap();

        if !header_msg.check(&self.token, &recv_buffer[..len]) {
            panic!("Received broken message")
        }

        let payload = &recv_buffer[0x20..header_msg.length as usize];
        let payload = miio::protocol::aes_decrypt(payload, &mut decode_buffer, &self.key, &self.iv);

        String::from_utf8(payload.to_vec()).expect("Unable to decode received message")
    }

}

#[derive(Serialize, Deserialize, Debug)]
struct JsonPayload <T> {
    id: u32,
    method: String,
    params: Vec<T>,
}

enum JsonParams {
    Ints(Vec<i32>),
    Strings(Vec<String>),
}

fn parse_args () -> (String, String, String, String, JsonParams) {

    let yaml = load_yaml!("cli.yml");

    let app = App::from_yaml(yaml);
    let matches = app.get_matches();

    let addr = matches.value_of("ip");
    let udp_port = matches.value_of("port").unwrap_or("54321");
    let method = matches.value_of("method");
    let token = matches.value_of("token");

    if addr.is_none() || addr.is_none() || method.is_none() || token.is_none() {
        App::from_yaml(yaml).write_help(&mut std::io::stderr()).unwrap();
        println!();
        exit(0);
    }

    let mut params : JsonParams = JsonParams::Strings(vec![]);

    if let Some(values) = matches.values_of("arguments") {

        let values : Vec<&str> = values.collect();
        let is_int = values.get(0).unwrap().parse::<i32>().is_ok();

        if is_int {
            params = JsonParams::Ints(values.iter().map(|x| x.parse::<i32>().unwrap()).collect());
        } else {
            params = JsonParams::Strings(values.iter().map(|&s| String::from(s)).collect());
        }

    }

    (addr.unwrap().to_owned(), udp_port.to_owned(), method.unwrap().to_owned(), token.unwrap().to_owned(), params)

}

fn main() {

    let (addr, udp_port, method, token, params) = parse_args();

    let mut dev = Device::find(token.borrow(), addr.borrow(), udp_port.borrow()).unwrap();

    let id = rand::thread_rng().gen();

    match params {
        JsonParams::Ints(arg) => {
            let payload = JsonPayload {id, method: method.to_owned(), params: arg};
            dev.send(payload).expect("Unable to send message");
        }
        JsonParams::Strings(arg) => {
            let payload = JsonPayload {id, method: method.to_owned(), params: arg};
            dev.send(payload).expect("Unable to send message");
        }
    }

    let result = dev.recv();

    println!("{}", result);
}
