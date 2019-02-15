
extern crate hex;
extern crate byteorder;
extern crate bincode;

use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::net::UdpSocket;
use std::default::Default;
use std::borrow::Borrow;
use std::fmt;
use bincode::{serialize, deserialize};

struct MiioHeader {
    magic: u16,
    length: u16,  // == packet_length + 0x20
    unknown: u32, // This value is always 0, except in the "Hello" packet, when it's 0xFFFFFFFF
    did: u32,     // Device ID
    stamp: u32,
    md5: u128
}

impl Default for MiioHeader {
    fn default() -> MiioHeader {
        MiioHeader {
            magic: 0x2131,
            length: 0x20,
            unknown: 0,
            did: 0,
            stamp: 0,
            md5: 0
        }
    }
}

impl fmt::Debug for MiioHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MiioHeader {{\n\
        magic: {:x},\n\
        length: {:x}\n\
        unknown: {:x}\n\
        did: {:x}\n\
        stamp: {:x}\n\
        md5: {:x}\n\
        }}",
           self.magic,
           self.length,
           self.unknown,
           self.did,
           self.stamp,
           self.md5
        )
    }
}

impl MiioHeader {

    fn serialize(self) -> Result<Vec<u8>, std::io::Error> {

        let mut buff = Vec::new();

        buff.write_u16::<BigEndian>(self.magic)?;
        buff.write_u16::<BigEndian>(self.length)?;
        buff.write_u32::<BigEndian>(self.unknown)?;
        buff.write_u32::<BigEndian>(self.did)?;
        buff.write_u32::<BigEndian>(self.stamp)?;
        buff.write_u128::<BigEndian>(self.md5)?;

        Ok(buff)
    }

    fn unserialize(buff: &[u8; 256]) -> Result<MiioHeader, std::io::Error> {

        let mut rdr = Cursor::new(buff.to_vec());

        Ok(MiioHeader {
            magic: rdr.read_u16::<BigEndian>()?,
            length: rdr.read_u16::<BigEndian>()?,
            unknown: rdr.read_u32::<BigEndian>()?,
            did: rdr.read_u32::<BigEndian>()?,
            stamp: rdr.read_u32::<BigEndian>()?,
            md5: rdr.read_u128::<BigEndian>()?
        })
    }


    fn hello() -> MiioHeader {
        MiioHeader {
            magic: 0x2131,
            length: 0x20,
            unknown: std::u32::MAX,
            did: std::u32::MAX,
            stamp: std::u32::MAX,
            md5: std::u128::MAX
        }
    }
}


//struct MiioHello {
//
//}

fn main() {

    //let socket = UdpSocket::bind("127.0.0.1:34254").expect("couldn't bind to address");
    let socket= UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.168.1.146:54321").unwrap();

    let hello = MiioHeader::hello();

    socket.send(hello.serialize().unwrap().borrow()).unwrap();

    let mut msg_buffer: [u8; 256] = [0; 256];
    socket.recv(&mut msg_buffer).unwrap();

    println!("{:?}", MiioHeader::unserialize(&msg_buffer).unwrap());
}
