
use std::fmt;
use crypto::{md5, digest::Digest};

const MIIO_MAGIC : u16 = 0x2131;
const MIIO_UNKNOWN : u32 = 0;
const HEADER_LENGTH : usize = 0x20;
const MD5_SIZE : usize = 16;

#[derive(Serialize, Deserialize, PartialEq)]
pub struct MiioHeader {
    pub magic: u16,
    pub length: u16,  // includes header
    pub unknown: u32, // This value is always 0, except in the "Hello" packet, when it's 0xFFFFFFFF
    pub did: u32,     // Device ID
    pub stamp: u32,
    pub md5: [u8; 16],
}

impl MiioHeader {

    pub fn new(length: usize, did: u32, stamp: u32, checksum: &[u8]) -> MiioHeader {

        let md5 : [u8; MD5_SIZE] = {
            let mut hash = [0u8; MD5_SIZE];
            hash.copy_from_slice(checksum);
            hash
        };

        MiioHeader {
            magic: MIIO_MAGIC,
            length: (length + HEADER_LENGTH) as u16,
            unknown: 0,
            did,
            stamp,
            md5,
        }
    }

    pub fn hello() -> MiioHeader {

        let mut hello = MiioHeader::new(
            0,
            std::u32::MAX,
            std::u32::MAX,
            &[0xffu8; MD5_SIZE]);

        hello.unknown = std::u32::MAX;
        hello
    }

    pub fn check_header(&self) -> bool{

        let magic = self.magic == MIIO_MAGIC;
        let unknown = self.unknown == MIIO_UNKNOWN;
        let length = self.length >= HEADER_LENGTH as u16;

        magic && unknown && length
    }

    pub fn check(&self, token : &[u8], buffer : &[u8]) -> bool {

        let sh_out : [u8; MD5_SIZE] = {
            let mut sh_out = [0u8; MD5_SIZE];
            let mut sh = md5::Md5::new();

            sh.input(&buffer[..HEADER_LENGTH - MD5_SIZE]);      // header except checksum
            sh.input(token);                                    // token instead of checksum
            sh.input(&buffer[HEADER_LENGTH .. self.length as usize]);      // remainder of message

            sh.result(&mut sh_out);
            sh_out
        };

        let checksum = self.md5 == sh_out;

        self.check_header() && checksum
    }

    pub fn insert_checksum(msg : &mut [u8]) {

        let mut sh = md5::Md5::new();
        let mut checksum = [0u8; MD5_SIZE];

        sh.input(&msg);
        sh.result(&mut checksum);

        let checksum_field = &mut msg[0x20 - 16 .. 0x20];
        checksum_field.copy_from_slice(&checksum);
    }
}

impl fmt::Debug for MiioHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\
        MiioHeader {{\n\
            magic: {:x},\n\
            length: {:x}\n\
            unknown: {:x}\n\
            did: {:x}\n\
            stamp: {:x}\n\
            md5: {:x?}\n\
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

