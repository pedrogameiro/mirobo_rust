
use std::fmt;

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

        let md5 : [u8; 16] = {
            let mut hash = [0u8; 16];
            hash.copy_from_slice(checksum);
            hash
        };

        MiioHeader {
            magic: 0x2131,
            length: length as u16 + 0x20,
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
            &[0xffu8; 16]);

        hello.unknown = std::u32::MAX;
        hello
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

