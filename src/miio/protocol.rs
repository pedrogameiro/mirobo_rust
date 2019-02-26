
use crypto::{aes, md5, digest::Digest};
use crypto::buffer::{ ReadBuffer, WriteBuffer}; //, BufferResult };

pub fn md5sum(data: &[u8]) -> [u8; 16] {
    let mut md5_codec = md5::Md5::new();
    let mut output: [u8; 16] = [0; 16];

    md5_codec.input(data);
    md5_codec.result(&mut output);
    output
}

pub fn aes_encrypt<'a>(data: &[u8], out_buffer: &'a mut [u8], key: &[u8], iv: &[u8]) -> &'a mut [u8] {
    let mut aes_coder = aes::cbc_encryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        crypto::blockmodes::PkcsPadding);

    let len: usize;
    {
        let mut read_buffer = crypto::buffer::RefReadBuffer::new(data);
        let mut write_buffer = crypto::buffer::RefWriteBuffer::new(out_buffer);

        aes_coder.encrypt(&mut read_buffer, &mut write_buffer, true).expect("Unable to encrypt message.");

        len = write_buffer.position();
    }

    &mut out_buffer[..len]
}

pub fn aes_decrypt<'a>(data: &[u8], out_buffer: &'a mut [u8], key: &[u8], iv: &[u8]) -> &'a mut [u8] {
    let mut aes_decoder = aes::cbc_decryptor(
        aes::KeySize::KeySize128,
        &key,
        &iv,
        crypto::blockmodes::PkcsPadding);

    let len: usize;
    {
        let mut read_buffer = crypto::buffer::RefReadBuffer::new(data);
        let mut write_buffer = crypto::buffer::RefWriteBuffer::new(out_buffer);

        aes_decoder.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        len = write_buffer.position();
    }

    &mut out_buffer[..len]
}

pub struct AesKeys {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

pub fn gen_aes_keys(token: &[u8]) -> AesKeys {

    let mut md5_coder = md5::Md5::new();

    let mut key: [u8; 16] = [0; 16];
    let mut iv: [u8; 16] = [0; 16];

    md5_coder.input(&token);
    md5_coder.result(&mut key);

    md5_coder.reset();

    md5_coder.input(&key);
    md5_coder.input(&token);
    md5_coder.result(&mut iv);

    AesKeys {key: key, iv: iv}
}
