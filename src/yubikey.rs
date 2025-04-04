use std::fs::File;
use std::io::{BufRead, BufReader};
use std::cmp::PartialEq;
use std::fs::OpenOptions;
use std::io::Write;

use hex::FromHex;
use aes::Aes128;
use aes::cipher::{Block, BlockDecrypt, KeyInit};
use file_lock::{FileLock, FileOptions};


use crate::*;

const STRICT_ANTI_REPLAY: bool = false; // Fail if we can't update the session counters

#[derive(Debug, PartialEq)]
pub struct YubikeyPrivateIdentity([u8; 6]);
impl YubikeyPrivateIdentity {
    fn from_str(hex_key: &str) -> Result<YubikeyPrivateIdentity, Box<dyn std::error::Error>> {
        let hex_key = hex_key.trim();
        let bytes = Vec::from_hex(hex_key)
            .map_err(|e| format!("Invalid hex string: {}", e))?;
        YubikeyPrivateIdentity::from_bytes(&bytes)
    }
    fn from_bytes(bytes: &[u8]) -> Result<YubikeyPrivateIdentity, Box<dyn std::error::Error>> {
        Ok(YubikeyPrivateIdentity(bytes.try_into()?))
    }
}
#[derive(Debug)]
pub struct YubikeyAesKey([u8; 16]);

impl YubikeyAesKey {
    fn from_str(hex_key: &str) -> Result<YubikeyAesKey, Box<dyn std::error::Error>> {
        let hex_key = hex_key.trim();
        let bytes = Vec::from_hex(hex_key)
            .map_err(|e| format!("Invalid hex string: {}", e))?;
        Ok(YubikeyAesKey((&bytes[..]).try_into()?))
    }
}

#[derive(Debug)]
pub struct Yubikey {
    local_username: String,
    public_id: String,
    private_id: YubikeyPrivateIdentity,
    encryption_key: YubikeyAesKey,
    last_usage_count: u16,
    last_session_count: u8,
}

#[derive(Debug)]
pub struct YubikeyStore {
    filename: String,
    lock: FileLock,
    keys: Vec<Yubikey>
}

impl YubikeyStore {
    pub fn load(filename: &str) -> Result<YubikeyStore, Box<dyn std::error::Error>> {
        let options = FileOptions::new().read(true).write(true);
        const BLOCK_UNTIL_AVAILABLE: bool = true;
        let lock = FileLock::lock(filename, BLOCK_UNTIL_AVAILABLE, options)?;
        let mut yubikey_store = YubikeyStore {
            filename: filename.to_string(),
            lock,
            keys: Vec::<Yubikey>::new()
        };
        yubikey_store.read()?;
        Ok(yubikey_store)
    }
    fn read(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let reader = BufReader::new(&self.lock.file);
        for line in reader.lines() {
            let line = line.unwrap_or(String::from(""));
            let tokens: Vec<&str> = line.
                split(":").
                collect::<Vec<&str>>();

            // TODO: If there is something botched in the shadow line format
            // we shouldn't bail here. We should log an error, and ignore the
            // entry.
            if tokens.len()>=4 {
                self.keys.push( Yubikey {
                    local_username: tokens[0].to_string(),
                    public_id: tokens[1].to_string(),
                    private_id: YubikeyPrivateIdentity::from_str(tokens[2])?,
                    encryption_key: YubikeyAesKey::from_str(tokens[3])?,
                    last_usage_count: tokens.get(4).unwrap_or(&"0").parse::<u16>()?,
                    last_session_count: tokens.get(5).unwrap_or(&"0").parse::<u8>()?
                });
            }
        }
        Ok(())
    }
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let filename: String = format!("{}.tmp.{}", self.filename, std::process::id());
        let mut file: File = OpenOptions::new().
            write(true).
            create(true).
            truncate(true).
            open(&filename)?;
        for yubikey in &self.keys {
            let _ = writeln!(file, "{}:{}:{}:{}:{}:{}",
                             yubikey.local_username,
                             yubikey.public_id,
                             hex::encode(&yubikey.private_id.0),
                             hex::encode(&yubikey.encryption_key.0),
                             yubikey.last_usage_count,
                             yubikey.last_session_count
            );
        }
        std::fs::rename(&filename, &self.filename)?;
        Ok(())
    }

    pub fn validate_otp_for_user(&mut self, otp: &str, username: &str) -> Result<Option<YubikeyOtp>, Box<dyn std::error::Error>> {

        // Trim white space here
        let otp = otp.trim();

        // Check length of OTP first of all
        if otp.len() != 44 {
            return Ok(None);
            // return Err("OTP must be 44 characters".into());
        }

        // Read the public key from the OTP
        let public_id = &otp[..12];

        // Look through the key store.
        // If the username matches and the public identity matches,
        // proceed to decrypt the protected content

        for candidate in &mut self.keys {
            if candidate.public_id == public_id && candidate.local_username == username {
                let bytes = match decrypt_bytes(demodhex(&otp[12..])?,
                                                &candidate.encryption_key) {
                    Ok(data) => data,
                    Err(e) => continue, // length error or CRC failure
                };

                // Build an OTP struct from the raw unencrypted bytes
                let otp = YubikeyOtp::from_bytes(public_id, &bytes[0..16])?;

                // Check the private ID matches what we expect
                if otp.private_id == candidate.private_id {

                    // If the OTP counter is greater than last time, or
                    // if the OTP counters are equal but the session count
                    // is greater than last time, update the counters, and
                    // authentication is successful -> OK

                    if otp.counter > candidate.last_usage_count ||
                        (otp.counter == candidate.last_usage_count &&
                            otp.session_counter > candidate.last_session_count) {
                            candidate.last_session_count = otp.session_counter;
                            candidate.last_usage_count = otp.counter;
                            if STRICT_ANTI_REPLAY {
                                self.save()?;           // fail if we can't write the session counters
                            } else {
                                let _ = self.save();    // tolerate failure to update counters
                            }
                            return Ok(Some(otp))
                    }

                }
            }
        }

        // Authentication did not succeed
        Ok(None)
    }

}

#[derive(Debug)]
pub struct YubikeyOtp {
    public_id: String,
    private_id: YubikeyPrivateIdentity,
    counter: u16,
    timestamp: [u8; 3],
    session_counter: u8,
    random: u16,
    crc: u16,
}

impl YubikeyOtp {
    pub fn from_bytes(public_id: &str, bytes: &[u8]) -> Result<YubikeyOtp, Box<dyn std::error::Error>> {
        Ok(YubikeyOtp {
            public_id: String::from(public_id),
            private_id: YubikeyPrivateIdentity::from_bytes(&bytes[0..6])?,
            counter: u16::from_le_bytes(bytes[6..8].try_into().unwrap_or([0u8; 2])),
            timestamp: bytes[8..11].try_into().unwrap(),
            session_counter: bytes[11],
            random: u16::from_le_bytes(bytes[12..14].try_into().unwrap_or([0u8; 2])),
            crc: u16::from_le_bytes(bytes[14..16].try_into().unwrap_or([0u8; 2]))
        })
    }
}

// Utility function to convert from modhex to vanilla hex
fn demodhex(modhex: &str) -> Result<Vec<u8>, String> {
    const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

    let mut result = Vec::new();

    for chunk in modhex.as_bytes().chunks(2) {
        if chunk.len() != 2 {
            return Err("Invalid modhex length".to_string());
        }

        let high = MODHEX.iter().position(|&x| x == chunk[0]).map(|x| x as u8)
            .ok_or("Invalid modhex character")?;
        let low = MODHEX.iter().position(|&x| x == chunk[1]).map(|x| x as u8)
            .ok_or("Invalid modhex character")?;

        result.push((high << 4) | low as u8);
    }

    Ok(result)
}

// Verify the Yubikey OTP structure CRC, which should evaluate to having
// a residual value of 0xf0b8
fn verify_crc(data: &[u8]) -> bool {
    let mut crc = 0xffff;

    for byte in data[..16].iter() {
        let mut tmp = crc ^ (*byte as u16);
        for _ in 0..8 {
            if tmp & 1 == 1 {
                tmp = (tmp >> 1) ^ 0x8408;
            } else {
                tmp >>= 1;
            }
        }
        crc = tmp;
    }

    crc == 0xf0b8
}

// Decrypt the fixed block of 16 bytes using the AES key,
// calling the CRC check before returning
pub fn decrypt_bytes(encrypted_bytes: Vec<u8>,
                     key: &YubikeyAesKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    if encrypted_bytes.len() != 16 {
        return Err("Encrypted data length != 16".into());
    }

    // Create AES-128-ECB cipher
    let cipher = Aes128::new(&(key.0).into());

    // Decrypt the single 16-byte block
    let mut bytes = encrypted_bytes.clone();
    cipher.decrypt_block(Block::<Aes128>::from_mut_slice(bytes.as_mut_slice()));

    if bytes.len() != 16 {
        return Err("Decrypted data length != 16".into());
    }

    if !verify_crc(&bytes) {
        return Err("CRC check failed".into());
    }
    Ok(bytes)
}