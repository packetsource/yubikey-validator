#![allow(unused)]

use whoami;
use lazy_static::lazy_static;

const YUBIKEY_DATABASE_FILE: &str = "/etc/shadow.yk";

mod yubikey;
mod config;

lazy_static! {
    // Command line configuration
    pub static ref CONFIG: config::Config = config::Config::cmdline();
}


fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut key_store = yubikey::YubikeyStore::load(&CONFIG.filename)?;

    let mut otp = String::new();
    if CONFIG.args.len()==0 {
        std::io::stdin().read_line(&mut otp)?;
    } else {
        otp = CONFIG.args.get(0).unwrap().clone();
    }

    match key_store.validate_otp_for_user(&otp.trim(), &CONFIG.username)? {
        Some(otp) => println!("Parsed OTP: {:?}", otp),
        None => { println!("No match"); }
    }

    Ok(())
}