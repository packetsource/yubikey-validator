
use std::process;
use std::env;
const DEFAULT_FILENAME: &str = "shadow.yk";

#[derive(Debug)]
pub struct Config {
    pub verbose: bool, // -v
    pub filename: String,
    pub username: String,
    pub args: Vec<String>,
}

/* Chappell's lightweight getopt() for rust */
impl Default for Config {
    fn default() -> Config {
        Config {
            verbose: false,
            filename: String::from(DEFAULT_FILENAME),
            username: whoami::username(),
            args: vec![],
        }
    }
}
impl Config {
    pub fn usage() {
        eprintln!("Usage: yubikey-validator [-f shadow.yk] [-u username] [OTP]");
        eprintln!("       - attempts to validate username against a Yubikey OTP");
        eprintln!("         using secret data contained within shadow.yk file");
        eprintln!("         Note: shadow.yk must be writable to update counters and prevent replay!");
        eprintln!("");
        eprintln!("         Program a yubikey for a serial-number based public identity,");
        eprintln!("         random private identity, and random secret like this:");
        eprintln!("");
        eprintln!("         \"ykman otp yubiotp -S -g -G 1\"");
        eprintln!("");
        eprintln!("Example output from ykman:");
        eprintln!("  Using YubiKey serial as public ID: vvccccbcjkhj");
        eprintln!("  Using a randomly generated private ID: b3670f6e29e4");
        eprintln!("  Using a randomly generated secret key: 41539f79378b1ce36fd71057ce6c1d79");
        eprintln!("");
        eprintln!("Store this, colon-separated, in /etc/shadow.yk thus (no space indent):");
        eprintln!(" username:vvccccbcjkhj:b3670f6e29e4:41539f79378b1ce36fd71057ce6c1d79");
        eprintln!("");
        eprintln!("Please get your own key https://yubico.com/store, don't use mine :) -- Adam.");

        process::exit(1);
    }

    pub fn cmdline() -> Config {
        let mut config = Config::default();

        let mut args = env::args();
        let _ = args.next(); // blow off the first argument
        while let Some(a) = args.next() {
            config.args.push(match a.as_str() {
                "-v" => {
                    config.verbose = true;
                    continue;
                }
                "-f" => {
                    config.filename = args.next().expect("expected filename").to_string();
                    continue;
                },

                "-h" => {
                    Self::usage();
                    break;
                }
                "-?" => {
                    Self::usage();
                    break;
                },
                _ => a,
            });
        }

        config
    }
}
