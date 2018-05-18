extern crate trust_dns_resolver;

use std::env;
use std::process;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::lookup::TxtLookup;

const NAME: &'static str = env!("CARGO_PKG_NAME");
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

struct HesiodConfig {
    lhs: String,
    rhs: String,
}

impl HesiodConfig {
    pub fn new() -> HesiodConfig {
        let hc = match File::open("/etc/hesiod.conf") {
            Ok(f) => f,
            Err(error) => {
                eprintln!("Couldn't open /etc/hesiod.conf: {}\n", error);
                eprint!("Please make sure hesiod is installed and ");
                eprintln!("configured first");
                process::exit(1);
            }
        };
        let mut values = Vec::<String>::new();
        let mut lines = BufReader::new(hc);
        let mut line = String::new();
        while lines.read_line(&mut line).unwrap() > 0 {
            if line.len() > 4 && line.contains("hs=") {
                let ns = line.len() - 1;
                line.truncate(ns);
                let value = format!("{}", line)[4..].to_string();
                if line.starts_with("lhs=") {
                    values.insert(0, value);
                } else if line.starts_with("rhs=") {
                    values.push(value);
                } else {
                    line.clear();
                    continue;
                }
            }
            line.clear();
        }
        HesiodConfig { lhs: values.remove(0), rhs: values.remove(0) }
    }
    fn domain(&self) -> String {
        format!("{}{}", self.lhs, self.rhs)
    }
}

fn string_from_rdata(resp: &std::boxed::Box<[u8]>) -> String {
    match String::from_utf8(resp.to_vec()) {
        Ok(s) => s,
        Err(_e) => {
            eprintln!("Received an unexpected DNS response");
            process::exit(1)
        }
    }
}

fn lookup(address: &str) -> TxtLookup {
    let resolver = match Resolver::from_system_conf() {
        Ok(reso) => reso,
        Err(_e) => {
            eprintln!("Can't set up system resolver");
            process::exit(1)
        },
    };

    match resolver.txt_lookup(&address) {
        Ok(resp) => resp,
        Err(_e) => {
            // If we don't find any records, we don't care
            process::exit(0)
        },
    }
}

pub trait TxtLookupExt {
    fn public_ssh_keys(&self) -> Vec<String>;
}

impl TxtLookupExt for TxtLookup {
    fn public_ssh_keys(&self) -> Vec<String> {
        self.iter()
            .map(|r| r.txt_data()
                    .iter()
                    .map(|d| string_from_rdata(d))
                    .collect::<Vec<_>>()
                    .join(""))
            .collect()
    }
}

fn handle_args() -> (Vec<String>, Vec<String>) {
    // This function is me being lazy
    let args: Vec<_> = env::args().collect();
    let oargs: Vec<_> = args.iter()
                        .filter(|a| a.starts_with("-"))
                        .map(|a| a.trim_left_matches("-").to_string())
                        .collect();
    let fargs: Vec<_> = args.iter()
                       .enumerate()
                       .filter(|(i, a)| *i != 0 && !a.starts_with("-"))
                       .map(|(_i, a)| a.clone()).collect();
    if fargs.len() < 1 {
        eprintln!("No username supplied");
        print_help(1);
    } else if fargs.len() == 2 && !Path::new(&fargs[1]).exists() {
        eprintln!("Authorized Keys file does not exist");
        print_help(1);
    } else if fargs.len() > 2 {
        eprintln!("Too many arguments supplied");
        print_help(1);
    }
    if oargs.len() > 0 {
        if oargs[0].starts_with("h") {
            print_help(0);
        } else if oargs[0].contains("v") {
            println!("{} ({})", NAME, VERSION);
            process::exit(0);
        }
    }
    (fargs, oargs)
}

fn print_pubkey_records(address: &String, fp: &String) {
    let pk = match File::open(fp) {
        Ok(f) => f,
        Err(error) => {
            eprintln!("Couldn't open {}: {}\n", fp, error);
            process::exit(1);
        }
    };
    let mut lines = BufReader::new(pk);
    let mut line = String::new();
    while lines.read_line(&mut line).unwrap() > 0 {
        let ns = line.len() - 1;
        line.truncate(ns);
        let chars: Vec<char> = line.chars().collect();
        // XXX Should deal with bytes instead but also make sure utf-8 chars
        // aren't mangled
        let chunks: &Vec<_> = &chars.chunks(255)
                              .map(|c| c.iter().collect::<String>())
                              .collect();
        print!("{}. TXT ", address);
        for chunk in chunks {
            print!("\"{}\" ", chunk);
        }
        println!("");
        line.clear();
    }
}

fn print_nsupdate_commands(address: &String, fp: &String) {
    println!("TODO ... {} / {}", address, fp);
}

fn print_help(ec: i32) {
    if ec > 0 {
        eprintln!("");
    }
    println!("Usage: {} USERNAME [--nsupdate] [AUTHKEYSFILE]\n", NAME);
    println!("{}", NAME);
    println!("{}", "=".to_string().repeat(NAME.chars().count()));
    print!("Queries and prints SSH public keys from/to Hesiod-esque DNS TXT");
    println!(" records");
    process::exit(ec);
}

fn main() {
    let (args, opts) = handle_args();
    let username = &args[0];
    let config = HesiodConfig::new();
    let address = format!("{}.ssh{}", username, config.domain());
    if args.len() == 2 &&
       opts.len() < 1 {
        print_pubkey_records(&address, &args[1]);
        process::exit(0);
    } else if args.len() == 2 &&
              opts.len() == 1 &&
              opts[0].contains("nsupdate") {
        print_nsupdate_commands(&address, &args[1]);
        process::exit(0);
    }
    let response = lookup(&address);

    for line in response.public_ssh_keys() {
        println!("{}", line);
    }
}
