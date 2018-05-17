extern crate trust_dns_resolver;

use std::env;
use std::process;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::collections::HashMap;
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
                println!("Couldn't open /etc/hesiod.conf: {}\n", error);
                println!("Please make sure hesiod is installed and configured first");
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
            println!("Received an unexpected DNS response");
            process::exit(1)
        }
    }
}

fn lookup(address: &str) -> TxtLookup {
    let resolver = match Resolver::from_system_conf() {
        Ok(reso) => reso,
        Err(_e) => {
            println!("Can't set up system resolver");
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

fn map_response(response: &TxtLookup) -> HashMap<i8, String> {
    let mut unordered = HashMap::new();
    for keypart in response.iter() {
        let order = string_from_rdata(&keypart.txt_data()[0]);
        let order_i = match order.parse::<i8>() {
            Ok(s) => s,
            Err(_e) => {
                println!("Priority field is not a valid 8 bit integer");
                process::exit(1)
            }
        };
        let record = string_from_rdata(&keypart.txt_data()[1]);
        unordered.insert(order_i, record);
    }
    unordered
}

fn handle_args() -> Vec<String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("No username supplied");
        print_help(1);
    } else if args.len() == 3 && !Path::new(&args[2]).exists() {
        println!("Authorized Keys file does not exist");
        print_help(1);
    } else if args.len() > 3 {
        println!("Too many arguments supplied");
        print_help(1);
    }
    // I'm lazy
    if args[1].starts_with("-") {
        if args[1].contains("-h") {
            print_help(0);
        } else if args[1].contains("-v") {
            println!("{} ({})", NAME, VERSION);
            process::exit(0);
        }
    }
    args
}

fn print_pubkey_records(address: &String, fp: &String) {
    let pk = match File::open(fp) {
        Ok(f) => f,
        Err(error) => {
            println!("Couldn't open {}: {}\n", fp, error);
            process::exit(1);
        }
    };
    let mut lines = BufReader::new(pk);
    let mut line = String::new();
    let mut counter = 0;
    while lines.read_line(&mut line).unwrap() > 0 {
        let ns = line.len() - 1;
        line.truncate(ns);
        let chars: Vec<char> = line.chars().collect();
        let split = &chars.chunks(255)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<_>>();
        for chunk in split {
            print!("{}. TXT \"{}\" ", address, counter);
            println!("\"{}\"", chunk);
            counter += 1;
        }
        line.clear();
        counter += 1;
    }
    process::exit(0);
}

fn print_help(ec: i32) {
    if ec > 0 {
        println!("");
    }
    println!("Usage: {} USERNAME [AUTHKEYSFILE]\n", NAME);
    println!("{}", NAME);
    println!("{}", String::from("=").repeat(NAME.chars().count()));
    println!("Queries and prints SSH public keys from/to Hesiod-esque DNS TXT records");
    process::exit(ec);
}

fn main() {
    let args = handle_args();
    let username = &args[1];
    let config = HesiodConfig::new();
    let address = format!("{}.ssh{}", username, config.domain());
    if args.len() > 2 {
       print_pubkey_records(&address, &args[2]);
    }
    let response = lookup(&address);

    let unordered = map_response(&response);
    for i in 0..unordered.len() {
        let ui = i as i8;
        let record = &unordered[&ui];
        print!("{}", record);
        if record.len() < 255 &&
           (!record.starts_with("ssh-") || record.contains(" ")) {
            print!("\n");
        }
    }
}
