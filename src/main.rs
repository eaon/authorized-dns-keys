#[macro_use]
extern crate structopt;
extern crate trust_dns_resolver;

use structopt::StructOpt;
use std::process;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::lookup::TxtLookup;

#[derive(StructOpt)]
#[structopt(name = "authorized-dns-keys", about = "Queries and prints SSH public keys from/to Hesiod-esque DNS TXT")]
struct Opt {
    #[structopt(parse(from_str))]
    username: String,
    #[structopt(long = "nsupdate")]
    nsupdate: bool,
    #[structopt(short = "c", long = "config", parse(from_os_str))]
    config: Option<PathBuf>,
    #[structopt(parse(from_os_str))]
    authkeysfile: Option<PathBuf>
}

struct HesiodConfig {
    lhs: String,
    rhs: String,
}

impl HesiodConfig {
    pub fn new(from_path: &Option<PathBuf>) -> HesiodConfig {
        let path = match from_path {
            Some(path) => {
                if ! path.as_path().exists() {
                    eprintln!("Hesiod config '{}' does not exist", path.display());
                    process::exit(1);
                }
                path.as_path()
            },
            None => Path::new("/etc/hesiod.conf")
        };
        let hc = match File::open(path) {
            Ok(f) => f,
            Err(error) => {
                eprintln!("Couldn't open '{}': {}\n", path.display(),  error);
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
                let value = line.clone()[4..].to_string();
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

fn print_pubkey_records(address: &str, path: &PathBuf) {
    let pk = match File::open(path) {
        Ok(f) => f,
        Err(error) => {
            eprintln!("Couldn't open '{}': {}\n", path.display(), error);
            process::exit(1);
        }
    };
    for line in BufReader::new(pk).lines().map(|l| l.unwrap()) {
        // TXT records can be 255 bytes long rather than 255 characters long
        // Make sure we don't mess that up
        let chars: Vec<_> = line.chars().map(|c| (c, c.len_utf8())).collect();
        print!("{}. TXT \"", address);
        let mut chunkl: usize = 0;
        for char in chars {
            print!("{}", char.0);
            chunkl += char.1;
            if chunkl == 255 {
                print!("\" \"");
                chunkl = 0;
            }
        }
        println!("\"");
    }
}

fn print_nsupdate_commands(address: &str, fp: &str) {
    println!("TODO ... {} / {}", address, fp);
}

fn main() {
    let opt = Opt::from_args();
    let config = HesiodConfig::new(&opt.config);
    let address = format!("{}.ssh{}", opt.username, config.domain());
    if opt.nsupdate {
        if opt.authkeysfile.is_none() {
            println!("<authkeysfile> needs to be supplied when using --nsupdate");
            process::exit(0);
        }
        print_nsupdate_commands(&address, &opt.username);
        process::exit(0);
    }
    if let Some(ref authkf) = opt.authkeysfile {
        print_pubkey_records(&address, &*authkf);
        process::exit(0);
    }
    let response = lookup(&address);

    for line in response.public_ssh_keys() {
        println!("{}", line);
    }
}
