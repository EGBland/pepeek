use std::env;
use std::fs::File;
use std::io; 
use std::mem::transmute;
use std::process;

pub mod pe;
use crate::pe::CoffHeader;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: pepeek <path to exe/dll>");
        process::exit(1);
    }

    let path = &args[1];
    let handle = File::open(path).expect("could not open file!!");
    let header = crate::pe::win::get_header(&handle).expect("could not get header address!!");
    println!("{}", path);
    println!(
        "Machine type: 0x{:04x} ({})",
        header.target_machine as u16, header.target_machine
    );
    println!(
        "Characteristics: 0x{:04x} ({:?})",
        header.characteristics.bits(),
        header.characteristics
    );
}
