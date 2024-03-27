use std::env;
use std::fs::File;
use std::process;

pub mod pe;
use crate::pe::{CoffCharacteristics, CoffHeader};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: pepeek <path to exe/dll>");
        process::exit(1);
    }

    let path = &args[1];
    let handle = File::open(path).expect("could not open file!!");

    let from_file = crate::pe::win::get_headers_from_file(&handle).unwrap();
    let optional_pe32 = from_file.optional_header_pe32();
    let optional_pe32plus = from_file.optional_header_pe32plus();

    if let Some(opt) = optional_pe32 {
        println!("{:?}", opt);
    }

    if let Some(opt) = optional_pe32plus {
        println!("{:?}", opt);
    }

    if let Some(dirs) = from_file.data_directories() {
        for dir in dirs {
            println!("{:?}", dir);
        }
    }

    for header in from_file.section_headers() {
        let name = String::from_utf8_lossy(&header.name);
        println!("{}", name);
        println!("{:?}", header);
    }
}

#[allow(dead_code)]
fn print_info(header: &CoffHeader) {
    println!(
        "Machine type: {:?} ({}) (0x{:04x})",
        header.target_machine, header.target_machine, header.target_machine as u16
    );

    if header.characteristics.contains(CoffCharacteristics::Dll) {
        println!("DLL? yes");
    } else {
        println!("DLL? no");
    }
}
