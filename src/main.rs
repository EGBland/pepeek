use chrono::prelude::DateTime;
use chrono::Utc;
use pe::{traits::PEHeader, DataDirectory, OptionalHeaderPe32, OptionalHeaderPe32Plus, SectionHeader};
use std::env;
use std::fs::File;
use std::path::Path;
use std::process;
use std::time::{Duration, UNIX_EPOCH};

pub mod pe;
use crate::pe::{CoffCharacteristics, CoffHeader};

const DATA_DIRECTORY_DISPLAY_NAMES: [&str; 16] = [
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug",
    "Architecture",
    "Global Ptr",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "IAT",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved",
];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: pepeek <path to exe/dll>");
        process::exit(1);
    }

    let path = Path::new(&args[1]);
    let handle = File::open(path).expect("could not open file!!");

    let from_file = crate::pe::win::get_headers_from_file(&handle).unwrap();
    println!("{}", path.file_name().unwrap().to_str().unwrap());
    print_coff_info(&from_file);
    print_optional_info(&from_file);
    print_section_headers(&from_file.section_headers());
}

fn print_coff_info(full_header: &Box<dyn PEHeader>) {
    let coff_header = full_header.coff_header();

    println!("COFF Header:");
    println!("\tTime created: {}", format_time_created(coff_header));
    println!(
        "\tMachine type: {:?} ({}) (0x{:04x})",
        coff_header.target_machine, coff_header.target_machine, coff_header.target_machine as u16
    );
    println!("\tSections: {}", coff_header.number_of_sections);
    if coff_header.characteristics.contains(CoffCharacteristics::Dll) {
        println!("\tDLL? yes");
    } else {
        println!("\tDLL? no");
    }
    println!("\tOptional headers size: {}", coff_header.size_of_optional_header);
    println!("\tCharacteristics: {:?}", coff_header.characteristics);
}

fn print_optional_info(full_header: &Box<dyn PEHeader>) {
    if let Some(pe32_header) = full_header.optional_header_pe32() {
        print_optional_info_pe32(pe32_header);
        print_data_directories(&full_header.data_directories().unwrap());
    }

    if let Some(pe32plus_header) = full_header.optional_header_pe32plus() {
        print_optional_info_pe32plus(pe32plus_header);
        print_data_directories(&full_header.data_directories().unwrap());
    }
}

fn print_optional_info_pe32(header: &OptionalHeaderPe32) {
    let standard_fields = &header.standard_fields;
    let windows_fields = &header.windows_fields;
    println!("PE32 optional header:");

    println!("\tStandard fields:");
    println!(
        "\t\tLinker version:             {}.{}",
        standard_fields.major_linker_version, standard_fields.minor_linker_version
    );
    println!("\t\tBase of code:               {0} ({0:08X}h)", standard_fields.base_of_code);
    println!("\t\tSize of code:               {0} ({0:08X}h)", standard_fields.size_of_code);
    println!("\t\tBase of data:               {0} ({0:08X}h)", standard_fields.base_of_data);
    println!("\t\tSize of initialised data:   {0} ({0:08X}h)", standard_fields.size_of_initialised_data);
    println!("\t\tSize of uninitialised data: {0} ({0:08X}h)", standard_fields.size_of_uninitialised_data);
    println!("\t\tEntry point address:        {0} ({0:08X}h)", standard_fields.address_of_entry_point);

    println!("\tWindows fields:");
    println!("\t\tImage base:                 {0} ({0:08X}h)", windows_fields.image_base);
    println!("\t\tSection alignment:          {0} ({0:08X}h)", windows_fields.section_alignment);
    println!("\t\tFile alignment:             {0} ({0:08X}h)", windows_fields.file_alignment);
    println!(
        "\t\tOS version:                 {}.{}",
        windows_fields.major_operating_system_version, windows_fields.minor_operating_system_version
    );
    println!(
        "\t\tImage version:              {}.{}",
        windows_fields.major_image_version, windows_fields.minor_image_version
    );
    println!("\t\tSubsystem:                  {}", windows_fields.subsystem);
    println!(
        "\t\tSubsystem version:          {}.{}",
        windows_fields.major_subsystem_version, windows_fields.minor_subsystem_version
    );
    println!("\t\tSize of image:              {0} ({0:08X}h)", windows_fields.size_of_image);
    println!("\t\tSize of headers:            {0} ({0:08X}h)", windows_fields.size_of_headers);
    println!("\t\tSize of stack reserve:      {0} ({0:08X}h)", windows_fields.size_of_stack_reserve);
    println!("\t\tSize of stack commit:       {0} ({0:08X}h)", windows_fields.size_of_stack_commit);
    println!("\t\tSize of heap reserve:       {0} ({0:08X}h)", windows_fields.size_of_heap_reserve);
    println!("\t\tSize of heap commit:        {0} ({0:08X}h)", windows_fields.size_of_heap_commit);
    println!("\t\tNumber of data directories: {}", windows_fields.number_of_rva_and_sizes);
    println!("\t\tDLL characteristics:        {:?}", windows_fields.dll_characteristics);
}

fn print_optional_info_pe32plus(header: &OptionalHeaderPe32Plus) {
    let standard_fields = &header.standard_fields;
    let windows_fields = &header.windows_fields;
    println!("PE32+ optional header:");

    println!("\tStandard fields:");
    println!(
        "\t\tLinker version:             {}.{}",
        standard_fields.major_linker_version, standard_fields.minor_linker_version
    );
    println!("\t\tBase of code:               {0} ({0:08X}h)", standard_fields.base_of_code);
    println!("\t\tSize of code:               {0} ({0:08X}h)", standard_fields.size_of_code);
    println!("\t\tSize of initialised data:   {0} ({0:08X}h)", standard_fields.size_of_initialised_data);
    println!("\t\tSize of uninitialised data: {0} ({0:08X}h)", standard_fields.size_of_uninitialised_data);
    println!("\t\tEntry point address:        {0} ({0:08X}h)", standard_fields.address_of_entry_point);

    println!("\tWindows fields:");
    println!("\t\tImage base:                 {0} ({0:016X}h)", windows_fields.image_base);
    println!("\t\tSection alignment:          {0} ({0:08X}h)", windows_fields.section_alignment);
    println!("\t\tFile alignment:             {0} ({0:08X}h)", windows_fields.file_alignment);
    println!(
        "\t\tOS version:                 {}.{}",
        windows_fields.major_operating_system_version, windows_fields.minor_operating_system_version
    );
    println!(
        "\t\tImage version:              {}.{}",
        windows_fields.major_image_version, windows_fields.minor_image_version
    );
    println!("\t\tSubsystem:                  {}", windows_fields.subsystem);
    println!(
        "\t\tSubsystem version:          {}.{}",
        windows_fields.major_subsystem_version, windows_fields.minor_subsystem_version
    );
    println!("\t\tSize of image:              {0} ({0:08X}h)", windows_fields.size_of_image);
    println!("\t\tSize of headers:            {0} ({0:08X}h)", windows_fields.size_of_headers);
    println!("\t\tSize of stack reserve:      {0} ({0:016X}h)", windows_fields.size_of_stack_reserve);
    println!("\t\tSize of stack commit:       {0} ({0:016X}h)", windows_fields.size_of_stack_commit);
    println!("\t\tSize of heap reserve:       {0} ({0:016X}h)", windows_fields.size_of_heap_reserve);
    println!("\t\tSize of heap commit:        {0} ({0:016X}h)", windows_fields.size_of_heap_commit);
    println!("\t\tNumber of data directories: {}", windows_fields.number_of_rva_and_sizes);
    println!("\t\tDLL characteristics:        {:?}", windows_fields.dll_characteristics);
}

fn print_data_directories(dirs: &Vec<DataDirectory>) {
    println!("\tData directories:");
    for (i, dir) in dirs.iter().enumerate() {
        if i < 16 {
            println!("\t\tTable {}: {}", i, DATA_DIRECTORY_DISPLAY_NAMES[i]);
        } else {
            println!("\t\tTable {}", i);
        }
        println!("\t\t\tVirtual address: {0} ({0:08X}h)", dir.virtual_address);
        println!("\t\t\tSize:            {0} ({0:08X}h)", dir.size);
    }
}

fn print_section_headers(section_headers: &Vec<SectionHeader>) {
    println!("Section headers:");
    for (i, header) in section_headers.iter().enumerate() {
        let name_str = String::from_utf8_lossy(&header.name);
        println!("\tSection {}: {}", i, name_str);
        println!("\t\tVirtual size:           {0} ({0:08X}h)", header.virtual_size);
        println!("\t\tVirtual address:        {0} ({0:08X}h)", header.virtual_address);
        println!("\t\tSize of raw data:       {0} ({0:08X}h)", header.size_of_raw_data);
        println!("\t\tPointer to raw data:    {0} ({0:08X}h)", header.pointer_to_raw_data);
        println!("\t\tPointer to relocations: {0} ({0:08X}h)", header.pointer_to_relocations);
        println!("\t\tNumber of relocations:  {0} ({0:08X}h)", header.number_of_relocations);
        println!("\t\tFlags:                  {:?}", header.characteristics);
    }
}

fn format_time_created(header: &CoffHeader) -> String {
    let unix_time = UNIX_EPOCH + Duration::from_secs(header.time_date_stamp as u64);
    let datetime = DateTime::<Utc>::from(unix_time);
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}
