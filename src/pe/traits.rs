use super::{CoffHeader, DataDirectory, OptionalHeaderPe32, OptionalHeaderPe32Plus, SectionHeader};

pub trait PEHeader {
    fn coff_header(&self) -> &CoffHeader;
    fn optional_header_pe32(&self) -> Option<&OptionalHeaderPe32>;
    fn optional_header_pe32plus(&self) -> Option<&OptionalHeaderPe32Plus>;
    fn data_directories(&self) -> Option<&Vec<DataDirectory>>;
    fn section_headers(&self) -> &Vec<SectionHeader>;
}
