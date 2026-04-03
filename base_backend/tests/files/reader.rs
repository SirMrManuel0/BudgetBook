use base_backend::files::{
    reader::deafault_reader::DefaultReader,
    traits::read::Reader,
};

#[test]
fn read() {
    match DefaultReader::read("tests/files/test_folder/read.test") {
        Ok(v) => {
            if v != "content".as_bytes() {
                panic!("The content of the file was not correctly written.");
            }
        },
        Err(e) => { panic!("{}", e.msg) }
    }
}
