use base_backend::files::{
    writer::default_writer::DefaultWriter,
    traits::write::Writer,
};

#[test]
fn write() {
    match DefaultWriter::write("tests/files/test_folder/read.test", "content".as_bytes()) {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    };
}
