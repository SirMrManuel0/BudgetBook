use base_backend::files::{
    deleter::default_deleter::DefaultDeleter,
    traits::deleter::Deleter,
    errors::files_error::FilesErrorKind,
};

#[test]
fn delete_file() {
    match DefaultDeleter::delete_file("tests/files/test_folder/test.file") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    }

    match DefaultDeleter::delete_file("tests/files/test_folder/test.file") {
        Ok(_) => { panic!("This should not have been valid. The file should already be deleted."); },
        Err(e) => match e.kind {
            FilesErrorKind::FileNotFound => {},
            _ => { panic!("{}", e.msg); }
        }
    }
}

#[test]
fn delete_folder() {
    match DefaultDeleter::delete_folder("tests/files/test_folder/folder1/folder2/folder3/") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg) }
    }

    match DefaultDeleter::delete_folder("tests/files/test_folder/folder1/folder2/folder3/") {
        Ok(_) => { panic!("This should not have been valid. The folder should already be deleted."); },
        Err(e) => match e.kind {
            FilesErrorKind::FolderNotFound => {},
            _ => { panic!("{}", e.msg); }
        }
    }
}

#[test]
fn delete_folders_all() {
    match DefaultDeleter::delete_folders_all("tests/files/test_folder/folder1/") {
        Ok(_) => {},
        Err(_) => {}
    }

    match DefaultDeleter::delete_folders_all("tests/files/test_folder/folder1/") {
        Ok(_) => { panic!("This should not have been valid. The fodlers should already be deleted."); },
        Err(e) => match e.kind {
            FilesErrorKind::FolderNotFound => {},
            _ => { panic!("{}", e.msg); }
        }
    }
}
