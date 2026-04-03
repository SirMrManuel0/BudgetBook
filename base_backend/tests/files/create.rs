use base_backend::files::{
    create::default_create::DefaultCreate,
    traits::create::{ Create, SafeCreate },
    errors::files_error::FilesErrorKind
};

#[test]
fn create_file() {
    match DefaultCreate::create_file("tests/files/test_folder/test.file") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    };

    match DefaultCreate::create_file(&"tests/files/test_folder/error/test.file") {
        Ok(_) => { panic!("This should not work, because the folder 'error' does not exist.") },
        Err(e) => match e.kind {
            FilesErrorKind::FileNotFound => {},
            _ => { panic!("{}", e.msg); }
        }
    };
}

#[test]
fn create_folder() {
    match DefaultCreate::create_folder("tests/files/test_folder/folder1/") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    }

    match DefaultCreate::create_folder("tests/files/test_folder/folder1/") {
        Ok(_) => { panic!("This should not have worked. The folder should already exist.") },
        Err(e) => match e.kind { 
            FilesErrorKind::FolderAlreadyExists => {},
            _ => { panic!("{}", e.msg); }
        }
    }
}

#[test]
fn create_folders_all() {
    match DefaultCreate::create_folders_all("tests/files/test_folder/folder1/folder2/folder3/") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    }
}

#[test]
fn safe_create_file() {
    match DefaultCreate::safe_create_file("tests/files/test_folder/test.file") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    };

    match DefaultCreate::safe_create_file("tests/files/test_folder/test.file") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    };
}

#[test]
fn safe_create_folder() {
    match DefaultCreate::safe_create_folder("tests/files/test_folder/folder1/") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    }

    match DefaultCreate::safe_create_folder("tests/files/test_folder/folder1/") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    }
}

#[test]
fn safe_create_folders_all() {
    match DefaultCreate::safe_create_folders_all("tests/files/test_folder/folder1/folder2/folder3/") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    }

    match DefaultCreate::safe_create_folders_all("tests/files/test_folder/folder1/folder2/folder3/") {
        Ok(_) => {},
        Err(e) => { panic!("{}", e.msg); }
    }
}
