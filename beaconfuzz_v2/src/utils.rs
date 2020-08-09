use std::fs::File;
use std::io;
use std::io::Read;

use walkdir::WalkDir;

/// Read the contents from file path
pub fn read_from_path(path_str: &String) -> Result<Vec<u8>, io::Error> {
    let mut buffer: Vec<u8> = Vec::new();
    let file_path = std::path::PathBuf::from(path_str);
    let mut file = File::open(file_path)?;
    file.read_to_end(&mut buffer)?;
    drop(file);
    Ok(buffer)
}

/// List files names in folder string
pub fn list_files_in_folder(path_str: &str) -> Result<Vec<String>, ()> {
    let mut list: Vec<String> = Vec::<String>::new();
    for entry in WalkDir::new(path_str).into_iter().filter_map(|e| e.ok()) {
        if entry.metadata().unwrap().is_file() {
            //println!("{}", entry.path().display());
            list.push(entry.path().display().to_string());
        }
    }
    Ok(list)
}
