use std::fs::File;
use std::io;
use std::io::Read;

/// Read the contents from file path
pub fn read_from_path(path_str: &String) -> Result<Vec<u8>, io::Error> {
    let mut buffer: Vec<u8> = Vec::new();
    let file_path = std::path::PathBuf::from(path_str);

    println!("file_to_process: {:?}", file_path);

    let mut file = File::open(file_path)?;
    file.read_to_end(&mut buffer)?;
    drop(file);
    Ok(buffer)
}
