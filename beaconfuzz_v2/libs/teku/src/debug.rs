use std::fs::File;
use std::io::Write;

const PREFIX: &str = "teku";

pub fn dump_post_state(post: &[u8], out: &[u8]) {
    // Create dump file for lighthouse post
    // in case lighthouse return an error, this file will be the pre-state
    let mut file_post =
        File::create(&format!("{}_debug_post.ssz", PREFIX)).expect("Cannot open debug_post file");

    // write the content
    file_post
        .write(&post)
        .expect("Cannot write debug_post file");

    // Create dump file for other client post
    let mut file_out =
        File::create(&format!("{}_debug_out.ssz", PREFIX)).expect("Cannot open debug_out file");
    // write the content
    file_out.write(&out).expect("Cannot write debug_out file");
}
