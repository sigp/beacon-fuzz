use std::env;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// TODO do we want any more wrapped bindings here, so the unsafe stuff is done here?

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_it() {
        unsafe {
            hello();
        }
    }

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
