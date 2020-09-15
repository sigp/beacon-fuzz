extern "C" {
    pub fn hello();
}

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
