fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}

pub struct Rng(u64);

impl Rng {
    /// Create a new random number generator
    pub fn new() -> Self {
        Rng(0x8644d6eb17b7ab1a) // ^ rdtsc())
    }

    /// Generate a random number
    #[inline]
    pub fn rand(&mut self) -> usize {
        let val = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        val as usize
    }
}
