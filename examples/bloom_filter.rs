//! Bloom filter usage.
//!
//! Bloom filter is a probabilistic data structure that is used to check
//! whether the element definitely is not in set or may be in the set.
//!
//! Instead of a traditional hash-based set, that takes up too much memory,
//! this structure permits less memory with a tolerable false positive rate.
//!
//! This library does not provide explicit bloom filter reimplementation.
//! You can use specialized [`bloomfilter`](https://docs.rs/bloomfilter/latest/bloomfilter/)
//! crate instead.

use bloomfilter::Bloom;

fn bloom_filter_example() {
    // Create a filter with <0.01% probability of false positive for 10_000 elements
    let mut filter = Bloom::new_for_fp_rate(10_000, 1e-4);
    println!("Adding items...");
    for i in 1..=100u64 {
        filter.set(&i);
    }
    println!("Checking items presence...");
    for i in 1..=100u64 {
        assert!(filter.check(&i));
    }
    println!("All added items found!");
}

#[test]
fn test_run() {
    bloom_filter_example();
}

fn main() {
    bloom_filter_example();
}
