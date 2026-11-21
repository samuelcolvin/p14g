//! Random bytes rarely parse, so this target starts from statements the policy accepts and splices in
//! fragments chosen by the input: forbidden names, quoting, and syntax pgsafe has no representation for.
#![no_main]

use fuzz::{FRAGMENTS, SEEDS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&seed, edits)) = data.split_first() else {
        return;
    };
    let mut sql = SEEDS[usize::from(seed) % SEEDS.len()].to_owned();
    // each edit is three bytes: where, what, and whether to insert or overwrite
    for &[position, choice, mode] in edits.as_chunks::<3>().0.iter().take(8) {
        let fragment = FRAGMENTS[usize::from(choice) % FRAGMENTS.len()];
        let mut at = usize::from(position) * sql.len() / 256;
        while !sql.is_char_boundary(at) {
            at -= 1;
        }
        if mode % 2 == 0 {
            sql.insert_str(at, fragment);
        } else {
            let mut end = (at + fragment.len()).min(sql.len());
            while !sql.is_char_boundary(end) {
                end += 1;
            }
            sql.replace_range(at..end, fragment);
        }
    }
    fuzz::check(&sql);
});
