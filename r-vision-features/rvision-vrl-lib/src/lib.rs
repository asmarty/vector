#![deny(clippy::all)]
// #![deny(unreachable_pub)]
#![deny(unused_allocation)]
#![deny(unused_extern_crates)]
#![deny(unused_assignments)]
#![deny(unused_comparisons)]

// mod util;

#[cfg(feature = "parse_cef")]
mod parse_cef;

pub fn all() -> Vec<Box<dyn vrl::prelude::Function>> {
    vec![
        #[cfg(feature = "parse_cef")]
        Box::new(parse_cef::ParseCef),
    ]
}
