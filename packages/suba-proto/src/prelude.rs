//! The `alloc` items the crate uses, re-exported so modules read the same with and without `std`.

#[allow(unused_imports)] // the macro is only used from tests and doc examples
pub(crate) use alloc::{
    borrow::Cow,
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
