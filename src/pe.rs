use std::fmt::Display;

use self::traits::PEHeader;

/// Error enums for the crate.
pub mod err;

/// PE header structs.
pub mod headers;

/// PE body structs.
pub mod body;

/// PE traits.
pub mod traits;

/// Windows-specific implementation for deserialisation.
#[cfg(windows)]
pub mod win;

/// UNIX-specific implementation for deserialisation.
#[cfg(unix)]
pub mod unix;
