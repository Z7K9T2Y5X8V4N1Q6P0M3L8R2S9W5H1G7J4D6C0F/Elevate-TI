//! Declarative helper macros for streamlined Win32 interaction.
//!
//! Provides lightweight macros that wrap raw Win32 calls and automatically
//! convert failures into [`crate::error::ElevateError::Win32`] with correct
//! operation labels, eliminating boilerplate `.map_err` expressions.

/// Invokes a Win32 expression returning a [`windows::core::Result`] and transforms
/// any encountered error into an [`crate::error::ElevateError::Win32`] with the stringified expression.
macro_rules! win32_call {
    ($function_name:ident ( $($arguments:tt)* )) => {
        unsafe { $function_name($($arguments)*) }.map_err(|source| $crate::error::ElevateError::Win32 {
            operation: stringify!($function_name),
            source,
        })
    };
}

pub(crate) use win32_call;
