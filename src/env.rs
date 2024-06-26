use libc::c_char;
use memchr::memchr;
use crate::types::*;
use pam_sys as raw;

use std::ffi::{CStr, OsString};

#[derive(Clone)]
pub struct PamEnvList {
    inner: Vec<(OsString, OsString)>
}

pub fn get_pam_env(handle: &mut PamHandle) -> Option<PamEnvList> {
    let env = unsafe {
        raw::pam_getenvlist(handle)
    };
    if !env.is_null() {
        Some(PamEnvList::from_ptr(env as *const *const c_char))
    } else {
        None
    }
}

impl PamEnvList {
    pub(crate) fn from_ptr(ptr: *const *const c_char) -> PamEnvList {
        let mut result = Vec::new();

        unsafe {
            let mut current = ptr;
            if !current.is_null() {
                while !(*current).is_null() {
                    if let Some(key_value) = parse_env_line(CStr::from_ptr(*current).to_bytes()) {
                        result.push(key_value);
                    }
                    current = current.add(1);
                }
            }
        }

        drop_env_list(ptr);
        return PamEnvList { inner: result };
    }

    pub fn to_vec(&self) -> Vec<(String, String)> {
	self.inner.clone().into_iter().map(|(a,b)| (a.into_string().unwrap(), b.into_string().unwrap())).collect()
    }
}


fn parse_env_line(input: &[u8]) -> Option<(OsString, OsString)> {
    // Strategy (copied from glibc): Variable name and value are separated
    // by an ASCII equals sign '='. Since a variable name must not be
    // empty, allow variable names starting with an equals sign. Skip all
    // malformed lines.
    use std::os::unix::prelude::OsStringExt;

    if input.is_empty() {
        return None;
    }
    let pos = memchr(b'=', input);
    pos.map(|p| {
        (
            OsStringExt::from_vec(input[..p].to_vec()),
            OsStringExt::from_vec(input[p + 1..].to_vec()),
        )
    })
}

#[cfg(target_os = "linux")]
fn drop_env_list(ptr: *const *const c_char) {
    unsafe { crate::ffi::pam_misc_drop_env(ptr as *mut *mut c_char) };
}

#[cfg(not(target_os = "linux"))]
fn drop_env_list(ptr: *const *const c_char) {
    // FIXME: verify this
    let mut cur = *ptr;
    while !ptr.is_null() {
        unsafe { free(ptr) };
        ptr = ptr.add(1);
    }
    unsafe { free(ptr) };
}
