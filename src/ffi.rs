use crate::crypto::{
    decrypt_v2, decrypt_v2_with_key, derive_v2_key_for_envelope, encrypt_v2,
    reencrypt_v2_with_key,
};
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use zeroize::Zeroize;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

#[repr(C)]
pub struct NvBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl NvBuffer {
    fn empty() -> Self {
        Self { data: ptr::null_mut(), len: 0 }
    }

    fn from_vec(mut value: Vec<u8>) -> Self {
        let result = Self { data: value.as_mut_ptr(), len: value.len() };
        std::mem::forget(value);
        result
    }
}

fn set_error(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(sanitized).ok();
    });
}

unsafe fn password_from_ptr(password: *const c_char) -> Result<String, &'static str> {
    if password.is_null() {
        return Err("A master password is required.");
    }
    CStr::from_ptr(password)
        .to_str()
        .map(str::to_owned)
        .map_err(|_| "The master password must be valid UTF-8.")
}

unsafe fn bytes_from_ptr<'a>(data: *const u8, len: usize) -> Result<&'a [u8], &'static str> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() && len != 0 {
        return Err("Input data is missing.");
    }
    Ok(std::slice::from_raw_parts(data, len))
}

#[no_mangle]
pub unsafe extern "C" fn nv_encrypt_json(password: *const c_char, json: *const u8, json_len: usize) -> NvBuffer {
    let password = match password_from_ptr(password) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };
    let json = match bytes_from_ptr(json, json_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };

    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    NvBuffer::from_vec(encrypt_v2(&password, json))
}

#[no_mangle]
pub unsafe extern "C" fn nv_decrypt_json(password: *const c_char, envelope: *const u8, envelope_len: usize) -> NvBuffer {
    let password = match password_from_ptr(password) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };
    let envelope = match bytes_from_ptr(envelope, envelope_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };

    match decrypt_v2(&password, envelope) {
        Ok(plaintext) => NvBuffer::from_vec(plaintext.as_slice().to_vec()),
        Err(error) => {
            set_error(error.to_string());
            NvBuffer::empty()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nv_derive_vault_key(
    password: *const c_char,
    envelope: *const u8,
    envelope_len: usize,
) -> NvBuffer {
    let password = match password_from_ptr(password) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };
    let envelope = match bytes_from_ptr(envelope, envelope_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };

    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    match derive_v2_key_for_envelope(&password, envelope) {
        Ok(key) => NvBuffer::from_vec(key.as_slice().to_vec()),
        Err(error) => {
            set_error(error.to_string());
            NvBuffer::empty()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nv_decrypt_json_with_key(
    key: *const u8,
    key_len: usize,
    envelope: *const u8,
    envelope_len: usize,
) -> NvBuffer {
    let key = match bytes_from_ptr(key, key_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };
    let envelope = match bytes_from_ptr(envelope, envelope_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };

    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    match decrypt_v2_with_key(key, envelope) {
        Ok(plaintext) => NvBuffer::from_vec(plaintext.as_slice().to_vec()),
        Err(error) => {
            set_error(error.to_string());
            NvBuffer::empty()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nv_reencrypt_json_with_key(
    key: *const u8,
    key_len: usize,
    existing_envelope: *const u8,
    existing_envelope_len: usize,
    json: *const u8,
    json_len: usize,
) -> NvBuffer {
    let key = match bytes_from_ptr(key, key_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };
    let existing_envelope = match bytes_from_ptr(existing_envelope, existing_envelope_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };
    let json = match bytes_from_ptr(json, json_len) {
        Ok(value) => value,
        Err(error) => {
            set_error(error);
            return NvBuffer::empty();
        }
    };

    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    match reencrypt_v2_with_key(key, existing_envelope, json) {
        Ok(envelope) => NvBuffer::from_vec(envelope),
        Err(error) => {
            set_error(error.to_string());
            NvBuffer::empty()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn nv_free_buffer(buffer: NvBuffer) {
    if !buffer.data.is_null() {
        std::slice::from_raw_parts_mut(buffer.data, buffer.len).zeroize();
        drop(Vec::from_raw_parts(buffer.data, buffer.len, buffer.len));
    }
}

#[no_mangle]
pub extern "C" fn nv_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ref().map_or(ptr::null(), |value| value.as_ptr()))
}
