#![allow(unused)]

use libc::{c_char, c_int, c_void};
use std::ffi::CStr;
use std::ptr;

mod yubikey; use yubikey::*;

// PAM constants to return success/failure
const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_SERVICE_ERR: c_int = 9;

// Constants for use as item parameter
const PAM_SERVICE: c_int = 1;
const PAM_USER: c_int = 2;
const PAM_TTY: c_int = 3;
const PAM_RHOST: c_int = 4;
const PAM_CONV: c_int = 5;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_RUSER: c_int = 8;
const PAM_USER_PROMPT: c_int = 9;

const DEBUG: bool = false;  // debug/diagnostic output
const YUBIKEY_DATABASE_FILE: &str = "/etc/shadow.yk";

// PAM handle type (opaque to us)
type PamHandle = c_void;

// PAM API function signatures
#[link(name = "pam")]
extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_authtok(
        pamh: *mut PamHandle,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    // int pam_get_item(const pam_handle_t *pamh, int item_type,
    // const void **item);
    fn pam_get_item(pamh: *mut PamHandle, item_type: c_int, item: *mut *const c_char)
                    -> c_int;
}


#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    unsafe {

        // Get the username
        let mut username_ptr: *const c_char = ptr::null();
        let status = pam_get_user(pamh, &mut username_ptr, ptr::null());
        if status != PAM_SUCCESS || username_ptr.is_null() {
            eprintln!("Failed to get username");
            return PAM_SERVICE_ERR;
        }
        let username_cstr = CStr::from_ptr(username_ptr);
        let username = match username_cstr.to_str() {
            Ok(s) => s,
            Err(_) => {
                eprintln!("Invalid username encoding");
                return PAM_AUTH_ERR;
            }
        };

        // Get password
        let prompt: &CStr = c"Yubikey OTP: ";
        let mut password_ptr: *const c_char = ptr::null();
        let status = pam_get_authtok(pamh, PAM_AUTHTOK, &mut password_ptr, CStr::as_ptr(prompt));
        if status != PAM_SUCCESS || password_ptr.is_null() {
            eprintln!("Failed to get password");
            return PAM_SERVICE_ERR;
        }
        let password_cstr = CStr::from_ptr(password_ptr);
        let password = match password_cstr.to_str() {
            Ok(s) => s,
            Err(_) => {
                eprintln!("Invalid password encoding");
                return PAM_AUTH_ERR;
            }
        };

        // Custom validation logic
        match validate_credentials(username, password) {
            true => {
                if DEBUG {
                    eprintln!("Authentication succeeded for {}", username);
                }
                PAM_SUCCESS
            }
            false => {
                if DEBUG {
                    eprintln!("Authentication failed for {}", username);
                }
                PAM_AUTH_ERR
            }
        }
    }
}

// Apparently required for PAM service modules, but we don't implement
// credential setting
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

// Custom validation logic
pub fn validate_credentials(username: &str, password: &str) -> bool {
    if DEBUG {
        eprintln!("Validating Yubikey login for: username={}, password={}", username, password);
    }
    let mut key_store = match YubikeyStore::load(YUBIKEY_DATABASE_FILE) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Cannot open Yubikey datastore: {}", &e);
            return false;
        }
    };
    match key_store.validate_otp_for_user(password, username) {
        Ok(Some(otp)) => {
            if DEBUG {
                eprintln!("Authenticated OTP successfully: {:?}", otp)
            }
            true
        },
        Ok(None) => {
            if DEBUG {
                eprintln!("Unable to validate OTP");
            }
            false
        }
        Err(e) => {
            eprintln!("{}", &e);
            false
        }
    }
}