// Copyright notice at end of file.

//! Utility for importing and exporting Threema backups.
//! 
//! r3ma_backup provides functions for decrypting and encrypting Threema backups.
//! For more information on the used procedure take a look at page 6 in this [pdf](https://threema.ch/press-files/cryptography_whitepaper.pdf).

use data_encoding::BASE32;
use pbkdf2::pbkdf2;
use rand::prelude::*;
use salsa20::{
    stream_cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher},
    XSalsa20,
};
use sha2::{Digest, Sha256};
use std::{fs::File, io::prelude::*, path::Path};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// A simple structure containing an 8 byte utf-8 Threema id and a 32 byte secret_key.
#[derive(Debug)]
pub struct ThreemaBackup {
    pub threema_id: [u8; 8],
    pub secret_key: [u8; 32],
}

/// Imports a threema backup string with a given password.
///
/// This uses the reverse process explained in this [pdf](https://threema.ch/press-files/cryptography_whitepaper.pdf)
/// to import a threema backup. This can be used to obtain your secret key.
/// 
/// # Example
/// ```
///  let backup = "5Z6N-JH5D-2PEK-L2Y3-Q3NY-R7KB-YNDT-HYHB-7HPB-T7NO-DJV3-CMGE-O5EO-NEG7-OJ2W-XSEJ-URDM-MHJ4-JFAN-2VCO";
///  let secret_key = import(&backup.to_string(), "password").unwrap().secret_key;
/// ```
pub fn import(backup: &String, password: &str) -> Result<ThreemaBackup, &'static str> {
    let backup_trimmed = backup.replace('-', "");
    if let Ok(backup_decoded) = BASE32.decode(backup_trimmed.as_bytes()) {
        let salt = &backup_decoded[..8];
        let mut key: [u8; 32] = [0; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, 100000, &mut key);
        let mut cipher = XSalsa20::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&[0u8; 24]),
        );
        let mut ciphertext = Vec::from(&backup_decoded[8..]);
        cipher.apply_keystream(ciphertext.as_mut_slice());
        let mut hasher = Sha256::new();
        hasher.input(&ciphertext[0..40]);
        if &ciphertext[40..42] == &hasher.result()[..2] {
            let mut threema_id = [0u8; 8];
            threema_id.copy_from_slice(&ciphertext[..8]);
            let mut secret_key = [0u8; 32];
            secret_key.copy_from_slice(&ciphertext[8..40]);
            Ok(ThreemaBackup {
                threema_id,
                secret_key,
            })
        } else {
            Err("Checksum incorrect.")
        }
    } else {
        Err("Backup invalid.")
    }
}

/// Exports a threema backup string with a given password.
///
/// This uses the process explained in this [pdf](https://threema.ch/press-files/cryptography_whitepaper.pdf)
/// to export a threema backup. This can be used to safely store your secret key together with
/// your Threema identity.
/// 
/// # Example
/// ```
///  let backup = export(&[0; 8], &[0; 32], "password").unwrap();
/// ```
pub fn export(
    threema_id: &[u8],
    secret_key: &[u8],
    password: &str,
) -> Result<String, &'static str> {
    if threema_id.len() >= 8 && secret_key.len() >= 32 {
        let mut backup = [0u8; 42];
        &backup[..8].copy_from_slice(&threema_id[..8]);
        &backup[8..40].copy_from_slice(&secret_key[..32]);
        let mut hasher = Sha256::new();
        hasher.input(&backup[..40]);
        &backup[40..].copy_from_slice(&hasher.result()[..2]);
        let mut salt = [0u8; 8];
        thread_rng().fill_bytes(&mut salt);
        let mut key: [u8; 32] = [0; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, 100000, &mut key);
        let mut cipher = XSalsa20::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&[0u8; 24]),
        );
        cipher.apply_keystream(&mut backup);
        let mut cipher_bytes = [0u8; 50];
        &cipher_bytes[..8].copy_from_slice(&salt);
        &cipher_bytes[8..].copy_from_slice(&backup);
        let mut backup_result = BASE32.encode(&cipher_bytes);
        backup_result.reserve(19);
        for i in 0..19 {
            backup_result.insert(4 + i * 5, '-');
        }
        Ok(backup_result)
    } else {
        Err("Either ID or secret key too short.")
    }
}

/// Imports a threema backup with a given password from a file.
///
/// See [import](fn.import.html) for more info on the procedure.
pub fn import_from_file(path: &Path, password: &str) -> Result<ThreemaBackup, &'static str> {
    match File::open(path) {
        Ok(mut file) => {
            let mut backup = [0u8; 99];
            if let Err(_) = file.read_exact(&mut backup) {
                Err("Could not read file.")
            } else {
                match std::str::from_utf8(&backup) {
                    Ok(backup_string) => import(&backup_string.to_string(), &password),
                    _ => Err("Could not decode file."),
                }
            }
        }
        Err(_) => Err("Could not open file."),
    }
}

/// Exports a threema backup string with a given password to a file.
///
/// See [export](fn.export.html) for more info on the procedure.
pub fn export_to_file(
    path: &Path,
    threema_id: &[u8],
    secret_key: &[u8],
    password: &str,
) -> Result<(), &'static str> {
    match File::create(path) {
        Ok(mut file) => match export(threema_id, secret_key, password) {
            Ok(backup) => {
                if let Err(_) = file.write(&backup.as_bytes()) {
                    Err("Could not write to file.")
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(e),
        },
        _ => Err("Could not create/open file."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_export() {
        let backup = export(&[0; 8], &[0; 32], "password").unwrap();
        let reimport = import(&backup, "password").unwrap();
        assert_eq!(reimport.threema_id, [0u8; 8]);
        assert_eq!(reimport.secret_key, [0u8; 32]);
    }

    #[test]
    fn test_import_export_file() {
        let path = Path::new("./tmp.txt");
        export_to_file(path, &[0; 8], &[0; 32], "password").expect("Export failed");
        let backup = import_from_file(path, "password").expect("Import failed");
        assert_eq!(backup.threema_id, [0u8; 8]);
        assert_eq!(backup.secret_key, [0u8; 32]);
        std::fs::remove_file(path).expect("Could not remove temporary file tmp.txt");
    }
}

// Copyright 2020 Lars Pieschel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.