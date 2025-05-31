mod tui;
mod key_operations;
mod network_operations;
mod key_exchange;
mod authentication;
mod encryption;

use tui::{MessagingApp, run_tui};
use key_operations::{key_operations_dilithium, key_operations_eddsa};
use network_operations::{
    create_client_with_proxy,
    fetch_kyber_pubkey,
    fetch_dilithium_pubkeys,
    fetch_eddsa_pubkeys,
    fetch_ciphertext,
    send_kyber_pubkey,
    send_dilithium_pubkey,
    send_eddsa_pubkey,
    send_ciphertext,
    send_encrypted_message,
    receive_and_fetch_messages,
};
use key_exchange::{kyber_key_exchange, perform_ecdh_key_exchange};
use authentication::{
    sign_data_with_dilithium,
    sign_data_with_eddsa,
    verify_signature_with_dilithium,
    verify_signature_with_eddsa,
};
use encryption::{
    derive_salt_from_password,
    derive_key,
    combine_shared_secrets,
    encrypt_data,
    decrypt_data,
};

use oqs::sig::{Sig, PublicKey, SecretKey, Algorithm as SigAlgorithm};
use rand::Rng;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use hex;
use std::io::{self, Write};
use std::result::Result;
use std::{
    collections::HashSet,
    error::Error,
};
use serde::{Deserialize, Serialize};
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use sha3::{Sha3_512, Digest};
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use rfd::MessageDialog;
use rfd::MessageButtons;
use rfd::MessageLevel;
use rfd::MessageDialogResult;
use rpassword::read_password;

#[cfg(unix)]

fn get_raw_bytes_public_key(pk: &PublicKey) -> &[u8] {
    pk.as_ref() 
}

fn get_raw_bytes_secret_key(sk: &SecretKey) -> &[u8] {
    sk.as_ref() 
}

#[derive(Serialize, Deserialize, Debug)] 
struct MessageData {
    message: String,
    room_id: String,
}

fn fingerprint_dilithium_public_key(public_key: &PublicKey) -> String {

    let raw_bytes = public_key.as_ref(); 
    let hashed = Sha3_512::digest(raw_bytes);
    hex::encode(hashed)
}

fn fingerprint_eddsa_public_key(public_key: &Ed25519PublicKey) -> String {

    let hashed = Sha3_512::digest(public_key);
    hex::encode(hashed)
}

fn request_user_confirmation(
    fingerprint: &str,
    own_fingerprint: &str,
    password: &str,
) -> Result<bool, io::Error> {
    if fingerprint == own_fingerprint {
        return Ok(true);
    }

    let path = "contact_fingerprints.enc";
    let trusted_fingerprints = load_trusted_fingerprints(path, password)?;

    if trusted_fingerprints.contains(fingerprint) {
        println!("Auto-trusting stored fingerprint: {}", fingerprint);
        return Ok(true);
    }

    let message = format!(
        "🔒 Fingerprint Verification\n\n\
         Your fingerprint:\n{}\n\n\
         Received fingerprint:\n{}\n\n\
         Do you want to trust the received fingerprint?",
        own_fingerprint, fingerprint
    );

    let confirm = MessageDialog::new()
        .set_title("Trust New Fingerprint")
        .set_level(MessageLevel::Info)
        .set_description(&message)
        .set_buttons(MessageButtons::YesNo)
        .show();

    if confirm == MessageDialogResult::Yes {
        let remember = MessageDialog::new()
            .set_title("Remember Fingerprint?")
            .set_level(MessageLevel::Info)
            .set_description(
                "💾 Would you like to remember this fingerprint for future sessions?\n\
                 This prevents asking again for the same contact."
            )
            .set_buttons(MessageButtons::YesNo)
            .show();

        if remember == MessageDialogResult::Yes {
            save_fingerprint(path, fingerprint, password)?;
        }

        Ok(true)
    } else {
        Ok(false)
    }
}

fn load_trusted_fingerprints<P: AsRef<Path>>(
    path: P,
    password: &str
) -> Result<HashSet<String>, io::Error> {
    let mut set = HashSet::new();

    if let Ok(file) = File::open(&path) {
        for line in BufReader::new(file).lines() {
            if let Ok(encrypted_line) = line {
                match decrypt_data(&encrypted_line, password) {
                    Ok(fingerprint) => {
                        set.insert(fingerprint);
                    }
                    Err(err) => {
                        eprintln!("Warning: Could not decrypt a line in fingerprint file: {}", err);
                    }
                }
            }
        }
    }

    Ok(set)
}

fn save_fingerprint<P: AsRef<Path>>(
    path: P,
    fingerprint: &str,
    password: &str
) -> Result<(), io::Error> {
    match encrypt_data(fingerprint, password) {
        Ok(encrypted) => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            writeln!(file, "{}", encrypted)?;
            Ok(())
        }
        Err(e) => {
            eprintln!("Encryption error: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, "Failed to encrypt fingerprint"))
        }
    }
}

fn generate_random_room_id() -> String {
    const ID_LENGTH: usize = 16;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let mut rng = OsRng;
    let mut room_id = String::with_capacity(ID_LENGTH);

    for _ in 0..ID_LENGTH {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        room_id.push(CHARSET[idx] as char);
    }

    room_id
}

fn pad_message(message: &str, max_length: usize) -> String {
    let current_length = message.len();

    if current_length < max_length {
        let padding_len = max_length - current_length;

        let mut rng = OsRng;  
        let padding: String = (0..padding_len)
            .map(|_| rng.gen_range(33..127) as u8 as char) 
            .collect();

        return format!("{}<padding>{}</padding>", message, padding);
    }

    message.to_string()  
}

#[derive(Clone, Debug, Default)]
pub struct AppState {
    choice: String,
    server_url: String,
    username: String,
    private_password: String,
    is_group_chat: bool,
    room_id_input: String,
    room_password: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut state = AppState::default();

    println!("=== Amnezichat TUI ===");
    println!("Choose an action: [1] Create Room  [2] Join Room");

    let choice = read_line("Enter choice (1 or 2): ");
    match choice.as_str() {
        "1" => {
            state.choice = "create".into();
            state.room_id_input = generate_random_room_id();
            println!("Generated Room ID: {}", state.room_id_input);
        }
        "2" => {
            state.choice = "join".into();
            state.room_id_input = read_line("Enter Room ID: ");
        }
        _ => {
            println!("Invalid choice");
            return Ok(());
        }
    }

    state.server_url = read_line("Server URL: ");
    state.username = read_line("Username: ");
    println!("Private Password: ");
    state.private_password = read_password().expect("Failed to read password");

    let group_chat_input = read_line("Is this a group chat? (y/n): ");
    state.is_group_chat = group_chat_input.trim().eq_ignore_ascii_case("y");

    if state.is_group_chat {
        state.room_password = read_line("Enter Room Password (min 8 chars): ");
    }

    if let Err(err) = validate_state(&state) {
        eprintln!("❗ Error: {}", err);
        return Ok(());
    }

    run_app_logic(state)?;
    Ok(())
}


fn read_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn validate_state(state: &AppState) -> Result<(), Box<dyn Error>> {
    if state.server_url.is_empty() || state.username.is_empty() || state.private_password.is_empty() {
        return Err("Please fill in all required fields.".into());
    }
    if state.is_group_chat && state.room_password.len() <= 8 {
        return Err("Room password must be longer than 8 characters.".into());
    }
    Ok(())
}

pub fn run_app_logic(state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let sigalg = Sig::new(SigAlgorithm::Dilithium5)?;

    let room_id = state.room_id_input.clone();
    let url = state.server_url.clone();
    let username = state.username.clone();
    let private_password = state.private_password.clone();

    let room_password = if state.is_group_chat {
        let salt = derive_salt_from_password(&state.room_password);
        let key = derive_key(&state.room_password, &salt);
        hex::encode(key)
    } else {
        String::new()
    };

    let hybrid_shared_secret = if state.is_group_chat {
        println!("Skipping key exchange. Using room password as shared secret.");
        room_password
    } else {
        let (dilithium_pk, dilithium_sk) =
            key_operations_dilithium(&sigalg, &username, &private_password)?;

        let (eddsa_sk, eddsa_pk) = key_operations_eddsa(&username, &private_password)?;

        send_dilithium_pubkey(&room_id, &hex::encode(&dilithium_pk), &url);
        send_eddsa_pubkey(&room_id, &hex::encode(&eddsa_pk), &url);

        let fingerprint_dilithium = fingerprint_dilithium_public_key(&dilithium_pk);
        println!("Own Dilithium5 fingerprint: {}", fingerprint_dilithium);

        let eddsa_pk_array: &[u8; 32] = eddsa_pk.as_slice().try_into().expect("Invalid Ed25519 public key length");
        let eddsa_public_key = Ed25519PublicKey::from_bytes(eddsa_pk_array)?;
        let fingerprint_eddsa = fingerprint_eddsa_public_key(&eddsa_public_key);
        println!("Own EdDSA fingerprint: {}", fingerprint_eddsa);

        let mut processed_fingerprints = std::collections::HashSet::from([
            fingerprint_dilithium.clone(),
            fingerprint_eddsa.clone(),
        ]);

        let mut all_other_dilithium_keys = Vec::new();
        while all_other_dilithium_keys.len() < 1 {
            println!("Waiting for Dilithium public key...");
            thread::sleep(Duration::from_secs(5));
            for encoded_pk in fetch_dilithium_pubkeys(&room_id, &url) {
                if let Ok(decoded_pk) = hex::decode(&encoded_pk) {
                    if let Some(public_key_ref) = sigalg.public_key_from_bytes(&decoded_pk) {
                        let public_key = public_key_ref.to_owned();
                        let fetched_fingerprint = fingerprint_dilithium_public_key(&public_key);
                        if processed_fingerprints.contains(&fetched_fingerprint) {
                            continue;
                        }
                        if request_user_confirmation(
                            &fetched_fingerprint,
                            &fingerprint_dilithium,
                            &private_password,
                        )? {
                            all_other_dilithium_keys.push(public_key);
                            processed_fingerprints.insert(fetched_fingerprint);
                        }
                    }
                }
            }
        }

        let mut eddsa_key = None;
        while eddsa_key.is_none() {
            println!("Waiting for EdDSA public key...");
            thread::sleep(Duration::from_secs(5));
            for encoded_pk in fetch_eddsa_pubkeys(&room_id, &url) {
                if let Ok(decoded_pk) = hex::decode(&encoded_pk) {
                    if decoded_pk.len() == 32 {
                        let pk_array: &[u8; 32] = decoded_pk.as_slice().try_into().expect("Invalid Ed25519 key length");
                        if let Ok(public_key) = Ed25519PublicKey::from_bytes(pk_array) {
                            let fetched_fingerprint = fingerprint_eddsa_public_key(&public_key);
                            if processed_fingerprints.contains(&fetched_fingerprint) {
                                continue;
                            }
                            if request_user_confirmation(
                                &fetched_fingerprint,
                                &fingerprint_eddsa,
                                &private_password,
                            )? {
                                eddsa_key = Some(public_key);
                                processed_fingerprints.insert(fetched_fingerprint);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let mut all_dilithium_pks = vec![dilithium_pk];
        all_dilithium_pks.extend(all_other_dilithium_keys);

        let kyber_shared_secret =
            kyber_key_exchange(&room_id, &all_dilithium_pks, &dilithium_sk, &url)?;

        let ecdh_shared_secret = perform_ecdh_key_exchange(
            &room_id,
            &eddsa_sk.to_bytes(),
            &eddsa_key.unwrap(),
            &url,
        )?;

        combine_shared_secrets(&kyber_shared_secret, &ecdh_shared_secret)?
    };

    println!("Hybrid shared secret established.");
    println!("You can now start messaging!");

    let shared_hybrid_secret = Arc::new(hybrid_shared_secret);
    let shared_room_id = Arc::new(Mutex::new(room_id.clone()));
    let shared_url = Arc::new(Mutex::new(url.clone()));

    let _random_data_thread = {
        let shared_room_id = Arc::clone(&shared_room_id);
        let shared_url = Arc::clone(&shared_url);
        let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);

        thread::spawn(move || loop {
            let mut random_data = vec![0u8; OsRng.next_u32() as usize % 2048 + 1];
            OsRng.fill_bytes(&mut random_data);

            let dummy_message = format!("[DUMMY_DATA]: {:?}", random_data);
            let padded_message = pad_message(&dummy_message, 2048);
            let encrypted = match encrypt_data(&padded_message, &shared_hybrid_secret) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error encrypting dummy message: {}", e);
                    continue;
                }
            };

            let room_id = shared_room_id.lock().unwrap();
            let url = shared_url.lock().unwrap();

            if let Err(e) = send_encrypted_message(&encrypted, &room_id, &url) {
                eprintln!("Error sending dummy message: {}", e);
            }

            thread::sleep(Duration::from_secs(OsRng.next_u32() as u64 % 120 + 1));
        })
    };

    let _fetch_thread = {
        let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);
        let shared_room_id = Arc::clone(&shared_room_id);
        let shared_url = Arc::clone(&shared_url);

        thread::spawn(move || loop {
            let room_id = shared_room_id.lock().unwrap().clone();
            let url = shared_url.lock().unwrap().clone();

            if let Err(e) =
                receive_and_fetch_messages(&room_id, &shared_hybrid_secret, &url, true)
            {
                eprintln!("Error fetching messages: {}", e);
            }

            thread::sleep(Duration::from_secs(10));
        })
    };

    let app = MessagingApp::new(username, shared_hybrid_secret, shared_room_id, shared_url);

    run_tui(app)?;

    Ok(())
}
