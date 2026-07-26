use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use crate::cli::{confirm, hex_bytes};
use crate::crypto::{
    bruteforce_data_save, crack_index_save, detect_steam_id_from_index_path,
    resolve_steam_id, xor_with_key, zlib_compress, zlib_decompress, VALID_FLG,
};
use crate::utils::{backup_folder, build_out_path, collect_save_folders};

pub fn cmd_decrypt_folder(folder: &Path, steam_id: Option<u64>) {
    let folders = collect_save_folders(folder);
    if folders.is_empty() {
        println!("[warn] no save containers found under {}", folder.display());
        return;
    }
    let mut processed = 0usize;
    for save_dir in &folders {
        println!("\nSave container: {}", save_dir.display());
        let index_path = save_dir.join("index.save");
        let data_path  = save_dir.join("data.save");
        let sid = resolve_steam_id(steam_id, &index_path, None, false);
        if let Some(sid) = sid {
            if index_path.exists() { decrypt_index(&index_path, sid); }
            if data_path.exists()  { decrypt_data(&data_path, sid); }
            processed += 1;
        } else {
            eprintln!(
                "  [ERROR] Could not determine SteamID64 for {}. Use --steam-id.",
                save_dir.display()
            );
        }
    }
    println!("------------------------------------------------");
    println!("Decryption completed. Processed {processed} save containers.");
}

pub fn cmd_decrypt_file(path: &Path, steam_id: Option<u64>) {
    let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
    let dir  = path.parent().unwrap_or(Path::new("."));

    let sid = if name.contains("index") {
        resolve_steam_id(steam_id, path, None, false)
    } else {
        resolve_steam_id(steam_id, &dir.join("index.save"), None, false)
    };

    let Some(sid) = sid else {
        eprintln!("[ERROR] Could not determine SteamID64. Use --steam-id.");
        std::process::exit(1);
    };

    if name.contains("index") {
        decrypt_index(path, sid);
    } else {
        decrypt_data(path, sid);
    }
}

fn decrypt_index(path: &Path, steam_id: u64) {
    println!("  Processing index.save:");
    let ciphertext = fs::read(path).expect("cannot read index.save");
    let plaintext  = xor_with_key(&ciphertext, steam_id);
    if plaintext.windows(15).any(|w| w == b"SSaveGameHeader") {
        println!("    [OK] Header structure verified: found 'SSaveGameHeader'");
    }
    let out = build_out_path(path, ".decrypted");
    fs::write(&out, &plaintext).expect("cannot write decrypted index");
    println!("    [SUCCESS] Dumped decrypted index raw payload -> {}", out.file_name().unwrap().to_string_lossy());
}

fn decrypt_data(path: &Path, steam_id: u64) {
    println!("  Processing data.save:");
    let ciphertext = fs::read(path).expect("cannot read data.save");
    let xored      = xor_with_key(&ciphertext, steam_id);
    match zlib_decompress(&xored) {
        Some(payload) => {
            println!("    [OK] Decrypted and decompressed successfully ({} raw bytes).", payload.len());
            if payload.len() >= 12 {
                let head_len = (u32::from_le_bytes(payload[4..8].try_into().unwrap()) & 0x3FFF_FFFF) as usize;
                if head_len < 100 && payload.len() >= 8 + head_len {
                    let class = String::from_utf8_lossy(&payload[8..8 + head_len]);
                    println!("    Save Data Class: '{class}'");
                }
            }
            let out = build_out_path(path, ".decrypted");
            fs::write(&out, &payload).expect("cannot write decrypted data");
            println!("    [SUCCESS] Dumped decrypted raw save payload -> {}\n", out.file_name().unwrap().to_string_lossy());
        }
        None => {
            eprintln!("    [ERROR] Decompression failed. The SteamID {steam_id} may be incorrect, or the file is corrupted.\n");
        }
    }
}

pub fn cmd_encrypt_folder(folder: &Path, steam_id: Option<u64>) {
    let folders = collect_save_folders(folder);
    let mut processed = 0usize;
    for save_dir in &folders {
        println!("\nSave container: {}", save_dir.display());
        let index_dec = save_dir.join("index.save.decrypted");
        let data_dec  = save_dir.join("data.save.decrypted");
        if !index_dec.exists() && !data_dec.exists() {
            println!("  [SKIP] No .decrypted files found.");
            continue;
        }
        let index_path = save_dir.join("index.save");
        match resolve_steam_id(steam_id, &index_path, None, false) {
            Some(sid) => {
                if index_dec.exists() { encrypt_index(&index_dec, &save_dir.join("index.save"), sid); }
                if data_dec.exists()  { encrypt_data(&data_dec,   &save_dir.join("data.save"),  sid); }
                processed += 1;
            }
            None => eprintln!(
                "  [ERROR] Could not determine SteamID64 for {}. Use --steam-id.",
                save_dir.display()
            ),
        }
    }
    println!("------------------------------------------------");
    println!("Encryption completed. Processed {processed} save containers.");
}

pub fn cmd_encrypt_file(path: &Path, steam_id: Option<u64>) {
    let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
    let dir  = path.parent().unwrap_or(Path::new("."));
    let sid  = resolve_steam_id(steam_id, &dir.join("index.save"), None, false);
    let Some(sid) = sid else {
        eprintln!("[ERROR] Could not determine SteamID64. Use --steam-id.");
        std::process::exit(1);
    };
    if name.contains("index") {
        encrypt_index(path, &dir.join("index.save"), sid);
    } else {
        encrypt_data(path, &dir.join("data.save"), sid);
    }
}

pub fn encrypt_index(decrypted_path: &Path, output_path: &Path, steam_id: u64) {
    println!("  Processing index.save.decrypted:");
    if !decrypted_path.exists() {
        println!("    [WARN] Not found: {}", decrypted_path.display());
        return;
    }
    let plaintext = fs::read(decrypted_path).expect("cannot read decrypted index");
    if plaintext.len() < 8 {
        eprintln!("    [ERROR] File too short.");
        return;
    }
    let ciphertext = xor_with_key(&plaintext, steam_id);
    // backup_if_needed(output_path);
    fs::write(output_path, &ciphertext).expect("cannot write encrypted index");
    println!("    [SUCCESS] Encrypted index saved to -> {}\n", output_path.file_name().unwrap().to_string_lossy());
}

pub fn encrypt_data(decrypted_path: &Path, output_path: &Path, steam_id: u64) {
    println!("  Processing data.save.decrypted:");
    if !decrypted_path.exists() {
        println!("    [WARN] Not found: {}", decrypted_path.display());
        return;
    }
    let plaintext  = fs::read(decrypted_path).expect("cannot read decrypted data");
    let compressed = zlib_compress(&plaintext);
    let ciphertext = xor_with_key(&compressed, steam_id);
    // backup_if_needed(output_path);
    fs::write(output_path, &ciphertext).expect("cannot write encrypted data");
    println!("    [SUCCESS] Encrypted and packed save -> {}\n", output_path.file_name().unwrap().to_string_lossy());
}

pub fn cmd_resign_folder(folder: &Path, to_id: u64, from_id: Option<u64>, auto_confirm: bool) {
    match backup_folder(folder) {
        Ok(bak) => println!("  [OK] Backed up to: {}", bak.display()),
        Err(e)  => eprintln!("  [WARN] Backup failed: {e} — proceeding anyway"),
    }

    let folders = collect_save_folders(folder);
    if folders.is_empty() {
        println!("[warn] no save containers found under {}", folder.display());
        return;
    }

    let mut resigned = 0usize;
    for save_dir in &folders {
        println!("\nFound save container in: {}", save_dir.display());
        if resign_container(save_dir, to_id, from_id, auto_confirm) {
            resigned += 1;
        }
    }
    println!("------------------------------------------------");
    println!("Re-signing finished. Resigned {resigned} save containers successfully!");
}

pub fn cmd_resign_file(path: &Path, to_id: u64, from_id: Option<u64>) {
    let dir  = path.parent().unwrap_or(Path::new("."));
    match backup_folder(dir) {
        Ok(bak) => println!("  [OK] Folder backed up -> {}", bak.display()),
        Err(e)  => eprintln!("  [WARN] Folder backup failed: {e} — proceeding anyway"),
    }
    let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
    if name.contains("index") {
        let sid = resolve_steam_id(from_id, path, None, false).unwrap_or_else(|| {
            eprintln!("[ERROR] Cannot determine from-id. Use --from-id.");
            std::process::exit(1);
        });
        resign_index(path, sid, to_id);
    } else {
        let index_path = dir.join("index.save");
        let sid = resolve_steam_id(from_id, &index_path, Some(path), true).unwrap_or_else(|| {
            eprintln!("[ERROR] Cannot determine from-id. Use --from-id.");
            std::process::exit(1);
        });
        resign_data(path, sid, to_id);
    }
}

fn resign_container(save_dir: &Path, to_id: u64, user_from_id: Option<u64>, auto_confirm: bool) -> bool {
    let index_path = save_dir.join("index.save");
    let data_path  = save_dir.join("data.save");
    let has_index  = index_path.exists();
    let has_data   = data_path.exists();

    if has_index && has_data {
        let index_sid = detect_steam_id_from_index_path(&index_path);
        print!("  [AUTO] Bruteforcing data.save encryption key... ");
        std::io::stdout().flush().ok();
        let start = Instant::now();
        let ciphertext = fs::read(&data_path).expect("cannot read data.save");
        let data_key   = bruteforce_data_save(&ciphertext);
        let elapsed    = start.elapsed();

        let data_sid = match data_key {
            Some(k) => {
                println!("cracked in {:?}: {k}", elapsed);
                k
            }
            None => {
                println!("FAILED");
                eprintln!("  [ERROR] data.save bruteforce failed and no manual SteamID64 was specified. Skipping container.");
                eprintln!("          Run with: fl007 resign --folder <path> --to-id <TargetSID> --from-id <SourceSID>");
                return false;
            }
        };

        let index_sid = match index_sid {
            Some(s) => s,
            None => {
                eprintln!("  [ERROR] index.save auto-detect failed and no manual SteamID64 was specified. Skipping container.");
                eprintln!("          Run with: fl007 resign --folder <path> --to-id <TargetSID> --from-id <SourceSID>");
                return false;
            }
        };

        if index_sid == data_sid {
            println!("  [OK] Keys match! Both files are bound to same SteamID64: {index_sid}");
            let from = user_from_id.unwrap_or(index_sid);
            resign_index(&index_path, from, to_id);
            resign_data(&data_path, from, to_id);
        } else {
            println!("  {}", "!".repeat(64));
            println!("  [WARNING] STEAMID MISMATCH DETECTED!");
            println!("    index.save is bound to: {index_sid}");
            println!("    data.save is encrypted with: {data_sid}");
            println!("  {}", "!".repeat(64));

            if let Some(from) = user_from_id {
                println!("  Using manual override key {from} for both files.");
                resign_index(&index_path, from, to_id);
                resign_data(&data_path, from, to_id);
            } else if auto_confirm
                || confirm(
                    &format!("Proceed with dynamic split re-signing?\n    (index.save will use {index_sid} and data.save will use {data_sid})"),
                    true,
                )
            {
                println!("  Proceeding with dynamic splitting...");
                resign_index(&index_path, index_sid, to_id);
                resign_data(&data_path, data_sid, to_id);
            } else {
                println!("  Skipped this container per user rejection.");
                return false;
            }
        }
    } else if has_index {
        println!("  [INFO] Only index.save is present in this container.");
        let index_sid = detect_steam_id_from_index_path(&index_path);
        let sid = match index_sid.or(user_from_id) {
            Some(s) => s,
            None => {
                eprintln!("  [ERROR] index.save auto-detect failed and no manual SteamID64 was specified. Skipping container.");
                eprintln!("          Run with: fl007 resign --folder <path> --to-id <TargetSID> --from-id <SourceSID>");
                return false;
            }
        };
        let from = user_from_id.unwrap_or(sid);
        resign_index(&index_path, from, to_id);
        println!("  [INFO] data.save is missing, skipped data resigning.");
    } else if has_data {
        println!("  [INFO] Only data.save is present in this container.");
        print!("  [AUTO] Bruteforcing data.save encryption key... ");
        std::io::stdout().flush().ok();
        let start = Instant::now();
        let ct  = fs::read(&data_path).expect("cannot read data.save");
        let key = bruteforce_data_save(&ct);
        let elapsed = start.elapsed();
        match key {
            Some(k) => {
                println!("cracked in {:?}: {k}", elapsed);
                let from = user_from_id.unwrap_or(k);
                resign_data(&data_path, from, to_id);
                println!("  [INFO] index.save is missing, skipped index resigning.");
            }
            None => {
                println!("FAILED");
                eprintln!("  [ERROR] data.save bruteforce failed and no manual SteamID64 was specified. Skipping container.");
                eprintln!("          Run with: fl007 resign --folder <path> --to-id <TargetSID> --from-id <SourceSID>");
                return false;
            }
        }
    }
    true
}

fn resign_index(path: &Path, from_id: u64, to_id: u64) {
    println!("  Resigning index.save:");
    let ciphertext = fs::read(path).expect("cannot read index.save");
    let from_bytes = from_id.to_le_bytes();
    let to_bytes   = to_id.to_le_bytes();
    let resigned: Vec<u8> = ciphertext.iter().enumerate().map(|(i, &b)| b ^ from_bytes[i % 8] ^ to_bytes[i % 8]).collect();
    // backup_if_needed(path);
    fs::write(path, &resigned).expect("cannot write resigned index");
    println!("    [SUCCESS] index.save decrypted & resigned successfully!\n");
}

fn resign_data(path: &Path, from_id: u64, to_id: u64) {
    println!("  Resigning data.save:");
    let ciphertext = fs::read(path).expect("cannot read data.save");
    let decrypted  = xor_with_key(&ciphertext, from_id);
    let _payload = match zlib_decompress(&decrypted) {
        Some(p) => {
            println!("    [OK] Decrypted and decompressed payload successfully ({} raw bytes).", p.len());
            p
        }
        None => {
            eprintln!("    [ERROR] Decompression failed. Source SteamID may be incorrect or file is corrupted.");
            return;
        }
    };
    let from_bytes = from_id.to_le_bytes();
    let to_bytes   = to_id.to_le_bytes();
    let resigned: Vec<u8> = ciphertext.iter().enumerate().map(|(i, &b)| b ^ from_bytes[i % 8] ^ to_bytes[i % 8]).collect();
    // backup_if_needed(path);
    fs::write(path, &resigned).expect("cannot write resigned data");
    println!(
        "    [SUCCESS] data.save re-encrypted & resigned successfully! ({} bytes preserved)\n",
        resigned.len()
    );
}

pub fn cmd_bruteforce_folder(folder: &Path) {
    let folders = collect_save_folders(folder);
    for save_dir in &folders {
        println!("\n=== {} ===", save_dir.display());
        let index_path = save_dir.join("index.save");
        let data_path  = save_dir.join("data.save");
        if index_path.exists() { cmd_bruteforce_file(&index_path); }
        if data_path.exists()  { cmd_bruteforce_file(&data_path); }
    }
}

pub fn cmd_bruteforce_file(path: &Path) {
    let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
    let ciphertext = fs::read(path).expect("cannot read file");
    println!("Loaded ciphertext: {} bytes.", ciphertext.len());

    if name.contains("index") {
        println!("Detected index.save format. Initiating instant zero-cost XOR key reconstruction...");
        let start = Instant::now();
        match crack_index_save(&ciphertext) {
            Some(key) => {
                let elapsed = start.elapsed();
                println!("\n[SUCCESS] Key cracked in {elapsed:.6?}!");
                println!("  Cracked SteamID64: {key}");
                println!("  Cracked XOR Key:   {}", hex_bytes(&key.to_le_bytes()));
                let out   = build_out_path(path, ".decrypted");
                let plain = xor_with_key(&ciphertext, key);
                fs::write(&out, &plain).expect("cannot write");
                println!("  Saved decrypted index -> {}", out.file_name().unwrap().to_string_lossy());
            }
            None => eprintln!(
                "\n[FAILED] Instant key reconstruction failed to yield a valid SSaveGameHeader."
            ),
        }
    } else {
        let b0 = ciphertext[0] ^ 0x78;
        let b1_candidates: Vec<String> = VALID_FLG.iter().map(|&f| format!("0x{:02X}", ciphertext[1] ^ f)).collect();
        println!("Initiating accelerated zlib-constrained key-space reduction...");
        println!("  Key Byte 0 resolved to: 0x{b0:02X}");
        println!("  Key Byte 1 candidates:  {}", b1_candidates.join(", "));
        println!("  Testing remaining 16-bit key space (262,144 combinations)...");

        let start = Instant::now();
        match bruteforce_data_save(&ciphertext) {
            Some(key) => {
                let elapsed      = start.elapsed();
                let plain        = xor_with_key(&ciphertext, key);
                let decompressed = zlib_decompress(&plain).expect("decompressed must succeed after crack");
                println!("\n[SUCCESS] Key cracked in {elapsed:.4?}!");
                println!("  Cracked SteamID64: {key}");
                println!("  Cracked XOR Key:   {}", hex_bytes(&key.to_le_bytes()));
                println!("  Decompressed Size: {} bytes", decompressed.len());
                if decompressed.len() >= 12 {
                    let head_len = (u32::from_le_bytes(decompressed[4..8].try_into().unwrap()) & 0x3FFF_FFFF) as usize;
                    if head_len < 100 && decompressed.len() >= 8 + head_len {
                        let class = String::from_utf8_lossy(&decompressed[8..8 + head_len]);
                        println!("  Save Data Class:   '{class}'");
                    }
                }
                let out = build_out_path(path, ".decrypted");
                fs::write(&out, &decompressed).expect("cannot write");
                println!("  Saved raw decompressed file -> {}", out.file_name().unwrap().to_string_lossy());
            }
            None => {
                let elapsed = start.elapsed();
                println!(
                    "\n[FAILED] Brute-force completed in {elapsed:.4?} after 262144 tests. No key found."
                );
            }
        }
    }
}

pub fn cmd_unsign_folder(folder: &Path, steam_id: Option<u64>) {
    let folders = collect_save_folders(folder);
    if folders.is_empty() {
        println!("[warn] no save containers found under {}", folder.display());
        return;
    }
    let mut processed = 0usize;
    for save_dir in &folders {
        println!("\nUnsigning container: {}", save_dir.display());
        let index_path = save_dir.join("index.save");
        let data_path  = save_dir.join("data.save");
        let sid = resolve_steam_id(steam_id, &index_path, Some(&data_path), true);
        if let Some(sid) = sid {
            if index_path.exists() { unsign_file(&index_path, sid); }
            if data_path.exists()  { unsign_file(&data_path, sid); }
            processed += 1;
        } else {
            eprintln!(
                "  [ERROR] Could not determine SteamID64 for {}. Use --steam-id.",
                save_dir.display()
            );
        }
    }
    println!("------------------------------------------------");
    println!("Unsigning completed. Processed {processed} save containers.");
}

pub fn cmd_unsign_file(path: &Path, steam_id: Option<u64>) {
    let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
    let dir  = path.parent().unwrap_or(Path::new("."));

    let sid = if name.contains("index") {
        resolve_steam_id(steam_id, path, None, false)
    } else {
        resolve_steam_id(steam_id, &dir.join("index.save"), Some(path), true)
    };

    let Some(sid) = sid else {
        eprintln!("[ERROR] Could not determine SteamID64. Use --steam-id.");
        std::process::exit(1);
    };

    unsign_file(path, sid);
}

fn unsign_file(path: &Path, steam_id: u64) {
    println!("  Unsigning {}:", path.file_name().unwrap().to_string_lossy());
    let ciphertext = fs::read(path).expect("cannot read file");
    let plaintext = xor_with_key(&ciphertext, steam_id);
    fs::write(path, &plaintext).expect("cannot write unsigned file");
    println!("    [SUCCESS] File unsigned (Epic Games compatible) successfully!");
}

pub fn cmd_sign_folder(folder: &Path, steam_id: u64) {
    let folders = collect_save_folders(folder);
    if folders.is_empty() {
        println!("[warn] no save containers found under {}", folder.display());
        return;
    }
    let mut processed = 0usize;
    for save_dir in &folders {
        println!("\nSigning container: {}", save_dir.display());
        let index_path = save_dir.join("index.save");
        let data_path  = save_dir.join("data.save");
        if index_path.exists() { sign_file(&index_path, steam_id); }
        if data_path.exists()  { sign_file(&data_path, steam_id); }
        processed += 1;
    }
    println!("------------------------------------------------");
    println!("Signing completed. Processed {processed} save containers.");
}

pub fn cmd_sign_file(path: &Path, steam_id: u64) {
    sign_file(path, steam_id);
}

fn sign_file(path: &Path, steam_id: u64) {
    println!("  Signing {}:", path.file_name().unwrap().to_string_lossy());
    let plaintext = fs::read(path).expect("cannot read file");
    let ciphertext = xor_with_key(&plaintext, steam_id);
    fs::write(path, &ciphertext).expect("cannot write signed file");
    println!("    [SUCCESS] File signed (Steam compatible) successfully!");
}