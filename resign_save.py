import os
import shutil
import struct
import sys
import time
import zlib


def guess_xor_mask(index_path):
    if not os.path.exists(index_path):
        return None
    try:
        with open(index_path, "rb") as f:
            data = f.read()
        if len(data) < 24:
            return None
        pattern = b"meHeader"
        key_bytes = bytes(data[16 + i] ^ pattern[i] for i in range(8))
        key = struct.unpack("<Q", key_bytes)[0]
        
        decrypted = bytes(c ^ key_bytes[i % 8] for i, c in enumerate(data))
        if b"SSaveGameHeader" in decrypted:
            return key
    except Exception:
        pass
    return None


def detect_source_steam_id(index_path):
    guessed = guess_xor_mask(index_path)
    if guessed is not None:
        return guessed

    backup_path = os.path.join(os.path.dirname(index_path), "Backup", os.path.basename(index_path))
    target_path = backup_path
    if not os.path.exists(target_path):
        target_path = index_path
        
    try:
        with open(target_path, "rb") as f:
            data = f.read()
        if len(data) >= 28:
            account_id = struct.unpack_from("<I", data, 24)[0]
            detected_sid = 76561197960265728 + account_id
            return detected_sid
    except Exception:
        pass
    return None


def bruteforce_data_save_key(filepath):
    if not os.path.exists(filepath):
        return None
    backup_path = os.path.join(os.path.dirname(filepath), "Backup", os.path.basename(filepath))
    target_path = backup_path
    if not os.path.exists(target_path):
        target_path = filepath
        
    try:
        with open(target_path, "rb") as f:
            ciphertext = f.read()
    except Exception:
        return None
        
    if len(ciphertext) < 32:
        return None
        
    b0 = ciphertext[0] ^ 0x78
    valid_flgs = [0x01, 0x5E, 0x9C, 0xDA]
    b1_candidates = [ciphertext[1] ^ flg for flg in valid_flgs]
    
    header_chunk = ciphertext[:16]
    
    for b1 in b1_candidates:
        for b2 in range(256):
            for b3 in range(256):
                key = bytes([b0, b1, b2, b3, 0x01, 0x00, 0x10, 0x01])
                dec_header = bytes(c ^ key[i % 8] for i, c in enumerate(header_chunk))
                cmf = dec_header[0]
                flg = dec_header[1]
                
                if cmf == 0x78 and (cmf * 256 + flg) % 31 == 0:
                    try:
                        verify_chunk = bytes(c ^ key[i % 8] for i, c in enumerate(ciphertext[:128]))
                        decompressor = zlib.decompressobj()
                        decompressor.decompress(verify_chunk)
                        
                        full_decrypted = bytes(c ^ key[i % 8] for i, c in enumerate(ciphertext))
                        zlib.decompress(full_decrypted)
                        
                        steam_id = struct.unpack("<Q", key)[0]
                        return steam_id
                    except Exception:
                        pass
    return None


def resign_index_file(filepath, from_sid, to_sid):
    print(f"  Resigning index.save:")
    with open(filepath, 'rb') as f:
        original_ciphertext = f.read()
        
    from_sid_le = struct.pack("<Q", from_sid)
    to_sid_le = struct.pack("<Q", to_sid)
    
    new_ciphertext = bytes(c ^ from_sid_le[i % 8] ^ to_sid_le[i % 8] for i, c in enumerate(original_ciphertext))
    
    backup_dir = os.path.join(os.path.dirname(filepath), "Backup")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, os.path.basename(filepath))
    if not os.path.exists(backup_path):
        shutil.copy2(filepath, backup_path)
        print(f"    [OK] Backup created -> {backup_path}")
        
    with open(filepath, 'wb') as f:
        f.write(new_ciphertext)
    print(f"    [SUCCESS] index.save decrypted & resigned successfully!\n")


def resign_data_file(filepath, from_sid, to_sid):
    print(f"  Resigning data.save:")
    with open(filepath, 'rb') as f:
        original_ciphertext = f.read()
        
    from_sid_le = struct.pack("<Q", from_sid)
    to_sid_le = struct.pack("<Q", to_sid)
    
    decrypted_xor = bytes(c ^ from_sid_le[i % 8] for i, c in enumerate(original_ciphertext))
    
    try:
        decompressed_payload = zlib.decompress(decrypted_xor)
        print(f"    [OK] Decrypted and decompressed payload successfully ({len(decompressed_payload)} raw bytes).")
    except Exception as e:
        print(f"    [ERROR] Decompression failed. Source SteamID may be incorrect or file is corrupted. {e}")
        return False
        
    new_ciphertext = bytes(c ^ from_sid_le[i % 8] ^ to_sid_le[i % 8] for i, c in enumerate(original_ciphertext))
    
    backup_dir = os.path.join(os.path.dirname(filepath), "Backup")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, os.path.basename(filepath))
    if not os.path.exists(backup_path):
        shutil.copy2(filepath, backup_path)
        print(f"    [OK] Backup created -> {backup_path}")
        
    with open(filepath, 'wb') as f:
        f.write(new_ciphertext)
    print(f"    [SUCCESS] data.save re-encrypted & resigned successfully! ({len(new_ciphertext)} bytes preserved)\n")
    return True


def sign_unsign_file(filepath, steam_id, action="unsign"):
    print(f"  {action.capitalize()}ing {os.path.basename(filepath)}:")
    with open(filepath, 'rb') as f:
        original = f.read()
        
    key_bytes = struct.pack("<Q", steam_id)
    processed = bytes(c ^ key_bytes[i % 8] for i, c in enumerate(original))
    
    backup_dir = os.path.join(os.path.dirname(filepath), "Backup")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, os.path.basename(filepath))
    if not os.path.exists(backup_path):
        shutil.copy2(filepath, backup_path)
        print(f"    [OK] Backup created -> {backup_path}")
        
    with open(filepath, 'wb') as f:
        f.write(processed)
    print(f"    [SUCCESS] {os.path.basename(filepath)} {action}ed successfully!\n")


def get_confirmation(prompt, default=True, auto_confirm=False):
    if auto_confirm:
        return True
    if not sys.stdin.isatty():
        return default
    
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    suffix = " [Y/n]" if default else " [y/N]"
    
    while True:
        sys.stdout.write(prompt + suffix + ": ")
        choice = input().lower().strip()
        if choice == '':
            return default
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def print_usage():
    print("007 First Light (Knight) Save Tool (Python Version)")
    print("==================================================")
    print("Usage:")
    print("  python resign_save.py unsign <SourceSteamID64>")
    print("  python resign_save.py sign   <TargetSteamID64>")
    print("  python resign_save.py resign <TargetSteamID64> [SourceSteamID64]")
    print("\nLegacy Usage:")
    print("  python resign_save.py <TargetSteamID64> [SourceSteamID64]")
    print("\nFlags:")
    print("  -y / --yes   Auto-confirm mismatches")


def main():
    auto_confirm = "-y" in sys.argv or "--yes" in sys.argv
    clean_argv = [arg for arg in sys.argv if arg not in ("-y", "--yes")]
    
    mode = "resign"
    target_sid = None
    user_source_sid = None
    
    if len(clean_argv) >= 2:
        if clean_argv[1] in ("unsign", "sign", "resign"):
            mode = clean_argv[1]
            if len(clean_argv) < 3:
                print_usage()
                sys.exit(1)
            target_sid = int(clean_argv[2])
            if len(clean_argv) >= 4:
                user_source_sid = int(clean_argv[3])
        else:
            try:
                target_sid = int(clean_argv[1])
                mode = "resign"
                if len(clean_argv) >= 3:
                    user_source_sid = int(clean_argv[2])
            except ValueError:
                print_usage()
                sys.exit(1)
    else:
        print_usage()
        sys.exit(1)
        
    print(f"Starting Operation ({mode.upper()}):")
    if mode == "unsign":
        print(f"  Source SteamID64: {target_sid}")
    elif mode == "sign":
        print(f"  Target SteamID64: {target_sid}")
    else:
        if user_source_sid:
            print(f"  Source SteamID64: {user_source_sid} (Manually Specified)")
        else:
            print(f"  Source SteamID64: [AUTO-DETECT / BRUTEFORCE]")
        print(f"  Target SteamID64: {target_sid}")
    print("------------------------------------------------")
    
    processed_dirs = 0
    for root, dirs, files in os.walk("."):
        if "Backup" in dirs:
            dirs.remove("Backup")
        if ".git" in root or "007-firstlight-toolkit" in root:
            continue
            
        has_index = "index.save" in files
        has_data = "data.save" in files
        
        if has_index or has_data:
            print(f"\nFound save container in: {root}")
            
            index_path = os.path.join(root, "index.save")
            data_path = os.path.join(root, "data.save")

            if mode == "unsign":
                sid_to_use = target_sid or guess_xor_mask(index_path) or bruteforce_data_save_key(data_path)
                if not sid_to_use:
                    print("  [ERROR] Could not determine SteamID64. Use: py resign_save.py unsign <SourceSID>")
                    continue
                if has_index:
                    sign_unsign_file(index_path, sid_to_use, "unsign")
                if has_data:
                    sign_unsign_file(data_path, sid_to_use, "unsign")
                
            elif mode == "sign":
                if has_index:
                    sign_unsign_file(index_path, target_sid, "sign")
                if has_data:
                    sign_unsign_file(data_path, target_sid, "sign")
                    
            else:
                if has_index and has_data:
                    index_sid = detect_source_steam_id(index_path)
                    
                    print("  [AUTO] Bruteforcing data.save encryption key...")
                    start_t = time.time()
                    data_sid = bruteforce_data_save_key(data_path)
                    elapsed = time.time() - start_t
                    
                    if data_sid:
                        print(f"  [AUTO] data.save key cracked successfully in {elapsed:.3f}s: {data_sid}")
                    else:
                        print("  [ERROR] data.save bruteforce failed and no manual SteamID64 was specified. Skipping container.")
                        print("          Run with: py resign_save.py <TargetSID> <SourceSID>")
                        continue
                        
                    if not index_sid:
                        print("  [ERROR] index.save auto-detect failed and no manual SteamID64 was specified. Skipping container.")
                        print("          Run with: py resign_save.py <TargetSID> <SourceSID>")
                        continue

                    if index_sid == data_sid:
                        print(f"  [OK] Keys match! Both files are bound to same SteamID64: {index_sid}")
                        source_sid_to_use = user_source_sid or index_sid
                        resign_index_file(index_path, source_sid_to_use, target_sid)
                        resign_data_file(data_path, source_sid_to_use, target_sid)
                    else:
                        print("  " + "!" * 64)
                        print(f"  [WARNING] STEAMID MISMATCH DETECTED!")
                        print(f"    index.save is bound to: {index_sid}")
                        print(f"    data.save is encrypted with: {data_sid}")
                        print("  " + "!" * 64)
                        
                        if user_source_sid:
                            print(f"  Using manual override key {user_source_sid} for both files.")
                            resign_index_file(index_path, user_source_sid, target_sid)
                            resign_data_file(data_path, user_source_sid, target_sid)
                        else:
                            confirm_msg = f"  Proceed with dynamic split re-signing?\n    (index.save will use {index_sid} and data.save will use {data_sid})"
                            if get_confirmation(confirm_msg, default=True, auto_confirm=auto_confirm):
                                print("  Proceeding with dynamic splitting...")
                                resign_index_file(index_path, index_sid, target_sid)
                                resign_data_file(data_path, data_sid, target_sid)
                            else:
                                print("  Skipped this container per user rejection.")
                                continue
                                
                elif has_index:
                    print("  [INFO] Only index.save is present in this container.")
                    index_sid = detect_source_steam_id(index_path)
                    if not index_sid:
                        print("  [ERROR] index.save auto-detect failed and no manual SteamID64 was specified. Skipping container.")
                        print("          Run with: py resign_save.py <TargetSID> <SourceSID>")
                        continue
                    source_sid_to_use = user_source_sid or index_sid
                    resign_index_file(index_path, source_sid_to_use, target_sid)
                    print("  [INFO] data.save is missing, skipped data resigning.")
                    
                elif has_data:
                    print("  [INFO] Only data.save is present in this container.")
                    print("  [AUTO] Bruteforcing data.save encryption key...")
                    data_sid = bruteforce_data_save_key(data_path)
                    if not data_sid:
                        print("  [ERROR] data.save bruteforce failed and no manual SteamID64 was specified. Skipping container.")
                        print("          Run with: py resign_save.py <TargetSID> <SourceSID>")
                        continue
                    source_sid_to_use = user_source_sid or data_sid
                    resign_data_file(data_path, source_sid_to_use, target_sid)
                    print("  [INFO] index.save is missing, skipped index resigning.")
                    
            processed_dirs += 1
            
    print("------------------------------------------------")
    print(f"Operation finished. Processed {processed_dirs} save containers successfully!")


if __name__ == "__main__":
    main()