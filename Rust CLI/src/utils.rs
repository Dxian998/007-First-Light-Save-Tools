use std::fs;
use std::path::{Path, PathBuf};

pub fn collect_save_folders(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    collect_recursive(root, &mut result);
    result.sort();
    result
}

fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    let has_index = entries.iter().any(|e| e.file_name() == "index.save");
    let has_data  = entries.iter().any(|e| e.file_name() == "data.save");

    for entry in &entries {
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            let skip = name.contains(".git")
                || name.contains("007-firstlight-toolkit")
                || name == "Backup";
            if !skip {
                collect_recursive(&entry.path(), out);
            }
        }
    }

    if has_index || has_data {
        out.push(dir.to_path_buf());
    }
}

pub fn build_out_path(source_file: &Path, suffix: &str) -> PathBuf {
    let mut name = source_file
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    name.push_str(suffix);
    source_file.with_file_name(name)
}

#[allow(dead_code)]
pub fn backup_if_needed(path: &Path) {
    let parent = path.parent().unwrap_or(Path::new("."));
    let bak_dir = parent.join("Backup");
    if !bak_dir.exists() {
        let _ = fs::create_dir_all(&bak_dir);
    }
    let bak = bak_dir.join(path.file_name().unwrap());
    if !bak.exists() && path.exists() {
        if fs::copy(path, &bak).is_ok() {
            println!("    [OK] Backup created -> {}", bak.display());
        }
    }
}

pub fn backup_folder(folder: &Path) -> std::io::Result<PathBuf> {
    let bak_dir = folder.join("Backup");
    fs::create_dir_all(&bak_dir)?;
    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "Backup" {
            continue;
        }
        let dest = bak_dir.join(&name);
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), dest)?;
        }
    }
    Ok(bak_dir)
}

pub fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let dest  = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}