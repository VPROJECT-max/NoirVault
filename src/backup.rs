use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;

pub fn get_machine_id() -> String {
    let raw_id = machine_uid::get().unwrap_or_else(|_| "unknown_machine".to_string());
    // Hash the ID to prevent exposing raw hardware identifiers in vault.dat
    let mut hasher = Sha256::new();
    hasher.update(raw_id.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub fn execute_auto_backup() {
    let home_dir = match std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        Ok(dir) => dir,
        Err(_) => return, // Cannot determine home directory, abort backup
    };
    
    let backup_dir = PathBuf::from(home_dir).join(".noirvault_backups");
    if !backup_dir.exists() {
        if fs::create_dir_all(&backup_dir).is_err() {
            return;
        }
    }
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
        
    let backup_filename = format!("vault_{}.dat", timestamp);
    let backup_path = backup_dir.join(backup_filename);
    
    // Copy the raw encrypted blob from the USB drive to the local machine
    if fs::copy("vault.dat", &backup_path).is_ok() {
        // Prune to keep only the 5 most recent backups
        if let Ok(entries) = fs::read_dir(&backup_dir) {
            let mut backups: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().map_or(false, |ext| ext == "dat"))
                .collect();
                
            // Sort by modification time, oldest first
            backups.sort_by_key(|p| {
                p.metadata().and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            });
            
            // Remove older backups if we have more than 5
            if backups.len() > 5 {
                let to_remove = backups.len() - 5;
                for path in backups.iter().take(to_remove) {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
}
