slint::include_modules!();

mod backup;

use std::rc::Rc;
use std::cell::RefCell;
use slint::{SharedString, Timer, TimerMode, VecModel, Model};
use rfd::FileDialog;
use std::fs;
use noirvault::{crypto, memory};
use noirvault::memory::SecureBuffer;
use noirvault::vault::{VaultData, VaultItem};
use base64::prelude::*;
use totp_rs::{TOTP, Secret, Algorithm};

struct AppState {
    master_password: Option<SecureBuffer>,
    vault_data: VaultData,
}

impl Drop for AppState {
    fn drop(&mut self) {
        self.master_password = None;
    }
}

fn sync_ui_list(ui: &AppWindow, vault_data: &VaultData) {
    let epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let seconds_left = (30 - (epoch % 30)) as i32;
    
    let active_category = ui.get_active_category().to_string();
    let search_query = ui.get_search_query().to_string().to_lowercase();
    
    let current_model = ui.get_vault_items();
    
    let mut items = Vec::new();
    
    for item in vault_data.items.iter() {
        // Category Filter
        let category_match = match active_category.as_str() {
            "Passwords" => item.item_type == "password",
            "Secure Notes" => item.item_type == "note",
            "Files" => item.item_type == "file",
            "SSH Keys" => item.item_type == "ssh_key",
            _ => true, // "All Items"
        };
        
        if !category_match {
            continue;
        }
        
        // Search Filter
        if !search_query.is_empty() {
            let tags_str = item.tags.join(" ").to_lowercase();
            if !item.title.to_lowercase().contains(&search_query) 
               && !item.description.to_lowercase().contains(&search_query)
               && !tags_str.contains(&search_query) {
                continue;
            }
        }
        
        let mut totp_code = String::new();
        if !item.totp_secret.is_empty() {
            let clean_secret = item.totp_secret.replace(" ", "").to_uppercase();
            if let Ok(secret) = Secret::Encoded(clean_secret).to_bytes() {
                if let Ok(totp) = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret) {
                    totp_code = totp.generate_current().unwrap_or_default();
                }
            }
        }
        let title_lower = item.title.to_lowercase();
        let icon_type = if title_lower.contains("google") { "google" }
        else if title_lower.contains("github") { "github" }
        else if title_lower.contains("discord") { "discord" }
        else if title_lower.contains("steam") { "steam" }
        else if title_lower.contains("microsoft") { "microsoft" }
        else if title_lower.contains("aws") { "awg" }
        else if title_lower.contains("bank") { "bank" }
        else { &item.item_type };
        
        items.push(VaultItemUI {
            id: SharedString::from(&item.id),
            title: SharedString::from(&item.title),
            description: SharedString::from(&item.description),
            content: SharedString::from(&item.content),
            item_type: SharedString::from(&item.item_type),
            icon_type: SharedString::from(icon_type),
            totp_code: SharedString::from(totp_code),
            totp_seconds: seconds_left,
            tags: SharedString::from(item.tags.join(", ")),
        });
    }
    
    let replace_all = current_model.row_count() != items.len();
    
    if replace_all {
        let model = Rc::new(VecModel::from(items));
        ui.set_vault_items(model.into());
    } else {
        if let Some(vec_model) = current_model.as_any().downcast_ref::<VecModel<VaultItemUI>>() {
            for (i, item) in items.into_iter().enumerate() {
                vec_model.set_row_data(i, item);
            }
        } else {
            let model = Rc::new(VecModel::from(items));
            ui.set_vault_items(model.into());
        }
    }
}

fn save_vault_to_disk(state: &AppState) {
    let password = match &state.master_password {
        Some(value) => value,
        None => return,
    };
    let password = match std::str::from_utf8(password.as_slice()) {
        Ok(value) => value,
        Err(_) => return,
    };
    let data_bytes = state.vault_data.to_bytes();
    let envelope = crypto::encrypt_v2(password, &data_bytes);

    fs::write("vault.dat", envelope).expect("Failed to write vault.dat");
}

fn main() {
    memory::set_process_protections();
    
    let ui = AppWindow::new().unwrap();
    let ui_handle = ui.as_weak();
    
    let state = Rc::new(RefCell::new(AppState { 
        master_password: None,
        vault_data: VaultData::new(),
    }));
    
    ui.on_select_keyfile({
        let ui_handle = ui_handle.clone();
        move || {
            if let Some(path) = FileDialog::new().pick_file() {
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_keyfile_path(SharedString::from(path.to_string_lossy().to_string()));
                }
            }
        }
    });

    ui.on_unlock({
        let ui_handle = ui_handle.clone();
        let state = state.clone();
        move |password| {
            let ui = ui_handle.upgrade().unwrap();
            let mut current_state = state.borrow_mut();
            let password_buffer = SecureBuffer::from_slice(password.as_bytes());

            match fs::read("vault.dat") {
                Ok(file_bytes) if crypto::is_v2_envelope(&file_bytes) => {
                    let decrypted = match crypto::decrypt_v2(&password, &file_bytes) {
                        Ok(value) => value,
                        Err(_) => {
                            ui.set_status_message(SharedString::from("Invalid master password or corrupted vault."));
                            return;
                        }
                    };
                    match VaultData::from_bytes(decrypted.as_slice()) {
                        Ok(value) => current_state.vault_data = value,
                        Err(_) => {
                            ui.set_status_message(SharedString::from("Failed to parse vault data."));
                            return;
                        }
                    }
                }
                Ok(file_bytes) => {
                    if file_bytes.len() < 16 + 24 + 16 {
                        ui.set_status_message(SharedString::from("vault.dat is corrupted (too small)."));
                        return;
                    }
                    let keyfile_path = ui.get_keyfile_path().to_string();
                    if keyfile_path == "No keyfile selected (legacy vaults only)" {
                        ui.set_status_message(SharedString::from("This legacy vault needs its keyfile once before it can migrate."));
                        return;
                    }
                    let keyfile_bytes = match fs::read(keyfile_path) {
                        Ok(value) => value,
                        Err(_) => {
                            ui.set_status_message(SharedString::from("Failed to read the legacy keyfile."));
                            return;
                        }
                    };
                    let mut salt = [0u8; 16];
                    salt.copy_from_slice(&file_bytes[..16]);
                    let legacy_key = crypto::derive_key(&password, &keyfile_bytes, &salt);
                    let decrypted = match crypto::decrypt_data(&file_bytes[16..], &legacy_key) {
                        Some(value) => value,
                        None => {
                            ui.set_status_message(SharedString::from("Invalid master password or legacy keyfile."));
                            return;
                        }
                    };
                    match VaultData::from_bytes(decrypted.as_slice()) {
                        Ok(value) => current_state.vault_data = value,
                        Err(_) => {
                            ui.set_status_message(SharedString::from("Failed to parse vault data."));
                            return;
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    current_state.vault_data = VaultData::new();
                }
                Err(_) => {
                    ui.set_status_message(SharedString::from("Unable to read vault.dat."));
                    return;
                }
            }
            current_state.master_password = Some(password_buffer);
            
            ui.set_status_message(SharedString::from(""));
            ui.set_unlocked(true);
            
            let machine_id = backup::get_machine_id();
            let is_trusted = current_state.vault_data.trusted_machines.contains(&machine_id);
            ui.set_machine_trusted(is_trusted);
            
            if is_trusted {
                std::thread::spawn(|| {
                    backup::execute_auto_backup();
                });
            }
            
            sync_ui_list(&ui, &current_state.vault_data);
        }
    });
    
    ui.on_lock_and_exit({
        let state = state.clone();
        move || {
            let mut s = state.borrow_mut();
            s.master_password = None;
            s.vault_data = VaultData::new();
            let _ = slint::quit_event_loop();
        }
    });

    ui.on_toggle_trust_machine({
        let ui_handle = ui_handle.clone();
        let state = state.clone();
        move || {
            let mut s = state.borrow_mut();
            let machine_id = backup::get_machine_id();
            let mut trusted = false;
            
            if let Some(pos) = s.vault_data.trusted_machines.iter().position(|id| id == &machine_id) {
                s.vault_data.trusted_machines.remove(pos);
            } else {
                s.vault_data.trusted_machines.push(machine_id);
                trusted = true;
            }
            save_vault_to_disk(&s);
            
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_machine_trusted(trusted);
            }
        }
    });

    ui.on_add_item({
        let ui_handle = ui_handle.clone();
        let state = state.clone();
        move |item_type, title, description, content, totp_secret, tags_str| {
            let mut s = state.borrow_mut();
            
            let tags: Vec<String> = tags_str.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
                
            let new_item = VaultItem {
                id: uuid::Uuid::new_v4().to_string(),
                title: title.to_string(),
                description: description.to_string(),
                totp_secret: totp_secret.to_string(),
                tags,
                item_type: item_type.to_string(),
                content: content.to_string(),
                website: String::new(),
                notes: String::new(),
                favorite: false,
            };
            s.vault_data.items.push(new_item);
            save_vault_to_disk(&s);
            
            if let Some(ui) = ui_handle.upgrade() {
                sync_ui_list(&ui, &s.vault_data);
            }
        }
    });

    ui.on_pick_file_to_add({
        let ui_handle = ui_handle.clone();
        move || {
            if let Some(path) = FileDialog::new().pick_file() {
                if let Ok(bytes) = fs::read(&path) {
                    let b64 = BASE64_STANDARD.encode(&bytes);
                    if let Some(ui) = ui_handle.upgrade() {
                        ui.set_file_to_add_path(SharedString::from(path.to_string_lossy().to_string()));
                        ui.set_file_to_add_b64(SharedString::from(b64));
                    }
                }
            }
        }
    });

    ui.on_delete_item({
        let ui_handle = ui_handle.clone();
        let state = state.clone();
        move |id_str| {
            let mut s = state.borrow_mut();
            if let Some(pos) = s.vault_data.items.iter().position(|item| item.id == id_str.as_str()) {
                s.vault_data.items.remove(pos);
                save_vault_to_disk(&s);
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_selected_index(-1);
                    sync_ui_list(&ui, &s.vault_data);
                }
            }
        }
    });

    ui.on_extract_file({
        let state = state.clone();
        move |id_str| {
            let s = state.borrow();
            if let Some(item) = s.vault_data.items.iter().find(|i| i.id == id_str.as_str()) {
                if item.item_type == "file" {
                    if let Ok(bytes) = BASE64_STANDARD.decode(&item.content) {
                        if let Some(path) = FileDialog::new().set_file_name(&item.title).save_file() {
                            let _ = fs::write(path, bytes);
                        }
                    }
                }
            }
        }
    });

    ui.on_copy_to_clipboard({
        move |text| {
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                let text_str = text.to_string();
                let _ = clipboard.set_text(text_str.clone());
                
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(15));
                    if let Ok(mut cb) = arboard::Clipboard::new() {
                        if let Ok(current) = cb.get_text() {
                            if current == text_str {
                                let _ = cb.set_text("".to_string());
                            }
                        }
                    }
                });
            }
        }
    });
    
    ui.on_auto_type_password({
        let ui_handle = ui_handle.clone();
        let state = state.clone();
        move || {
            if let Some(ui) = ui_handle.upgrade() {
                let idx = ui.get_selected_index();
                if idx < 0 { return; }
                
                let model = ui.get_vault_items();
                if let Some(item_ui) = model.row_data(idx as usize) {
                    let id_str = item_ui.id;
                    let s = state.borrow();
                    
                    if let Some(item) = s.vault_data.items.iter().find(|i| i.id == id_str.as_str()) {
                        let password = item.content.clone(); 
                        
                        ui.set_auto_type_active(true);
                        ui.set_auto_type_countdown(3);
                        
                        let ui_timer_handle = ui_handle.clone();
                        std::thread::spawn(move || {
                            for i in (1..=3).rev() {
                                let weak = ui_timer_handle.clone();
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = weak.upgrade() {
                                        ui.set_auto_type_countdown(i);
                                    }
                                });
                                std::thread::sleep(std::time::Duration::from_secs(1));
                            }
                            
                            use enigo::{Enigo, KeyboardControllable};
                            let mut enigo = Enigo::new();
                            for c in password.chars() {
                                let mut buf = [0; 4];
                                enigo.key_sequence(c.encode_utf8(&mut buf));
                            }
                            
                            let weak_final = ui_timer_handle.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui) = weak_final.upgrade() {
                                    ui.set_auto_type_active(false);
                                }
                            });
                        });
                    }
                }
            }
        }
    });

    ui.on_handle_key_pressed({
        let ui_handle = ui_handle.clone();
        move |key| {
            if let Some(ui) = ui_handle.upgrade() {
                let current_idx = ui.get_selected_index();
                let model = ui.get_vault_items();
                let count = model.row_count() as i32;
                
                if count == 0 {
                    return;
                }
                
                match key.as_str() {
                    "up" => {
                        let new_idx = if current_idx <= 0 { count - 1 } else { current_idx - 1 };
                        ui.set_selected_index(new_idx);
                        ui.set_show_add_dialog(false);
                    },
                    "down" => {
                        let new_idx = if current_idx < 0 || current_idx >= count - 1 { 0 } else { current_idx + 1 };
                        ui.set_selected_index(new_idx);
                        ui.set_show_add_dialog(false);
                    },
                    "enter" => {
                        if current_idx >= 0 && current_idx < count {
                            if let Some(item_ui) = model.row_data(current_idx as usize) {
                                ui.invoke_copy_to_clipboard(item_ui.content);
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
    });

    // Dummy search handler to trigger live filtering
    ui.on_search({
        let ui_handle = ui_handle.clone();
        let state = state.clone();
        move |_text| {
            if let Some(ui) = ui_handle.upgrade() {
                let s = state.borrow();
                sync_ui_list(&ui, &s.vault_data);
            }
        }
    });
    
    let totp_timer = Timer::default();
    let ui_for_totp = ui_handle.clone();
    let state_for_totp = state.clone();
    totp_timer.start(TimerMode::Repeated, std::time::Duration::from_secs(1), move || {
        if let Some(ui) = ui_for_totp.upgrade() {
            let s = state_for_totp.borrow();
            if ui.get_unlocked() {
                sync_ui_list(&ui, &s.vault_data);
            }
        }
    });

    let extract_timer = Timer::default();
    let state_for_extract = state.clone();
    extract_timer.start(TimerMode::Repeated, std::time::Duration::from_secs(1), move || {
        if let Ok(exe_path) = std::env::current_exe() {
            if !exe_path.exists() {
                let mut s = state_for_extract.borrow_mut();
                s.master_password = None;
                s.vault_data = VaultData::new();
                std::process::abort();
            }
        }
    });

    ui.run().unwrap();
}
