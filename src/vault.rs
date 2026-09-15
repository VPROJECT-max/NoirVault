use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultData {
    pub items: Vec<VaultItem>,
    #[serde(default)]
    pub trusted_machines: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultItem {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub item_type: String, // "password" or "file" or "note" or "ssh_key"
    pub content: String, // plain text password, or base64 encoded file
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            trusted_machines: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize vault data")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
