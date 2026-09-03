use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AegisVault {
    pub version: u32,
    pub header: AegisHeader,
    pub db: AegisDbPayload,
}

#[derive(Debug, Deserialize)]
pub struct AegisHeader {
    pub slots: Option<Vec<AegisSlot>>,
    pub params: Option<AegisCipherParams>,
}

#[derive(Debug, Deserialize)]
pub struct AegisCipherParams {
    pub nonce: String,
    pub tag: String,
}

#[derive(Debug, Deserialize)]
pub struct AegisSlot {
    #[serde(rename = "type")]
    pub slot_type: u32,
    pub uuid: Option<String>,
    pub key: String,
    pub key_params: AegisCipherParams,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AegisDbPayload {
    Plain(AegisDatabase),
    Encrypted(String),
}

#[derive(Debug, Deserialize)]
pub struct AegisDatabase {
    pub version: Option<u32>,
    pub entries: Vec<AegisEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AegisEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    pub uuid: String,
    pub name: String,
    pub issuer: Option<String>,
    pub note: Option<String>,
    pub icon: Option<serde_json::Value>,
    pub info: AegisEntryInfo,
}

#[derive(Debug, Deserialize)]
pub struct AegisEntryInfo {
    pub secret: String,
    pub algo: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
    pub counter: Option<u64>,
}
