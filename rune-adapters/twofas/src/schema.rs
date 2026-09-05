use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TwoFasPayload {
    Object(TwoFasBackup),
    List(Vec<TwoFasService>),
}

#[derive(Debug, Deserialize, Default)]
pub struct TwoFasBackup {
    #[serde(default, rename = "schemaVersion")]
    pub schema_version: Option<u32>,
    #[serde(default, rename = "appVersionCode")]
    pub app_version_code: Option<u64>,
    #[serde(default, rename = "appVersionName")]
    pub app_version_name: Option<String>,
    #[serde(default, rename = "appOrigin")]
    pub app_origin: Option<String>,
    #[serde(default)]
    pub services: Vec<TwoFasService>,
    #[serde(default, rename = "servicesEncrypted")]
    pub services_encrypted: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TwoFasService {
    pub name: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<u64>,
    #[serde(default)]
    pub otp: TwoFasOtp,
    #[serde(default)]
    pub order: Option<TwoFasOrder>,
    #[serde(default)]
    pub badge: Option<serde_json::Value>,
    #[serde(default)]
    pub icon: Option<serde_json::Value>,
    #[serde(default, rename = "groupId")]
    pub group_id: Option<String>,
    #[serde(default, rename = "serviceTypeID")]
    pub service_type_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TwoFasOtp {
    pub link: Option<String>,
    pub label: Option<String>,
    pub account: Option<String>,
    pub issuer: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
    pub algorithm: Option<String>,
    pub counter: Option<u64>,
    #[serde(rename = "tokenType")]
    pub token_type: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TwoFasOrder {
    pub position: Option<i64>,
}
