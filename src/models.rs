use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::jwt_simple::prelude::Deserialize;
use millegrilles_common_rust::chrono::serde::ts_seconds;
use serde::Serialize;
use crate::external::mongo::CookieSessionRow;

#[derive(Serialize)]
pub struct EventAccountActivation {
    pub fingerprint_pk: String,
    pub certificat: String,
}

#[derive(Serialize, Deserialize)]
pub struct CookieSession {
    pub user_id: String,
    pub hostname: String,
    pub challenge: String,
    #[serde(with = "ts_seconds")]
    pub expiration: DateTime<Utc>,
}

impl From<CookieSessionRow> for CookieSession {
    fn from(row: CookieSessionRow) -> Self {
        Self {
            user_id: row.user_id,
            hostname: row.hostname,
            challenge: row.challenge,
            expiration: row.expiration,
        }
    }
}
