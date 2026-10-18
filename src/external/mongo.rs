use millegrilles_common_rust::{base64_url, bson, chrono, openssl};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::mongo_serde::option_chrono_04_datetime;
use millegrilles_common_rust::bson::serde_helpers::datetime::FromChrono04DateTime;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, RequestChallengeResponse};

pub const COLLECTION_NAME_REDOLOG: &str = "CoreAccounts/redolog";
pub const COLLECTION_NAME_TRACKING: &str = "CoreAccounts/tracking";
pub const COLLECTION_NAME_ACCOUNTS: &str = "CoreAccounts/accounts";
pub const NOM_COLLECTION_RECOVERY: &str = "CoreAccounts/recovery";
pub const NOM_COLLECTION_ACTIVATIONS: &str = "CoreAccounts/activations";
pub const NOM_COLLECTION_CHALLENGES: &str = "CoreAccounts/challenges";
pub const NOM_COLLECTION_WEBAUTHN_CREDENTIALS: &str = "CoreAccounts/webauthnCredentials";
pub const NOM_COLLECTION_TOTP_CREDENTIALS: &str = "CoreAccounts/totpCredentials";
pub const NOM_COLLECTION_COOKIES: &str = "CoreAccounts/cookies";


pub const INDEX_REDO_LOG_ID: &str = "redo_log_id";
pub const INDEX_RECOVERY_UNIQUE: &str = "recovery_unique";
pub const INDEX_CHALLENGES_UNIQUE: &str = "challenges_unique";
pub const INDEX_WEBAUTHN_UNIQUE: &str = "webauthn_unique";
pub const INDEX_COOKIE_UNIQUE: &str = "cookie_unique";
pub const INDEX_TOTP_UNIQUE: &str = "totp_unique";

pub const FIELD_USER_ID: &str = "userId";
pub const FIELD_USERNAME: &str = "nomUsager";
pub const FIELD_PRIVATE_ACCOUNT: &str = "compte_prive";
pub const FIELD_IS_ADMIN: &str = "delegation_globale";
pub const FIELD_CODE: &str = "code";
pub const FIELD_CHALLENGE_TYPE: &str = "type_challenge";
pub const FIELD_HOSTNAME: &str = "hostname";
pub const FIELD_CHALLENGE: &str = "challenge";
pub const FIELD_CORRELATION: &str = "correlation";
pub const FIELD_FINGERPRINT_PK: &str = "fingerprint_pk";
pub const FIELD_DATE_CREATED: &str = "created";
pub const FIELD_DATE_MODIFIED: &str = "last_modified";
pub const FIELD_LAST_AUTH: &str = "last_successful_authentication";
pub const FIELD_DELEGATION_GLOBALE: &str = "delegation_globale";
pub const FIELD_DELEGATION_VERSION: &str = "delegations_version";
pub const FIELD_DELEGATION_DATE: &str = "delegations_date";
pub const FIELD_WEBAUTHN: &str = "webauthn";

pub async fn create_index_mongodb(db: &dyn MongoDao) -> Result<(), CommonError> {
    db.create_index(
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_REDO_LOG_ID)), unique: true }),
    ).await?;

    db.create_index(
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_DATE_PROCESSED)), unique: false }),
    ).await?;

    db.create_index(
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_BID), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_BID)), unique: true }),
    ).await?;

    db.create_index(
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_DATE_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_DATE_PROCESSED)), unique: false })
    ).await?;

    db.create_index(
        COLLECTION_NAME_ACCOUNTS,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_USER_ID), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(FIELD_USER_ID)), unique: true })
    ).await?;

    db.create_index(
        COLLECTION_NAME_ACCOUNTS,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_USERNAME), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(FIELD_USERNAME)), unique: true })
    ).await?;

    db.create_index(
        NOM_COLLECTION_RECOVERY,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_USERNAME), direction: 1 },
            ChampIndex { nom_champ: String::from(FIELD_CODE), direction: 1 },
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_RECOVERY_UNIQUE)), unique: true })
    ).await?;

    db.create_index(
        NOM_COLLECTION_CHALLENGES,
        vec!(
            ChampIndex {nom_champ: String::from(FIELD_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_CHALLENGE_TYPE), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_HOSTNAME), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_CHALLENGE), direction: 1},
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_CHALLENGES_UNIQUE)), unique: true })
    ).await?;

    db.create_index(
        NOM_COLLECTION_WEBAUTHN_CREDENTIALS,
        vec!(
            ChampIndex {nom_champ: String::from(FIELD_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_HOSTNAME), direction: 1},
            ChampIndex {nom_champ: String::from("passkey.cred.cred_id"), direction: 1},
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_WEBAUTHN_UNIQUE)), unique: true })
    ).await?;

    db.create_index(
        NOM_COLLECTION_COOKIES,
        vec!(
            ChampIndex {nom_champ: String::from(FIELD_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_HOSTNAME), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_CHALLENGE), direction: 1},
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_COOKIE_UNIQUE)), unique: true })
    ).await?;

    db.create_index(
        NOM_COLLECTION_TOTP_CREDENTIALS,
        vec!(
            ChampIndex {nom_champ: String::from(FIELD_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_CORRELATION), direction: 1},
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_TOTP_UNIQUE)), unique: true })
    ).await?;

    db.create_index(
        NOM_COLLECTION_ACTIVATIONS,
        vec!(
            ChampIndex {nom_champ: String::from(FIELD_USER_ID), direction: 1},
            ChampIndex {nom_champ: String::from(FIELD_FINGERPRINT_PK), direction: 1},
        ),
        Some(IndexOptions { nom_index: Some(String::from(INDEX_TOTP_UNIQUE)), unique: true })
    ).await?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserAccountRow {
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,
    pub compte_prive: Option<bool>,
    pub delegation_globale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with="option_chrono_04_datetime")]
    pub delegations_date: Option<DateTime<Utc>>,
    pub delegations_version: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivationFingerprintPkUsagerRow {
    #[serde(rename="userId")]
    pub user_id: String,
    pub fingerprint_pk: String,
    #[serde(with = "FromChrono04DateTime")]
    pub created: DateTime<Utc>,
    pub certificat: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryRow {
    #[serde(rename="nomUsager")]
    pub username: String,
    pub code: String,
    pub csr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CookieSessionRow {
    pub user_id: String,
    pub hostname: String,
    pub challenge: String,
    #[serde(with = "FromChrono04DateTime")]
    pub created: DateTime<Utc>,
    #[serde(with = "FromChrono04DateTime")]
    pub expiration: DateTime<Utc>,
}

impl CookieSessionRow {
    pub fn new(user_id: &str, hostname: &str, duree_session: i64) -> Self {
        let date_expiration = Utc::now() + chrono::Duration::seconds(duree_session);

        let mut buffer_challenge = [0u8; 32];
        openssl::rand::rand_bytes(&mut buffer_challenge).expect("openssl::random::rand_bytes");
        let challenge = base64_url::encode(&buffer_challenge[..]);

        Self {
            user_id: user_id.into(),
            hostname: hostname.into(),
            challenge,
            created: Utc::now(),
            expiration: date_expiration,
        }
    }
}

pub async fn load_user_by_id(mongo: &dyn MongoDao, user_id: &str) -> Result<Option<UserAccountRow>, CommonError> {
    let filtre = doc! { FIELD_USER_ID: user_id };
    let collection = mongo.get_collection(COLLECTION_NAME_ACCOUNTS)?;
    match collection.find_one(filtre).await? {
        Some(c) => Ok(Some(bson::deserialize_from_document(c)?)),
        None => Ok(None)
    }
}

pub async fn check_user_existence(mongo: &dyn MongoDao, username: &str) -> Result<bool, CommonError> {
    let collection = mongo.get_collection(COLLECTION_NAME_ACCOUNTS)?;
    let filter = doc!{ FIELD_USERNAME: username };
    let exists = collection
        .find_one(filter)
        .projection(doc! {FIELD_USER_ID: true})
        .await?.is_some();
    Ok(exists)
}
