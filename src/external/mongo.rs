use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};

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
pub const FIELD_CODE: &str = "code";
pub const FIELD_CHALLENGE_TYPE: &str = "type_challenge";
pub const FIELD_HOSTNAME: &str = "hostname";
pub const FIELD_CHALLENGE: &str = "challenge";
pub const FIELD_CORRELATION: &str = "correlation";
pub const FIELD_FINGERPRINT_PK: &str = "fingerprint_pk";

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
