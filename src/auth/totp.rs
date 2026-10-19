use crate::auth::webauthn::WebauthnChallengeRow;
use crate::document_encryption::DocumentEncryptionService;
use crate::external::mongo::NOM_COLLECTION_CHALLENGES;
use millegrilles_common_rust::base64_url;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::hachages::HachageCode;
use millegrilles_common_rust::millegrilles_cryptographie::hachages::hacher_bytes;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use totp_rs::{Algorithm, Secret, TOTP};

pub struct GeneratedTotp {
    pub challenge_hashvalue: String,
    pub secret_base32: String,
    pub qr_base64: String,
}

pub async fn generate_totp<M>(
    mongo: &M,
    encryption: &DocumentEncryptionService,
    username: &str,
    user_id: &str,
    hostname: &str
) -> Result<GeneratedTotp, CommonError> where M: MongoDaoTyped {
    // Generate a new temporary TOTP for user_id
    let secret = Secret::generate_secret();

    // Save the user_id/secret for potential new TOTP credentials.
    let authenticator_id = format!("{}", username);
    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some(hostname.to_owned()),
        authenticator_id
    ).unwrap();
    let totp_url = totp.get_url();
    let challenge_hashvalue = base64_url::encode(&hacher_bytes(totp_url.as_bytes(), HachageCode::Blake2s256));

    // Encrypt the TOTP url, it contains the secret value
    let encrypted_url = encryption.encrypt(&totp_url).await?;

    let challenge_row = WebauthnChallengeRow::new_challenge_totp(user_id, hostname, &challenge_hashvalue, encrypted_url);
    let collection = mongo.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
    collection.insert_one(challenge_row).await?;

    let qr_base64 = totp.get_qr_base64()
        .map_err(|e| CommonError::String(format!("totp.get_qr_base64() Error: {:?}", e)))?;
    let secret_base32 = totp.get_secret_base32();

    Ok(GeneratedTotp {challenge_hashvalue, secret_base32, qr_base64})
}
