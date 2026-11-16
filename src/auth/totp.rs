use crate::auth::webauthn::WebauthnChallengeRow;
use crate::external::mongo::NOM_COLLECTION_CHALLENGES;
use millegrilles_common_rust::base64_url;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::hachages::HachageCode;
use millegrilles_common_rust::millegrilles_cryptographie::hachages::hacher_bytes;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::v3::DocumentEncryptionService;
use totp_rs::{Algorithm, Secret, Builder};

pub struct GeneratedTotp {
    pub challenge_hashvalue: String,
    pub secret_base32: String,
    pub qr_base64: String,
}

pub async fn generate_totp<M,E>(
    mongo: &M,
    encryption: &E,
    username: &str,
    user_id: &str,
    hostname: &str
) -> Result<GeneratedTotp, CommonError> where M: MongoDaoTyped, E: DocumentEncryptionService {
    // Generate a new temporary TOTP for user_id
    let secret = Secret::generate();

    // Save the user_id/secret for potential new TOTP credentials.
    let authenticator_id = format!("{}", username);
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA512)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(hostname.into())
        .with_account_name(authenticator_id)
        .build()
        .map_err(|e| CommonError::String(format!("Error creating TOTP instance: {:?}", e)))?;

    let totp_url = totp.to_url().map_err(|e| CommonError::String(format!("Error parsing TOTP url: {:?}", e)))?;
    let challenge_hashvalue = base64_url::encode(&hacher_bytes(totp_url.as_bytes(), HachageCode::Blake2s256));

    // Encrypt the TOTP url, it contains the secret value
    let encrypted_url = encryption.encrypt(&totp_url).await?;

    let challenge_row = WebauthnChallengeRow::new_challenge_totp(user_id, hostname, &challenge_hashvalue, encrypted_url);
    let collection = mongo.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
    collection.insert_one(challenge_row).await?;

    let qr_base64 = totp.to_qr_base64()
        .map_err(|e| CommonError::String(format!("totp.get_qr_base64() Error: {:?}", e)))?;
    let secret_base32 = totp.secret().to_base32();

    Ok(GeneratedTotp {challenge_hashvalue, secret_base32, qr_base64})
}
