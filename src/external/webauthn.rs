use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::jwt_simple::prelude::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::{openssl, uuid};
use millegrilles_common_rust::v3::ConfigService;
use millegrilles_common_rust::bson::serde_helpers::datetime::FromChrono04DateTime;
use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::mongo_serde::option_chrono_04_datetime;
use webauthn_rs::prelude::{Base64UrlSafeData, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, RequestChallengeResponse};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use crate::external::mongo::*;
use crate::error::Error as CoreError;

pub async fn prepare_registration<M>(
    config: &dyn ConfigService,
    mongo: &M,
    compte: &UserAccountRow,
    hostname: &str
) -> Result<WebauthnChallenge, CoreError> where M: MongoDaoTyped {
    let hostname = hostname.as_ref();
    let rp_origin = format!("https://{}/", hostname);
    let user_id = compte.user_id.as_str();
    let nom_usager = compte.nom_usager.as_str();
    let user_uuid = uuid::Uuid::new_v4().to_string();
    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;
    let filtre = doc! {
        FIELD_USER_ID: user_id,
        FIELD_CHALLENGE_TYPE: "registration",
        FIELD_HOSTNAME: &hostname,
    };
    let collection = mongo.get_collection_typed::<WebauthnChallenge>(NOM_COLLECTION_CHALLENGES)?;
    let doc_registration: WebauthnChallenge = match collection.find_one(filtre).await? {
        Some(inner) => inner,
        None => {
            let (challenge, registration) = generer_challenge_registration(
                rp_origin.as_str(), nom_usager, &user_uuid, idmg.as_str(), None::<&Vec<&str>>, // existing_credentials
            )?;
            let doc_registration = WebauthnChallenge::new_challenge_registration(
                user_id, user_uuid.as_str(), hostname, challenge, registration);

            // Save registration challenge
            collection.insert_one(&doc_registration).await?;

            doc_registration
        }
    };

    Ok(doc_registration)
}

#[derive(Serialize, Deserialize)]
struct ChallengeRegistrationWebauthn {
    user_uuid: String,
    registration_challenge: CreationChallengeResponse,
    /// Secret value, must remain server-side
    registration_state: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
struct ChallengeAuthenticationWebauthn {
    authentication_challenge: RequestChallengeResponse,
    /// Private, must not be exposed
    passkey_authentication: PasskeyAuthentication,
}

#[derive(Serialize, Deserialize)]
pub struct WebauthnChallenge {
    #[serde(rename="userId")]
    pub user_id: String,
    pub type_challenge: String,
    pub hostname: String,
    pub challenge: String,

    #[serde(rename="_mg-creation", with="FromChrono04DateTime")]
    pub date_creation: DateTime<Utc>,

    /// Pour une registration webauthn (private)
    webauthn_registration: Option<ChallengeRegistrationWebauthn>,

    /// Pour une authentification webauthn (private)
    webauthn_authentication: Option<ChallengeAuthenticationWebauthn>,

    /// TOTP configuration
    pub totp_url_encrypted: Option<EncryptedDocument>,
}

impl WebauthnChallenge {
    pub fn new_challenge_registration(
        user_id: &str,
        user_uuid: &str,
        hostname: &str,
        challenge: CreationChallengeResponse,
        registration: PasskeyRegistration
    ) -> Self {
        let webauthn_registration = ChallengeRegistrationWebauthn {
            user_uuid: user_uuid.into(),
            registration_challenge: challenge,
            registration_state: registration,
        };

        let challenge = webauthn_registration.registration_challenge.public_key.challenge.to_string();

        Self {
            user_id: user_id.into(),
            type_challenge: "registration".to_string(),
            hostname: hostname.into(),
            challenge,
            date_creation: Utc::now(),
            webauthn_registration: Some(webauthn_registration),
            webauthn_authentication: None,
            totp_url_encrypted: None,
        }
    }

    pub fn new_challenge_authentication(
        user_id: &str,
        hostname: &str,
        authentication_challenge: RequestChallengeResponse,
        passkey_authentication: PasskeyAuthentication
    ) -> Self {
        let challenge = authentication_challenge.public_key.challenge.to_string();

        let webauthn_authentication = ChallengeAuthenticationWebauthn {
            authentication_challenge, passkey_authentication };

        Self {
            user_id: user_id.into(),
            type_challenge: "authentication".to_string(),
            hostname: hostname.into(),
            challenge,
            date_creation: Utc::now(),
            webauthn_registration: None,
            webauthn_authentication: Some(webauthn_authentication),
            totp_url_encrypted: None,
        }
    }

    pub fn new_challenge_generique(
        user_id: &str,
        hostname: &str,
        challenge: Base64UrlSafeData,
        type_challenge: &str
    ) -> Self {
        let type_challenge = type_challenge.into();
        let challenge = challenge.to_string();

        Self {
            user_id: user_id.into(),
            type_challenge,
            hostname: hostname.into(),
            challenge,
            date_creation: Utc::now(),
            webauthn_registration: None,
            webauthn_authentication: None,
            totp_url_encrypted: None,
        }
    }

    pub fn new_challenge_totp(user_id: &str, hostname: &str, challenge: &str, encrypted_url: EncryptedDocument) -> Self {
        Self {
            user_id: user_id.into(),
            type_challenge: "totp".to_string(),
            hostname: hostname.into(),
            challenge: challenge.into(),
            date_creation: Utc::now(),
            webauthn_registration: None,
            webauthn_authentication: None,
            totp_url_encrypted: Some(encrypted_url)
        }
    }

    /// Accessor to avoid exposing the passkey_authentication (private)
    pub fn get_authentication_challenge(&self) -> Option<&RequestChallengeResponse> {
        match self.webauthn_authentication.as_ref() {
            Some(inner) => Some(&inner.authentication_challenge),
            None => None,
        }
    }

    /// Accessor to avoid exposing the registration_state
    pub fn get_registration_challenge(&self) -> Option<&CreationChallengeResponse> {
        match self.webauthn_registration.as_ref() {
            Some(inner) => Some(&inner.registration_challenge),
            None => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CredentialWebauthn {
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
    passkey: Passkey,
    #[serde(skip_serializing_if = "Option::is_none", with="option_chrono_04_datetime")]
    date_creation: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", with="option_chrono_04_datetime")]
    derniere_utilisation: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset_cles: Option<bool>,
}

fn generer_challenge_registration(
    rp_origin: &str,
    user_name: &str,
    user_uuid: &str,
    idmg: &str,
    existing_credentials: Option<&Vec<&str>>
) -> Result<(CreationChallengeResponse, PasskeyRegistration), CoreError> {
    let rp_origin_str = rp_origin.as_ref();
    let idmg = idmg.as_ref();
    debug!("generer_challenge_registration builder webauthn avec rp_origin: {}", rp_origin_str);
    let rp_origin = Url::parse(rp_origin_str)?;
    let rp_id = match rp_origin.host_str() {
        Some(inner) => inner,
        None => Err(format!("webauthn generer_challenge_registration Format url rp invalide : {}", rp_origin_str))?
    };
    debug!("generer_challenge_registration builder webauthn rp_origin parsed: {}", rp_origin);
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?
        .rp_name(idmg);
    let webauthn = builder.build()?;

    debug!("generer_challenge_registration Challenge genere : {:?}", webauthn);

    let user_uuid = uuid::Uuid::parse_str(user_uuid.as_ref())?;
    let user_name = user_name.as_ref();

    // Convertir existing credentials (si applicable)
    let credentials = match existing_credentials {
        Some(inner) => {
            let creds_str: Vec<&str> = inner.into_iter().map(|c| (*c).as_ref()).collect();
            let mut creds = Vec::new();
            for c in creds_str.into_iter() {
                let cred_uuid = match CredentialID::try_from(c) {
                    Ok(inner) => inner,
                    Err(e) => {
                        info!("Erreur parsing credential existing (SKIP) : {:?}", e);
                        continue;
                    }
                };
                creds.push(cred_uuid);
            }
            Some(creds)
        },
        None => None
    };

    let (challenge, passkey_registration) =
        webauthn.start_passkey_registration(
            user_uuid,
            user_name, user_name, credentials
        ).map_err(|e| CommonError::String(format!("Error in start_passkey_registration: {:?}", e)))?;

    debug!("challenge : {:?}", challenge);
    debug!("registration : {:?}", passkey_registration);

    Ok((challenge, passkey_registration))
}

pub async fn prepare_webauthn_authentication<M>(
    config: &dyn ConfigService,
    mongo: &M,
    compte: &UserAccountRow,
    hostname: &str
) -> Result<Option<WebauthnChallenge>, CommonError> where M: MongoDaoTyped {
    let hostname = hostname.as_ref();
    let user_id = compte.user_id.as_str();
    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    // Charger credentials existants
    let collection = mongo.get_collection_typed::<CredentialWebauthn>(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    let filtre = doc! { FIELD_USER_ID: user_id, "hostname": hostname };
    let mut credentials = Vec::new();
    let mut curseur = collection.find(filtre).await?;
    while let Some(cred) = curseur.next().await {
        credentials.push(cred?);
    }

    let doc_challenge = if credentials.len() == 0 {
        debug!("preparer_authentification_webauthn Aucuns credentials webauthn pour {}/{}", user_id, hostname);
        let valeur_challenge =  {
            let mut buffer_random = [0u8; 32];
            openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
            let challenge = buffer_random.to_vec();
            Base64UrlSafeData::from(challenge)
        };
        WebauthnChallenge::new_challenge_generique(user_id, hostname, valeur_challenge, "generique")

    } else {
        let (challenge, passkey_authentication) = match generer_challenge_authentification(
            hostname, idmg.as_str(), credentials) {
            Ok(inner) => inner,
            Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("preparer_authentification_webauthn Erreur {:?}", e)))?
        };

        WebauthnChallenge::new_challenge_authentication(user_id, hostname, challenge, passkey_authentication)
    };

    // Sauvegarder challenge
    let collection = mongo.get_collection_typed::<WebauthnChallenge>(NOM_COLLECTION_CHALLENGES)?;
    collection.insert_one(&doc_challenge).await?;

    Ok(Some(doc_challenge))
}

fn generer_challenge_authentification(
    hostname: &str,
    idmg: &str,
    creds: Vec<CredentialWebauthn>
) -> Result<(RequestChallengeResponse, PasskeyAuthentication), CoreError> {
    let idmg = idmg.as_ref();
    let hostname = hostname.as_ref();
    let webauthn = build_webauthn(hostname, idmg)?;

    let passkeys: Vec<Passkey> = creds.into_iter().map(|p| p.passkey).collect();

    let resultat = webauthn.start_passkey_authentication(&passkeys[..])?;
    Ok(resultat)
}

fn build_webauthn(hostname: &str, idmg: &str) -> Result<Webauthn, CoreError> {
    let idmg = idmg.as_ref();
    let rp_id = hostname.as_ref();
    let rp_origin = Url::parse(format!("https://{}/", rp_id).as_str())?;
    debug!("generer_challenge_registration builder webauthn rp_origin parsed: {}", rp_origin);
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?
        .rp_name(idmg);

    let webauthn = builder.build()?;
    Ok(webauthn)
}

#[derive(Clone, Debug, Deserialize)]
pub struct PasskeyAuthenticationCred2 {
    pub cred_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PasskeyAuthenticationCred {
    pub cred: PasskeyAuthenticationCred2
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct WebauthnCredentialsRow {
    #[serde(rename="userId")]
    pub user_id: String,
    pub hostname: String,
    #[serde(with = "FromChrono04DateTime")]
    pub date_creation: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none", with="option_chrono_04_datetime")]
    pub dernier_auth: Option<DateTime<Utc>>,
    pub passkey: PasskeyAuthenticationCred,
}
