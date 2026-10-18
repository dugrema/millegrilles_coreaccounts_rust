use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::jwt_simple::prelude::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::{chrono, openssl, serde_json, uuid};
use millegrilles_common_rust::v3::ConfigService;
use millegrilles_common_rust::bson::serde_helpers::datetime::FromChrono04DateTime;
use millegrilles_common_rust::common_messages::DemandeSignature;
use millegrilles_common_rust::formatteur_messages::preparer_btree_recursif;
use millegrilles_common_rust::hachages::hacher_bytes_vu8;
use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::reqwest::Url;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::mongo_serde::option_chrono_04_datetime;
use millegrilles_common_rust::multihash::Code;
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::chrono::serde::{ts_seconds, ts_milliseconds, ts_seconds_option};
use webauthn_rs::prelude::{AuthenticationResult, Base64UrlSafeData, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RequestChallengeResponse};
use webauthn_rs::{Webauthn, WebauthnBuilder};
use crate::external::mongo::*;
use crate::error::Error as CoreError;

pub async fn prepare_registration<M>(
    config: &dyn ConfigService,
    mongo: &M,
    compte: &UserAccountRow,
    hostname: &str
) -> Result<WebauthnChallengeRow, CoreError> where M: MongoDaoTyped {
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
    let collection = mongo.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
    let doc_registration: WebauthnChallengeRow = match collection.find_one(filtre).await? {
        Some(inner) => inner,
        None => {
            let (challenge, registration) = generer_challenge_registration(
                rp_origin.as_str(), nom_usager, &user_uuid, idmg.as_str(), None::<&Vec<&str>>, // existing_credentials
            )?;
            let doc_registration = WebauthnChallengeRow::new_challenge_registration(
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
pub struct WebauthnChallengeRow {
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

impl WebauthnChallengeRow {
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
) -> Result<Option<WebauthnChallengeRow>, CommonError> where M: MongoDaoTyped {
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
        WebauthnChallengeRow::new_challenge_generique(user_id, hostname, valeur_challenge, "generique")

    } else {
        let (challenge, passkey_authentication) = match generer_challenge_authentification(
            hostname, idmg.as_str(), credentials) {
            Ok(inner) => inner,
            Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("preparer_authentification_webauthn Erreur {:?}", e)))?
        };

        WebauthnChallengeRow::new_challenge_authentication(user_id, hostname, challenge, passkey_authentication)
    };

    // Sauvegarder challenge
    let collection = mongo.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientAssertResponseContent {
    #[serde(rename="authenticatorData")]
    pub authenticator_data: Base64UrlSafeData,
    #[serde(rename="clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
    #[serde(rename="signature")]
    pub signature: Base64UrlSafeData,
    #[serde(rename="userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientAssertionResponse {
    pub id64: Base64UrlSafeData,
    pub response: ClientAssertResponseContent
}

impl TryInto<PublicKeyCredential> for ClientAssertionResponse {
    type Error = millegrilles_common_rust::error::Error;

    fn try_into(self) -> Result<PublicKeyCredential, Self::Error> {
        let id_b64 = &self.id64;
        let response = &self.response;

        let val = json!({
            "id": id_b64,
            "rawId": id_b64,
            "response": {
                "authenticatorData": &response.authenticator_data,
                "clientDataJSON": response.client_data_json,
                "signature": response.signature,
                "userHandle": &response.user_handle
            },
            "type": "public-key"
        });

        Ok(serde_json::from_value(val)?)
    }
}

/// Contains private information - must not leave this module
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PasskeyAuthenticationStateAjuste {
    credentials: Value,
    policy: Value,
    challenge: Base64UrlSafeData,
    appid: Option<String>,
    allow_backup_eligible_upgrade: bool
}

/// Contains private information - must not leave this module
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PasskeyAuthenticationAjuste {
    ast: PasskeyAuthenticationStateAjuste,
}

impl TryInto<PasskeyAuthentication> for PasskeyAuthenticationAjuste {
    type Error = millegrilles_common_rust::error::Error;

    fn try_into(self) -> Result<PasskeyAuthentication, Self::Error> {
        let value = serde_json::to_value(self)?;
        Ok(serde_json::from_value(value)?)
    }
}

impl TryFrom<PasskeyAuthentication> for PasskeyAuthenticationAjuste {
    type Error = millegrilles_common_rust::error::Error;

    fn try_from(value: PasskeyAuthentication) -> Result<Self, Self::Error> {
        let value_conv = serde_json::to_value(value)?;
        Ok(serde_json::from_value(value_conv)?)
    }
}

async fn load_authentication_challenge<M>(
    mongo: &M,
    user_id: &str,
    hostname: &str,
    challenge: &str
) -> Result<PasskeyAuthenticationAjuste, CommonError> where M: MongoDaoTyped {
    // Charger challenge correspondant
    let collection = mongo.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
    let filtre = doc! {
        FIELD_USER_ID: user_id,
        FIELD_HOSTNAME: hostname,
        FIELD_CHALLENGE_TYPE: "authentication",
        FIELD_CHALLENGE: challenge,
    };

    debug!("Charger challenge webauthn {:?}", filtre);
    let doc_challenge: WebauthnChallengeRow = match collection.find_one(filtre.clone()).await? {
        Some(inner) => inner,
        None => return Err(CommonError::Str("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn inconnu ou expire"))
    };

    let doc_webauth_state = match doc_challenge.webauthn_authentication {
        Some(inner) => inner,
        None => Err(format!("core_maitredescomptes.commande_authentifier_webauthn Challenge webauthn absent (None)"))?
    };

    Ok(doc_webauth_state.passkey_authentication.try_into()?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DemandeSignatureCertificatWebauthn {
    #[serde(rename="activationTierce", skip_serializing_if = "Option::is_none")]
    pub activation_tierce: Option<bool>,
    pub csr: String,
    #[serde(with = "ts_seconds")]
    pub date: DateTime<Utc>,
    #[serde(rename = "nomUsager")]
    pub nom_usager: String,
}

impl DemandeSignatureCertificatWebauthn {
    /// Valide le message et retourne un hachage du contenu.
    fn valider(&self) -> Result<Vec<u8>, CommonError> {

        // Le message recu est valide pour 5 minutes
        // (aussi 1 minute dans l'autre sens si clock mal ajustee)
        let date_now = Utc::now();
        let date_message = self.date;
        if date_now - chrono::Duration::minutes(5) > date_message ||
            date_now + chrono::Duration::minutes(1) < date_message {
            Err("core_maitredescomptes.DemandeSignatureCertificatWebauthn Date expire/invalide")?
        }

        // Calculer le hachage du message
        self.hacher()
    }

    fn hacher(&self) -> Result<Vec<u8>, CommonError> {
        let map = serde_json::to_value(&self)?.as_object().expect("value map").to_owned();
        let value_ordered = preparer_btree_recursif(map)?;
        let value_serialisee = serde_json::to_string(&value_ordered)?;
        let value_bytes = value_serialisee.as_bytes();
        Ok(hacher_bytes_vu8(value_bytes, Some(Code::Blake2s256)))
    }
}

pub async fn verify_authentication_challenge<M>(
    mongo: &M,
    user_id: &str,
    hostname: &str,
    challenge: &str,
    idmg: &str,
    request: &DemandeSignatureCertificatWebauthn,
    client_assertion_response: ClientAssertionResponse,
) -> Result<AuthenticationResult, CoreError> where M: MongoDaoTyped {
    let mut passkey_authentication = load_authentication_challenge(mongo, user_id, hostname, challenge).await?;

    debug!("commande_authentifier_usager Demande certificat recue : {:?}", request);
    let hachage = request.valider()?;
    debug!("commande_authentifier_usager Hachage calcule pour demande de certificat : {:?}", hachage);
    let challenge = &passkey_authentication.ast.challenge;
    debug!("commande_authentifier_usager Challenge existant : {:?} / {}", challenge, challenge.to_string());
    let mut vec_challenge_acjuste = Vec::new();
    vec_challenge_acjuste.extend_from_slice(&challenge.0[..]);
    vec_challenge_acjuste.extend(hachage);
    debug!("commande_authentifier_usager Hachage ajuste pour demande de certificat : {:?}", vec_challenge_acjuste);
    passkey_authentication.ast.challenge = Base64UrlSafeData::from(vec_challenge_acjuste);

    let reg: PublicKeyCredential = client_assertion_response.try_into()?;
    // let cred_id = reg.id.clone();
    let passkey_authentication: PasskeyAuthentication = passkey_authentication.try_into()?;

    let webauthn_value = build_webauthn(hostname, idmg)?;
    Ok(webauthn_value.finish_passkey_authentication(&reg, &passkey_authentication)?)
}

pub async fn preparer_challenge_generique<M>(
    mongo: &M,
    compte: &UserAccountRow,
    hostname: &str,
    type_challenge: &str
) -> Result<WebauthnChallengeRow, CommonError> where M: MongoDaoTyped {
    let user_id = compte.user_id.as_str();

    // Genrerate a 32 bytes challenge
    let valeur_challenge =  {
        let mut buffer_random = [0u8; 32];
        openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
        let challenge = buffer_random.to_vec();
        Base64UrlSafeData::from(challenge)
    };

    let doc_challenge = WebauthnChallengeRow::new_challenge_generique(user_id, hostname, valeur_challenge, type_challenge);
    let collection = mongo.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
    collection.insert_one(&doc_challenge).await?;

    Ok(doc_challenge)
}

pub async fn preparer_registration_webauthn<M>(
    mongo: &M,
    compte: &UserAccountRow,
    hostname: &str,
    idmg: &str,
) -> Result<WebauthnChallengeRow, CoreError> where M: MongoDaoTyped {
    let hostname = hostname.as_ref();
    let rp_origin = format!("https://{}/", hostname);
    let user_id = compte.user_id.as_str();
    let nom_usager = compte.nom_usager.as_str();
    let user_uuid = uuid::Uuid::new_v4().to_string();
    let filtre = doc! {
        FIELD_USER_ID: user_id,
        FIELD_CHALLENGE_TYPE: "registration",
        FIELD_HOSTNAME: &hostname,
    };
    let collection = mongo.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
    let doc_registration: WebauthnChallengeRow = match collection.find_one(filtre).await? {
        Some(inner) => inner,
        None => {
            let (challenge, registration) = generer_challenge_registration(
                rp_origin.as_str(), nom_usager, &user_uuid, idmg, None::<&Vec<&str>>, // existing_credentials
            )?;
            let doc_registration = WebauthnChallengeRow::new_challenge_registration(
                user_id, user_uuid.as_str(), hostname, challenge, registration);

            // Sauvegarder dans la base de donnees
            collection.insert_one(&doc_registration).await?;

            doc_registration
        }
    };

    Ok(doc_registration)
}

pub async fn preparer_authentification_webauthn<M>(
    middleware: &M,
    compte: &UserAccountRow,
    hostname: &str,
    idmg: &str
) -> Result<WebauthnChallengeRow, millegrilles_common_rust::error::Error> where M: MongoDaoTyped {
    let user_id = compte.user_id.as_str();

    // Charger credentials existants
    let collection = middleware.get_collection_typed::<CredentialWebauthn>(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    let filtre = doc! { FIELD_USER_ID: user_id, FIELD_HOSTNAME: hostname };
    let mut credentials = Vec::new();
    let mut curseur = collection.find(filtre).await?;
    while let Some(row) = curseur.next().await {
        credentials.push(row?);
    }

    let doc_challenge = if credentials.len() == 0 {
        debug!("preparer_authentification_webauthn Aucuns credentials webauthn pour {}/{}", user_id, hostname);
        let valeur_challenge =  {
            let mut buffer_random = [0u8; 32];
            openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
            let challenge = buffer_random.to_vec();
            Base64UrlSafeData::from(challenge)
        };
        WebauthnChallengeRow::new_challenge_generique(user_id, hostname, valeur_challenge, "generique")

    } else {
        let (challenge, passkey_authentication) = match generer_challenge_authentification(
            hostname, idmg, credentials) {
            Ok(inner) => inner,
            Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("preparer_authentification_webauthn Erreur {:?}", e)))?
        };

        WebauthnChallengeRow::new_challenge_authentication(user_id, hostname, challenge, passkey_authentication)
    };

    // Sauvegarder challenge
    let collection = middleware.get_collection_typed::<WebauthnChallengeRow>(NOM_COLLECTION_CHALLENGES)?;
    collection.insert_one(&doc_challenge).await?;

    Ok(doc_challenge)
}
