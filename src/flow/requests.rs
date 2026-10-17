use std::collections::HashMap;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::{Securite, DELEGATION_GLOBALE_PROPRIETAIRE, RolesCertificats};
use crate::external::mq::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::optionepochseconds;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::v3::ConfigService;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};
use millegrilles_common_rust::chrono::serde::{ts_seconds, ts_milliseconds, ts_seconds_option};
use crate::constants::DELEGATION_OWNER;
use crate::external::mongo::*;
use crate::external::webauthn::{prepare_registration, prepare_webauthn_authentication, WebauthnCredentialsRow};

pub async fn process_request<M>(
    config: &dyn ConfigService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where
    M: MongoDaoTyped,
{
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in request")).await
    };

    match wrapper.message.kind {
        MessageKind::Requete => {
            match action {
                REQUETE_CHARGER_USAGER => request_load_user(config, mongo, outbound, wrapper).await,
                REQUETE_LISTE_USAGERS => request_list_users(mongo, outbound, wrapper).await,
                REQUETE_USERID_PAR_NOMUSAGER => request_userid_by_username(mongo, outbound, wrapper).await,
                REQUETE_GET_CSR_RECOVERY_PARCODE => request_get_csr_recovery_bycode(mongo, outbound, wrapper).await,
                REQUETE_LISTE_PROPRIETAIRES => request_list_admins(mongo, outbound, wrapper).await,
                REQUETE_COOKIE_USAGER => request_user_cookie(mongo, outbound, wrapper).await,
                REQUETE_PASSKEYS_USAGER => request_user_passkeys(mongo, outbound, wrapper).await,
                _ => {
                    info!("Unknown action {} for process_request, skipping", action);
                    Ok(())
                }
            }
        },
        _ => {
            info!("Unhandled message type with action {} for process_request, skipping", action);
            Ok(())
        }
    }
}

#[derive(Deserialize)]
struct RequestLoaduser {
    /// User_id, utilise de preference.
    #[serde(rename="userId")]
    user_id: Option<String>,

    /// Nom usager, utilise si le user_id est absent.
    #[serde(rename="nomUsager")]
    nom_usager: Option<String>,

    /// Url du serveur qui fait la demande (du point de vue usager).
    /// Requis pour webauthn, agit comme flag pour generer un nouveau challenge d'authentification.
    #[serde(rename="hostUrl")]
    host_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserAccountResponse {
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,
    pub compte_prive: Option<bool>,
    pub delegation_globale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with="optionepochseconds")]
    pub delegations_date: Option<DateTime<Utc>>,
    pub delegations_version: Option<usize>,
}

impl From<UserAccountRow> for UserAccountResponse {
    fn from(value: UserAccountRow) -> Self {
        Self {
            nom_usager: value.nom_usager,
            user_id: value.user_id,
            compte_prive: value.compte_prive,
            delegation_globale: value.delegation_globale,
            delegations_date: value.delegations_date,
            delegations_version: value.delegations_version,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseLoaduser {
    ok: bool,
    err: Option<String>,
    compte: Option<UserAccountResponse>,
    activations: Option<HashMap<String, ActivationFingerprintPkUsagerRow>>,
    generic_challenge: Option<String>,
    registration_challenge: Option<CreationChallengeResponse>,
    authentication_challenge: Option<RequestChallengeResponse>,
    webauth_credentials_count: Option<usize>,
}

impl From<UserAccountRow> for ResponseLoaduser {
    fn from(value: UserAccountRow) -> Self {
        Self {
            ok: true,
            err: None,
            compte: Some(value.into()),
            activations: None,
            generic_challenge: None,
            registration_challenge: None,
            authentication_challenge: None,
            webauth_credentials_count: None,
        }
    }
}

async fn request_load_user<M>(
    config: &dyn ConfigService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let request: RequestLoaduser = wrapper.message.deserialize()?;

    let mut filtre = doc!{};

    // Le filtre utilise le user_id du certificat de preference (et ignore les parametres).
    // Pour un certificat de service (1.public), va utiliser les parametres.
    let is_admin = wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    if wrapper.certificate.verifier_exchanges(vec![Securite::L1Public])? || is_admin {
        if let Some(nom_usager) = request.nom_usager.as_ref() {
            filtre.insert(FIELD_USERNAME, nom_usager);
        }
        if let Some(user_id) = request.user_id.as_ref() {
            filtre.insert(FIELD_USER_ID, user_id);
        }
    }

    if filtre.len() == 0 {
        match wrapper.certificate.get_user_id()? {
            Some(u) => {
                filtre.insert(FIELD_USER_ID, u);
            },
            None => match wrapper.certificate.verifier_exchanges(vec![Securite::L1Public])? {
                true => {
                    if let Some(nom_usager) = request.nom_usager.as_ref() {
                        filtre.insert(FIELD_USERNAME, nom_usager);
                    }
                    if let Some(user_id) = request.user_id.as_ref() {
                        filtre.insert(FIELD_USER_ID, user_id);
                    }
                },
                false => return outbound.respond( wrapper.delivery_info, ErrorMessage::err_code(403, "Unauthorized request")).await
            }
        }
    }

    let collection = mongo.get_collection_typed::<UserAccountRow>(COLLECTION_NAME_ACCOUNTS)?;
    let account_row = match collection.find_one(filtre).await? {
        Some(row) => row,
        None => return outbound.respond( wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown account")).await
    };

    let mut response = ResponseLoaduser::from(account_row.clone());
    if let Some(account) = response.compte.as_ref() {
        // Load account authentication information
        let user_id = account.user_id.as_str();

        debug!("Load activations for account {}", user_id);
        let filtre = doc!{ FIELD_USER_ID: user_id };
        let collection = mongo.get_collection_typed::<ActivationFingerprintPkUsagerRow>(NOM_COLLECTION_ACTIVATIONS)?;
        let mut activations = HashMap::new();
        let mut curseur = collection.find(filtre).await?;
        while let Some(r) = curseur.next().await {
            let row = r?;
            activations.insert(row.fingerprint_pk.clone(), row);
        }
        response.activations = Some(activations);

        if let Some(host_url) = request.host_url.as_ref() {
            debug!("request_load_user host_url {}", host_url);
            let hostname = host_url;

            let registration_webauthn = prepare_registration(config, mongo, &account_row, hostname).await
                .map_err(|e| CommonError::String(format!("prepare_registration Error: {:?}", e)))?;
            response.registration_challenge = match registration_webauthn.get_registration_challenge() {
                Some(inner) => Some(inner.to_owned()),
                None => return outbound.respond(
                    wrapper.delivery_info,
                    ErrorMessage::err_code(500, "Bad challenge format (registration_challenge=None)")
                ).await
            };

            let (generic, challenge) =
                match prepare_webauthn_authentication(config, mongo, &account_row, hostname).await?
                {
                    Some(doc_challenge) => {
                        match doc_challenge.get_authentication_challenge() {
                            Some(inner) => {
                                // Dropping the passkey_authentication, it must not be sent as a response (private)
                                (None, Some(inner.to_owned()))
                            },
                            None => (Some(doc_challenge.challenge), None)
                        }
                    },
                    None => (None, None)
                };
            response.generic_challenge = generic;
            response.authentication_challenge = challenge;

            let collection_creds = mongo.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
            let filtre = doc!{ FIELD_USER_ID: &user_id };
            let credentials_count = collection_creds.count_documents(filtre).await?;
            response.webauth_credentials_count = Some(credentials_count as usize);

            debug!("charger_usager reponse {:?}", response);
        } else if ! is_admin {
            return outbound.respond(
                wrapper.delivery_info ,
                ErrorMessage::err_code(400, "host_url was not provided in user request")
            ).await
        }
    }

    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct RequestUserList {
    liste_userids: Option<Vec<String>>,
    nom_masque_debut: Option<String>,
}

#[derive(Serialize)]
struct ResponseUserList {
    ok: bool,
    complet: bool,
    usagers: Vec<UserAccountResponse>,
}

async fn request_list_users<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let request: RequestUserList = wrapper.message.deserialize()?;

    let mut filtre = doc! {};
    if let Some(userids) = &request.liste_userids {
        filtre.insert(FIELD_USER_ID, doc!{"$in": userids});
    }

    let collection = mongo.get_collection_typed::<UserAccountRow>(COLLECTION_NAME_ACCOUNTS)?;
    let mut curseur = collection
        .find(filtre)
        .projection(doc!{
            FIELD_USERNAME: true,
            FIELD_USER_ID: true,
            FIELD_PRIVATE_ACCOUNT: true,
            FIELD_IS_ADMIN: true,
        })
        .await?;

    let mut users: Vec<UserAccountResponse> = Vec::new();
    while let Some(account) = curseur.next().await {
        users.push(account?.into());
    }

    let response = ResponseUserList { ok: true, complet: true, usagers: users };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct RequestUserIdByUsername {
    noms_usagers: Vec<String>,
}

#[derive(Serialize)]
struct ResponseUserIdByUsername {
    ok: bool,
    usagers: HashMap<String, Option<String>>,
}

async fn request_userid_by_username<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let request: RequestUserIdByUsername = wrapper.message.deserialize()?;

    // Inserer tous les nom_usagers demandes avec None. Assurer de retourner la reponse complete
    // si certains usagers sont inconnus.
    let mut users: HashMap<String, Option<String>> = HashMap::new();
    for nom_usager in &request.noms_usagers {
        users.insert(nom_usager.into(), None);
    }

    let filtre = doc! { FIELD_USERNAME: {"$in": request.noms_usagers}};
    debug!("get_userid_par_nomusager Requete noms usagers, filtre : {:?}", filtre);
    let collection = mongo.get_collection_typed::<UserAccountRow>(COLLECTION_NAME_ACCOUNTS)?;
    let mut curseur = collection
        .find(filtre)
        .projection(doc! {
            FIELD_USERNAME: true,
            FIELD_USER_ID: true,
        })
        .await?;

    while let Some(account) = curseur.next().await {
        let account = account?;
        users.insert(account.nom_usager.clone(), Some(account.user_id.clone()));
    }

    let response = ResponseUserIdByUsername { ok: true, usagers: users };
    outbound.respond(wrapper.delivery_info, response).await
}


#[derive(Deserialize)]
struct RequestCsrRecoveryByCode {
    nom_usager: Option<String>,
    code: String,
}

#[derive(Serialize)]
struct ResponseCsrRecoveryByCode {
    ok: bool,
    #[serde(rename="nomUsager")]
    nom_usager: String,
    code: String,
    csr: String,
}

async fn request_get_csr_recovery_bycode<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let request: RequestCsrRecoveryByCode = wrapper.message.deserialize()?;

    // Verifier si on a un usager avec delegation globale (permet d'utiliser le parametre nom_usager)
    let collection_accounts = mongo.get_collection_typed::<UserAccountRow>(COLLECTION_NAME_ACCOUNTS)?;
    let effective_username = match (request.nom_usager, wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?) {
        (Some(username), true) => username,
        _ => match wrapper.certificate.get_user_id()? {
            Some(user_id) => {
                let filtre = doc! { FIELD_USER_ID: &user_id };
                match collection_accounts.find_one(filtre).await? {
                    Some(account) => account.nom_usager,
                    None => {
                        // Access refused, unknown username
                        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await;
                    }
                }
            },
            None => {
                // Access refused, wrong certificate (user_id property is required)
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await;
            }
        },
    };

    let filtre = doc! { FIELD_USERNAME: &effective_username, FIELD_CODE: &request.code };
    let collection_recovery = mongo.get_collection_typed::<RecoveryRow>(NOM_COLLECTION_RECOVERY)?;
    match collection_recovery.find_one(filtre).await? {
        Some(row) => {
            let response = ResponseCsrRecoveryByCode {
                ok: true,
                nom_usager: effective_username,
                code: request.code,
                csr: row.csr
            };
            outbound.respond(wrapper.delivery_info, response).await
        },
        None => outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "No match found")).await
    }
}

async fn request_list_admins<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let _request: RequestUserList = wrapper.message.deserialize()?;

    let filtre = doc! { FIELD_IS_ADMIN: DELEGATION_OWNER };
    let collection = mongo.get_collection_typed::<UserAccountRow>(COLLECTION_NAME_ACCOUNTS)?;
    let mut curseur = collection
        .find(filtre)
        .projection(doc! {
            FIELD_USERNAME: true,
            FIELD_USER_ID: true,
        })
        .await?;

    let mut accounts: Vec<UserAccountResponse> = Vec::new();
    while let Some(account) = curseur.next().await {
        accounts.push(account?.into());
    }

    let response = ResponseUserList { ok: true, complet: true, usagers: accounts };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct RequestGetUserCookie {
    user_id: String,
    hostname: String,
    challenge: String,
}

#[derive(Serialize)]
struct ResponseGetUserCookie {
    ok: bool,
    #[serde(rename="nomUsager")]
    username: String,
    cookie: CookieSessionResponse,
}

#[derive(Serialize)]
pub struct CookieSessionResponse {
    pub user_id: String,
    pub hostname: String,
    pub challenge: String,
    #[serde(with = "ts_seconds")]
    pub expiration: DateTime<Utc>,
}

impl From<CookieSessionRow> for CookieSessionResponse {
    fn from(value: CookieSessionRow) -> Self {
        Self {
            user_id: value.user_id,
            hostname: value.hostname,
            challenge: value.challenge,
            expiration: value.expiration,
        }
    }
}

async fn request_user_cookie<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let request: RequestGetUserCookie = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive])? ||
        ! wrapper.certificate.verifier_roles(vec![RolesCertificats::MaitreComptes, RolesCertificats::WebAuth])? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await;
    }

    let filter = doc! {
        "user_id": request.user_id,
        "hostname": request.hostname,
        "challenge": request.challenge,
    };
    let collection = mongo.get_collection_typed::<CookieSessionRow>(NOM_COLLECTION_COOKIES)?;
    let cookie: CookieSessionResponse = match collection.find_one(filter).await? {
        Some(cookie) => cookie.into(),
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Cookie not found")).await
    };

    // Get username
    let filter_user = doc! {FIELD_USER_ID: &cookie.user_id};
    let collection_users = mongo.get_collection_typed::<UserAccountRow>(COLLECTION_NAME_ACCOUNTS)?;
    let user_account = collection_users
        .find_one(filter_user)
        .projection(doc! { FIELD_USERNAME: true, FIELD_USER_ID: true })
        .await?;

    match user_account {
        Some(user_account) => {
            let response = ResponseGetUserCookie { ok: true, username: user_account.nom_usager, cookie };
            outbound.respond(wrapper.delivery_info, response).await
        },
        None => outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "User account not found")).await
    }
}

#[derive(Deserialize)]
struct RequestGetUserPasskeys {
    #[serde(rename="userId")]
    user_id: Option<String>,
}

#[derive(Serialize)]
struct PasskeyResponse {
    cred_id: String,
    hostname: String,
    #[serde(with="ts_seconds")]
    date_creation: DateTime<Utc>,
    #[serde(with="ts_seconds_option")]
    dernier_auth: Option<DateTime<Utc>>,
}

impl From<WebauthnCredentialsRow> for PasskeyResponse {
    fn from(value: WebauthnCredentialsRow) -> Self {
        let dernier_auth = match value.dernier_auth {
            Some(inner) => DateTime::from_timestamp(inner.timestamp_millis()/1000, 0),
            None => None
        };
        Self {
            cred_id: value.passkey.cred.cred_id,
            hostname: value.hostname,
            date_creation: DateTime::from_timestamp(value.date_creation.timestamp_millis()/1000, 0).unwrap(),
            dernier_auth
        }
    }
}

#[derive(Serialize)]
struct ActivationReponse {
    fingerprint_pk: String,
    #[serde(with="ts_seconds")]
    date_creation: DateTime<Utc>,
}

impl From<ActivationFingerprintPkUsagerRow> for ActivationReponse {
    fn from(value: ActivationFingerprintPkUsagerRow) -> Self {
        Self {
            fingerprint_pk: value.fingerprint_pk,
            date_creation: value.date_creation,
        }
    }
}


#[derive(Serialize)]
struct CookieReponse {
    hostname: String,
    #[serde(with="ts_seconds")]
    expiration: DateTime<Utc>,
    #[serde(with="ts_seconds_option")]
    date_creation: Option<DateTime<Utc>>,
}

impl From<CookieSessionRow> for CookieReponse {
    fn from(value: CookieSessionRow) -> Self {
        Self {
            hostname: value.hostname,
            expiration: value.expiration,
            date_creation: Some(value.date_creation),
        }
    }
}

#[derive(Serialize)]
struct ResponseGetUserPasskeys {
    ok: bool,
    user_id: String,
    passkeys: Vec<PasskeyResponse>,
    activations: Vec<ActivationReponse>,
    cookies: Vec<CookieReponse>
}

async fn request_user_passkeys<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let request: RequestGetUserPasskeys = wrapper.message.deserialize()?;

    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    };

    // For admins, allow requesting a different user_id
    let user_id = match wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true => match request.user_id {
            Some(inner) => inner,
            None => user_id.to_owned()
        },
        false => user_id.to_owned()
    };

    let filter = doc! { FIELD_USER_ID: &user_id };
    let mut passkeys: Vec<PasskeyResponse> = Vec::new();
    let collection = mongo.get_collection_typed::<WebauthnCredentialsRow>(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    let mut curseur = collection.find(filter.clone()).await?;
    while let Some(cred) = curseur.next().await {
        let cred = cred?;
        passkeys.push(cred.into());
    }

    let activations = {
        let mut activations: Vec<ActivationReponse> = Vec::new();
        let collection = mongo.get_collection_typed::<ActivationFingerprintPkUsagerRow>(NOM_COLLECTION_ACTIVATIONS)?;
        let mut curseur = collection.find(filter).await?;
        while let Some(activation) = curseur.next().await {
            let activation = activation?;
            activations.push(activation.into());
        }
        activations
    };

    let cookies: Vec<CookieReponse> = {
        let mut cookies = Vec::new();
        let collection = mongo.get_collection_typed::<CookieSessionRow>(NOM_COLLECTION_COOKIES)?;
        let filter = doc! { "user_id": &user_id };
        let mut curseur = collection.find(filter).await?;
        while let Some(cookie) = curseur.next().await {
            let cookie = cookie?;
            debug!("get_passkeys_usager Activation : {:?}", cookie);
            cookies.push(cookie.into());
        }

        cookies
    };

    let reponse = ResponseGetUserPasskeys { ok: true, user_id: user_id.to_owned(), passkeys, activations, cookies };
    outbound.respond(wrapper.delivery_info, reponse).await
}
