use std::collections::HashMap;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::constantes::{Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
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
use crate::external::mongo::*;
use crate::external::webauthn::{prepare_registration, prepare_webauthn_authentication};

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
                REQUETE_GET_CSR_RECOVERY_PARCODE => request_get_csr_recovery_passcode(mongo, outbound, wrapper).await,
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

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

async fn request_list_users<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!();
}

async fn request_userid_by_username<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!();
}

async fn request_get_csr_recovery_passcode<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!();
}

async fn request_list_admins<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!();
}

async fn request_user_cookie<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!();
}

async fn request_user_passkeys<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!();
}
