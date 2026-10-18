use millegrilles_common_rust::{bson, serde_json};
use millegrilles_common_rust::bson::doc;
use crate::external::mongo::*;
use crate::external::mq::*;
use crate::external::webauthn::{preparer_challenge_generique, verify_certificate_signature_challenge, ClientAssertionResponse, DemandeSignatureCertificatWebauthn, preparer_registration_webauthn, preparer_authentification_webauthn, verify_authentication_challenge};
use crate::flow::certificates::{ajouter_fingerprint_pk_usager, signer_certificat_usager, signer_demande_certificat_usager};
use crate::flow::transactions::{AccountsTransactionService, TransactionInscrireUsager, TransactionResetWebauthnUsager, TransactionSupprimerCles};
use millegrilles_common_rust::certificats::{charger_csr, VerificateurPermissions, get_csr_subject, calculer_fingerprint_pk, csr_calculer_fingerprintpk};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::common_messages::ReponseSignatureCertificat;
use millegrilles_common_rust::constantes::{Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesOwned};
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tracing::{debug, error, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService, PkiService};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, TOTP, Secret};
use webauthn_rs::prelude::{Base64UrlSafeData, CreationChallengeResponse, PasskeyAuthentication, PublicKeyCredential, RequestChallengeResponse};
use crate::auth::cookie::creer_session_cookie;
use crate::auth::totp::generate_totp;
use crate::constants::{DOMAIN_NAME, EVENEMENT_EVICT_USAGER, EVENEMENT_INSCRIRE_COMPTE_USAGER};
use crate::flow::events::emettre_maj_compte_usager;
use crate::models::{CookieSession, EvictUserEvent};

pub async fn process_command<M>(
    config: &dyn ConfigService,
    pki: &dyn PkiService,
    chiffrage: &dyn ChiffrageService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where
    M: MongoDaoTyped,
{
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };

    match wrapper.message.kind {
        MessageKind::Commande => {
            match action {
                COMMANDE_SIGNER_COMPTEUSAGER => sign_user_account(config, pki, mongo, outbound, wrapper).await,
                COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE => sign_account_by_admin(pki, mongo, outbound, wrapper).await,
                COMMANDE_AJOUTER_CSR_RECOVERY => add_csr_recovery(outbound, mongo, wrapper).await,
                COMMANDE_AUTHENTIFIER_WEBAUTHN => authenticate_webauthn(config, pki, mongo, outbound, wrapper).await,
                COMMAND_AUTHENTICATE_TOTP => authenticate_totp(outbound, wrapper).await,
                COMMANDE_GENERER_CHALLENGE => generate_challenge(config, mongo, outbound, wrapper).await,
                COMMAND_GENERATE_OTP => generate_otp(mongo, outbound, wrapper).await,
                COMMANDE_SUPPRIMER_COOKIE => delete_cookie(mongo, outbound, wrapper).await,
                _ => {
                    info!("Unknown action {} for process_command, skipping", action);
                    Ok(())
                }
            }
        },
        _ => {
            info!("Unhandled message type with action {} for process_command, skipping", action);
            Ok(())
        }
    }


}

#[derive(Clone, Debug, Deserialize)]
struct CommandSignCertificate {
    #[serde(rename="demandeCertificat")]
    demande_certificat: DemandeSignatureCertificatWebauthn,

    // Champs pour demande de signature avec preuve webauthn
    challenge: String,
    hostname: String,

    /// Reponse webauthn
    #[serde(rename="clientAssertionResponse")]
    client_assertion_response: ClientAssertionResponse,
}

async fn sign_user_account<M>(
    config: &dyn ConfigService,
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let command: CommandSignCertificate = wrapper.message.deserialize()?;

    let account = match wrapper.certificate.get_user_id()? {
        Some(user_id) => match load_user_by_id(mongo, user_id.as_str()).await? {
            Some(account) => account,
            None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown account")).await
        },
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "No user ID provided in command")).await
    };

    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    match verify_certificate_signature_challenge(
        mongo,
        account.user_id.as_str(),
        command.hostname.as_str(),
        command.challenge.as_str(),
        idmg.as_str(),
        &command.demande_certificat,
        command.client_assertion_response,
    ).await {
        Ok(_inner) => (),  // Ok, no error
        Err(e) => {
            error!("verify_authentication_challenge Error: {:?}", e);
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Error verifying the signature")).await
        }
    }

    let response = signer_demande_certificat_usager(
        pki,
        mongo,
        outbound,
        &account,
        &command.demande_certificat
    ).await?;

    // Relay the response as-is
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct CommandeSignerCertificatParProprietaire {
    #[serde(rename="userId")]
    user_id: String,
    #[serde(rename="demandeCertificat")]
    demande_certificat: DemandeSignatureCertificatWebauthn,
}

async fn sign_account_by_admin<M>(
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {

    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    let command: CommandeSignerCertificatParProprietaire = wrapper.message.deserialize()?;
    let account = match load_user_by_id(mongo, command.user_id.as_str()).await? {
        Some(account) => account,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown user account")).await
    };

    let response = signer_demande_certificat_usager(
        pki,
        mongo,
        outbound,
        &account,
        &command.demande_certificat
    ).await?;

    // Relay the response as-is
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct CommandeAjouterCsrRecovery {
    csr: String,
    #[serde(rename="nomUsager")]
    nom_usager: String,
}

#[derive(Serialize)]
struct ResponseAjouterCsrRecovery {
    ok: bool,
    code: String,
}

async fn add_csr_recovery(
    outbound: &MessageOutboundFacade,
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let command: CommandeAjouterCsrRecovery = wrapper.message.deserialize()?;

    // Charger CSR et calculer fingerprint, code.
    let csr_parsed = charger_csr(command.csr.as_str())?;
    let csr_subject = get_csr_subject(&csr_parsed.as_ref())?;
    if csr_subject.get("commonName").is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Missing common name")).await
    };

    let cle_publique = csr_parsed.public_key()?;
    let fingerprint = calculer_fingerprint_pk(&cle_publique)?;
    let len_fingerprint = fingerprint.len();
    let fingerprint_lc = fingerprint.to_lowercase();
    let code_part1 = &fingerprint_lc[len_fingerprint - 8..len_fingerprint - 4];
    let code_part2 = &fingerprint_lc[len_fingerprint - 4..len_fingerprint];
    let code = format!("{}-{}", code_part1, code_part2);
    debug!("Code : {}", code);

    let filtre = doc! {
        "code": &code,
        "nomUsager": &command.nom_usager,
    };
    let ops = doc! {
        "$set": { "csr": &command.csr },
        "$setOnInsert": { FIELD_DATE_CREATED: bson::datetime::DateTime::now() },
        "$currentDate": { FIELD_DATE_MODIFIED: true },
    };
    let collection = mongo.get_collection(NOM_COLLECTION_RECOVERY)?;
    let _resultat = collection.update_one(filtre, ops).upsert(true).await?;

    let response = ResponseAjouterCsrRecovery { ok: true, code };
    outbound.respond(wrapper.delivery_info, response).await
}


#[derive(Clone, Serialize, Deserialize)]
struct ResponseChallengeAuthenticationWebauthn {
    #[serde(rename = "authenticatorData")]
    authenticator_data: Base64UrlSafeData,
    #[serde(rename = "clientDataJSON")]
    client_data_json: Base64UrlSafeData,
    signature: Base64UrlSafeData,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct ClientAuthentificationWebauthn {
    id64: Base64UrlSafeData,
    response: ResponseChallengeAuthenticationWebauthn,
    #[serde(rename = "type")]
    type_: Option<String>,
}

impl TryInto<PublicKeyCredential> for ClientAuthentificationWebauthn {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<PublicKeyCredential, Self::Error> {
        let id = self.id64;

        let pk_json = json!({
            "id": &id,
            "rawId": id,
            "response": self.response,
            "extensions": {},
            "type": self.type_,
        });

        Ok(serde_json::from_value(pk_json)?)
    }
}

#[derive(Deserialize)]
struct CommandeClientAuthentificationWebauthn {
    #[serde(rename = "demandeCertificat")]
    demande_certificat: Option<DemandeSignatureCertificatWebauthn>,
    #[serde(rename = "dureeSession", skip_serializing_if = "Option::is_none")]
    duree_session: Option<i64>,
    webauthn: ClientAuthentificationWebauthn,
}

#[derive(Deserialize)]
struct CommandeAuthentificationUsager {
    #[serde(rename="userId")]
    user_id: String,
    hostname: String,
    challenge: String,
    #[serde(rename="reponseWebauthn")]
    commande_webauthn: CommandeClientAuthentificationWebauthn,
}

#[derive(Serialize)]
struct ResponseAuthentificateUser {
    ok: bool,
    counter: u32,
    #[serde(rename = "userVerification")]
    user_verified: bool,
    certificat: Option<Vec<String>>,
    cookie: Option<CookieSession>,
}

async fn authenticate_webauthn<M>(
    config: &dyn ConfigService,
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let command: CommandeAuthentificationUsager = wrapper.message.deserialize()?;

    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    // Keep cred_id for database usage
    let reg: PublicKeyCredential = command.commande_webauthn.webauthn.clone().try_into()?;
    let cred_id = reg.id;

    // Check that the user account exists
    let user_account = match load_user_by_id(mongo, command.user_id.as_str()).await? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown user account")).await
    };

    let auth_result = match verify_authentication_challenge(
        mongo,
        command.user_id.as_str(),
        command.hostname.as_str(),
        command.challenge.as_str(),
        idmg.as_str(),
        command.commande_webauthn.demande_certificat.as_ref(),
        command.commande_webauthn.webauthn.try_into()
            .map_err(|e| CommonError::Str("Error mapping command.commande_webauthn.webauthn to ClientAuthentificationWebauthn"))?,
    ).await {
        Ok(result) => result,
        Err(e) => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    };

    // Supprimer challenge pour eviter reutilisation
    let collection = mongo.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let filtre = doc! {
        FIELD_USER_ID: &command.user_id,
        FIELD_HOSTNAME: &command.hostname,
        FIELD_CHALLENGE_TYPE: "authentication",
        FIELD_CHALLENGE: &command.challenge,
    };
    collection.delete_one(filtre).await?;

    // Conserver dernier acces pour la passkey
    let collection = mongo.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    let filtre = doc! {
        FIELD_USER_ID: &command.user_id,
        FIELD_HOSTNAME: &command.hostname,
        "passkey.cred.cred_id": cred_id,
    };
    let ops = doc! { "$set": { FIELD_LAST_AUTH: Utc::now() } };
    collection.update_one(filtre, ops).await?;

    // Prepare response, some values may be added (certificate, cookie)
    let mut response = ResponseAuthentificateUser {
        ok: true,
        counter: auth_result.counter(),
        user_verified: auth_result.user_verified(),
        certificat: None,
        cookie: None
    };

    if let Some(demande_certificat) = command.commande_webauthn.demande_certificat {
        let signed_certificate_response = signer_demande_certificat_usager(
            pki,
            mongo,
            outbound,
            &user_account,
            &demande_certificat
        ).await?;
        response.certificat = Some(signed_certificate_response.certificat);
    }

    if let Some(duree_session) = command.commande_webauthn.duree_session {
        let cookie = creer_session_cookie(mongo, command.user_id.as_str(), command.hostname.as_str(), duree_session).await?;
        response.cookie = Some(cookie.into());
    }

    outbound.respond(wrapper.delivery_info, response).await
}

async fn authenticate_totp(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
}

#[derive(Deserialize)]
struct CommandeGenererChallenge {
    #[serde(rename="userId")]
    user_id: Option<String>,
    hostname: String,
    delegation: Option<bool>,
    #[serde(rename="webauthnRegistration")]
    webauthn_registration: Option<bool>,
    #[serde(rename="webauthnAuthentication")]
    webauthn_authentication: Option<bool>,
}

#[derive(Serialize)]
struct ReponseCommandeGenererChallenge {
    challenge: Option<String>,
    registration_challenge: Option<CreationChallengeResponse>,
    authentication_challenge: Option<RequestChallengeResponse>,
    // passkey_authentication: Option<PasskeyAuthentication>,  // Do not send, value is private
}

async fn generate_challenge<M>(
    config: &dyn ConfigService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let command: CommandeGenererChallenge = wrapper.message.deserialize()?;

    //     let commande: CommandeGenererChallenge = message_contenu.deserialize()?;
    //     let hostname = commande.hostname.as_str();
    //
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => {
            if let Some(user_id) = command.user_id {
                if wrapper.certificate.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege])? {
                    user_id
                } else {
                    // Requestor not allowed to act on users
                    return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
                }
            } else {
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Missing user ID in command")).await
            }
        }
    };

    let account = match load_user_by_id(mongo, user_id.as_str()).await? {
        Some(account) => account,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown user account")).await
    };

    let mut response = ReponseCommandeGenererChallenge {
        challenge: None,
        registration_challenge: None,
        authentication_challenge: None,
    };

    if let Some(true) = command.delegation {
        let doc_challenge = preparer_challenge_generique(mongo, &account, command.hostname.as_str(), "delegation").await?;
        response.challenge = Some(doc_challenge.challenge);
    }

    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    if let Some(true) = command.webauthn_registration {
        let doc_challenge = match preparer_registration_webauthn(mongo, &account, command.hostname.as_str(), idmg.as_str()).await {
            Ok(inner) => inner,
            Err(e) => Err(millegrilles_common_rust::error::Error::String(format!("core_maitredescomptes.commande_generer_challenge Erreur {:?}", e)))?
        };
        match doc_challenge.get_registration_challenge() {
            Some(inner) => response.registration_challenge = Some(inner.to_owned()),
            None => return Err(CommonError::Str("Unable to generate registration challenge (webauthn_registration)"))
        }
    }

    if let Some(true) = command.webauthn_authentication {
        let challenge = preparer_authentification_webauthn(mongo, &account, command.hostname.as_str(), idmg.as_str()).await?;
        match challenge.get_authentication_challenge() {
            Some(inner) => response.authentication_challenge = Some(inner.to_owned()),
            None => return Err(CommonError::Str("Unable to generate authentication challenge (webauthn_authentication)"))
        }
    }

    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct CommandGenerateOtp {
    username: String,
    hostname: String,
}

#[derive(Serialize)]
struct ResponseGenerateOtp {
    correlation: String,
    qr_base64: String,
    secret_base32: String,
}

async fn generate_otp<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let command: CommandGenerateOtp = wrapper.message.deserialize()?;
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "user_id missing from certificate, access denied")).await
    };
    let user_account = match load_user_by_id(mongo, user_id.as_str()).await? {
        Some(account) => account,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown user account")).await
    };

    let generated_totp = generate_totp(mongo, command.username.as_str(), user_id.as_str(), command.hostname.as_str()).await?;

    //     let username = commande.username.as_str();
    //     let hostname = commande.hostname.as_str();




    //     // Save the user_id/secret for potential new TOTP credentials.
    //     let secret_string = secret.to_string();
    //     debug!("command_generate_otp New secret: {:?}", secret_string);
    //
    //     let authenticator_id = format!("{}", username);
    //
    //     let totp = TOTP::new(
    //         Algorithm::SHA512,
    //         6,
    //         1,
    //         30,
    //         secret.to_bytes().unwrap(),
    //         Some(hostname.to_string()),
    //         authenticator_id
    //     ).unwrap();
    //
    //     let totp_url = totp.get_url();
    //     debug!("TOTP url: {}", totp_url);
    //     // Hash the url to obfuscate the secret
    //     let challenge_hashvalue = base64_url::encode(&hacher_bytes(totp_url.as_bytes(), HachageCode::Blake2s256));
    //
    //     // Encrypt the TOTP url, it contains the secret value
    //     let encrypted_url = gestionnaire.encrypt_string(middleware, totp_url).await?;
    //
    //     let challenge_row = DocChallenge::new_challenge_totp(&user_id, hostname, &challenge_hashvalue, encrypted_url);
    //     let collection = middleware.get_collection_typed::<DocChallenge>(NOM_COLLECTION_CHALLENGES)?;
    //     collection.insert_one_with_session(challenge_row, None, session).await?;
    //
    //     // let token = totp.generate_current().unwrap();
    //     let qr_base64 = totp.get_qr_base64().expect("totp.get_qr_base64");
    //     let secret_base32 = totp.get_secret_base32();
    //     debug!("New TOTP base32 secret: {}, base 64 QR: {}", secret_base32, qr_base64);

    let response = ResponseGenerateOtp {
        correlation: generated_totp.challenge_hashvalue,
        qr_base64: generated_totp.qr_base64,
        secret_base32: generated_totp.secret_base32,
    };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
pub struct CommandDeleteCookie {
    pub user_id: String,
    pub hostname: String,
    pub challenge: String,
}

async fn delete_cookie(
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let command: CommandDeleteCookie = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_exchanges(vec![Securite::L3Protege, Securite::L2Prive, Securite::L1Public])? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    let filtre = doc!{
        "user_id": command.user_id,
        "hostname": command.hostname,
        "challenge": command.challenge,
    };
    let collection = mongo.get_collection(NOM_COLLECTION_COOKIES)?;
    collection.delete_one(filtre).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}


/// Process the command part of the transaction (checks, validations, volatile updates),
/// calls transaction processor and then handles responses and emits events.
pub async fn process_transaction<M>(
    mongo: &M,
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in transaction")).await
    };

    match wrapper.message.kind {
        MessageKind::Commande => {
            match action {
                TRANSACTION_INSCRIRE_USAGER => register_user(mongo, outbound, transaction, wrapper).await,
                TRANSACTION_AJOUTER_CLE => add_key(mongo, outbound, transaction, wrapper).await,
                TRANSACTION_MAJ_USAGER_DELEGATIONS => update_user_delegations(mongo, outbound, transaction, wrapper).await,
                TRANSACTION_AJOUTER_DELEGATION_SIGNEE => add_signed_delegation(mongo, outbound, transaction, wrapper).await,
                TRANSACTION_SUPPRIMER_CLES => delete_keys(outbound, transaction, wrapper).await,
                TRANSACTION_RESET_WEBAUTHN_USAGER => reset_user_webauthn(mongo, outbound, transaction, wrapper).await,
                TRANSACTION_REGISTER_OTP => register_otp(mongo, outbound, transaction, wrapper).await,
                _ => {
                    info!("Unknown action {} for process_transaction, skipping", action);
                    Ok(())
                }
            }
        },
        _ => {
            info!("Unhandled message type with action {} for process_command, skipping", action);
            Ok(())
        }
    }
}

async fn register_user<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionInscrireUsager = wrapper.message.deserialize()?;

    if check_user_existence(mongo, transaction_value.nom_usager.as_str()).await? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(409, "User already registered")).await
    }

    let csr = match transaction_value.csr {
        Some(csr) => csr,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "CSR missing from request")).await
    };

    let fingerprint_pk = match csr_calculer_fingerprintpk(csr.as_str()) {
        Ok(fp) => fp,
        Err(_) => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "CSR invalid")).await
    };

    let signed_certificate = signer_certificat_usager(
        outbound,
        transaction_value.nom_usager.as_str(),
        transaction_value.user_id.as_str(),
        csr.as_str(),
        None
    ).await?;
    ajouter_fingerprint_pk_usager(mongo, transaction_value.user_id.as_str(), fingerprint_pk.as_str()).await?;

    // Keep a copy
    let user_id = transaction_value.user_id.clone();
    let delivery = wrapper.delivery_info.clone();

    // Process transaction
    transaction.process_transaction(wrapper.into(), None).await?;

    // Send update events to account listeners
    emettre_maj_compte_usager(mongo, outbound, user_id.as_str(), Some(EVENEMENT_INSCRIRE_COMPTE_USAGER)).await?;

    outbound.respond(delivery, signed_certificate).await
}

async fn add_key<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}

async fn update_user_delegations<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}

async fn add_signed_delegation<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}

async fn delete_keys(
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    // Validation of structure
    let transaction_value: TransactionSupprimerCles = wrapper.message.deserialize()?;

    // Authorization
    match wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true => (), // Admin is allowed for all user_ids
        false => {
            match wrapper.certificate.get_user_id()? {
                Some(user_id) => {
                    if user_id.as_str() != transaction_value.user_id.as_str() {
                        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "User_id mismatch")).await
                    }
                },
                None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "User_id mismatch")).await
            }
        }
    }

    let delivery_info = wrapper.delivery_info.clone();

    // Process transaction
    transaction.process_transaction(wrapper.into(), None).await?;

    // Respond ok
    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

async fn reset_user_webauthn<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionResetWebauthnUsager = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    // Copy information required to finish processing the command after the transaction is saved
    let delivery_info = wrapper.delivery_info.clone();
    let user_id = transaction_value.user_id.clone();
    let reset_webauthn = transaction_value.reset_webauthn.unwrap_or(false);
    let evict_all_session = transaction_value.evict_all_sessions.unwrap_or(false);

    // Save transaction changes
    transaction.process_transaction(wrapper.into(), None).await?;

    // Proceed to resets/evictions
    if reset_webauthn {
        let filtre = doc! { FIELD_USER_ID: &user_id };
        let collection = mongo.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        if let Err(e) = collection.delete_many(filtre).await {
            error!("reset_user_webauthn Erreur delete_many activations {:?}", e);
        }
    }

    if evict_all_session {
        // Supprimer les cookies de sessions longue duree, emettre evenement evict
        {
            let filtre = doc! { FIELD_USER_ID: &user_id };
            let collection = mongo.get_collection(NOM_COLLECTION_COOKIES)?;
            if let Err(e) = collection.delete_many(filtre).await {
                error!("reset_user_webauthn Erreur delete_many cookies: {:?}", e);
            }
        }

        // Emettre message pour fermer toutes les sessions en cours de l'usager
        let routage = RoutageMessageAction::builder(
            DOMAIN_NAME,
            EVENEMENT_EVICT_USAGER,
            vec![Securite::L1Public]
        ).build();
        let event = EvictUserEvent { user_id };
        outbound.emit_event(routage, &event).await?;
    }

    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

async fn register_otp<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}
