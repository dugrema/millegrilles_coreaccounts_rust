use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use crate::external::mongo::*;
use crate::external::mq::*;
use crate::external::webauthn::{preparer_challenge_generique, verify_authentication_challenge, ClientAssertionResponse, DemandeSignatureCertificatWebauthn, preparer_registration_webauthn, preparer_authentification_webauthn};
use crate::flow::certificates::signer_demande_certificat_usager;
use crate::flow::transactions::AccountsTransactionService;
use millegrilles_common_rust::certificats::{charger_csr, VerificateurPermissions, get_csr_subject, calculer_fingerprint_pk};
use millegrilles_common_rust::constantes::{Securite, DELEGATION_GLOBALE_PROPRIETAIRE};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::tracing::{debug, error, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService, PkiService};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{CreationChallengeResponse, PasskeyAuthentication, RequestChallengeResponse};

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
                COMMANDE_AUTHENTIFIER_WEBAUTHN => authenticate_webauthn(outbound, wrapper).await,
                COMMAND_AUTHENTICATE_TOTP => authenticate_totp(outbound, wrapper).await,
                COMMANDE_GENERER_CHALLENGE => generate_challenge(config, mongo, outbound, wrapper).await,
                COMMAND_GENERATE_OTP => generate_otp(outbound, wrapper).await,
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

    match verify_authentication_challenge(
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

async fn authenticate_webauthn(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
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

    //     let compte = {
    //         let collection = middleware.get_collection(NOM_COLLECTION_USAGERS)?;
    //         let filtre = doc! { CHAMP_USER_ID: &user_id };
    //         let resultat = match collection.find_one_with_session(filtre, None, session).await? {
    //             Some(inner) => inner,
    //             None => {
    //                 let reponse = json!({"ok": true, "code": 1, "err": "Usager inconnu"});
    //                 match middleware.build_reponse(reponse) {
    //                     Ok(m) => return Ok(Some(m.0)),
    //                     Err(e) => Err(format!("Erreur preparation reponse commande_generer_challenge : {:?}", e))?
    //                 }
    //             }
    //         };
    //         convertir_bson_deserializable(resultat)?
    //     };

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

async fn generate_otp(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
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
                TRANSACTION_SUPPRIMER_CLES => delete_keys(mongo, outbound, transaction, wrapper).await,
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
    todo!()
    // let transaction_value: CommandSaveCertificate = wrapper.message.deserialize()?;

    // // Run transaction updates
    // let delivery_info = wrapper.delivery_info.clone();
    // //if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
    // let transaction_value = TransactionCertificat { pem: pem_chain_str, ca: transaction_value.ca };
    // if let Err(e) = transaction.process_value(
    //     DOMAIN_NAME,
    //     TRANSACTION_ACTION_NEW_CERTIFICATE,
    //     serde_json::to_value(transaction_value)?,
    //     None
    // ).await {
    //     info!("Error saving certificate: {:?}", e);
    //     return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error saving certificate")).await
    // }
    //
    // // Success
    // outbound.respond(delivery_info, ErrorMessage::ok()).await
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

async fn delete_keys<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}

async fn reset_user_webauthn<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}

async fn register_otp<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}
