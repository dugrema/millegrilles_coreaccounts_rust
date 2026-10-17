use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::{chrono, serde_json};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use crate::external::mq::*;
use crate::flow::transactions::AccountsTransactionService;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::tracing::{debug, error, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService, PkiService};
use millegrilles_common_rust::chrono::serde::{ts_seconds, ts_milliseconds, ts_seconds_option};
use millegrilles_common_rust::formatteur_messages::preparer_btree_recursif;
use millegrilles_common_rust::hachages::hacher_bytes_vu8;
use millegrilles_common_rust::multihash::Code;
use serde::{Deserialize, Serialize};
use crate::external::mongo::load_user_by_id;
use crate::external::webauthn::{verify_authentication_challenge, ClientAssertionResponse, DemandeSignatureCertificatWebauthn};
use crate::flow::certificates::signer_demande_certificat_usager;

pub async fn process_command<M>(
    config: &dyn ConfigService,
    pki: &dyn PkiService,
    chiffrage: &dyn ChiffrageService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };

    match wrapper.message.kind {
        MessageKind::Commande => {
            match action {
                COMMANDE_SIGNER_COMPTEUSAGER => sign_user_account(config, pki, mongo, outbound, wrapper).await,
                COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE => sign_account_by_admin(outbound, wrapper).await,
                COMMANDE_AJOUTER_CSR_RECOVERY => add_csr_recovery(outbound, wrapper).await,
                COMMANDE_AUTHENTIFIER_WEBAUTHN => authenticate_webauthn(outbound, wrapper).await,
                COMMAND_AUTHENTICATE_TOTP => authenticate_totp(outbound, wrapper).await,
                COMMANDE_GENERER_CHALLENGE => generate_challenge(outbound, wrapper).await,
                COMMAND_GENERATE_OTP => generate_otp(outbound, wrapper).await,
                COMMANDE_SUPPRIMER_COOKIE => delete_cookie(outbound, wrapper).await,
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

async fn sign_account_by_admin(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
}

async fn add_csr_recovery(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
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

async fn generate_challenge(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
}

async fn generate_otp(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
}

async fn delete_cookie(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
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
