use crate::external::mq::*;
use crate::flow::transactions::AccountsTransactionService;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{ChiffrageService, PkiService};

pub async fn process_command(
    chiffrage: &dyn ChiffrageService,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };

    match wrapper.message.kind {
        MessageKind::Commande => {
            match action {
                COMMANDE_SIGNER_COMPTEUSAGER => sign_user_account(outbound, wrapper).await,
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

async fn sign_user_account(
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    todo!()
    // let command: DemandeSignature = wrapper.message.deserialize()?;
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
