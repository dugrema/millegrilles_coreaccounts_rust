use crate::constants::DOMAIN_NAME;
use crate::external::mongo::*;
use crate::external::mq::*;
use crate::flow::transactions::AccountsTransactionService;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::common_messages::DemandeSignature;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::mongodb::options::Hint;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{ChiffrageService, PkiService};
use std::sync::Mutex;

pub async fn process_command(
    chiffrage: &dyn ChiffrageService,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };

    match wrapper.message.kind {
        MessageKind::Commande => {
            match action {
                // COMMAND_ACTION_SIGN_CSR => sign_csr(signing_state, outbound, wrapper).await,
                _ => {
                    info!("Unknown action {} for process_command, skipping", action);
                    Ok(())
                }
            }
        },
        // MessageKind::Evenement => {
        //     match action {
        //         // EVENT_KEYMASTER_CERTIFICATE => save_keymaster_certificate(chiffrage, wrapper).await,
        //         _ => {
        //             info!("Unknown action {} for process_command, skipping", action);
        //             Ok(())
        //         }
        //     }
        // },
        _ => {
            info!("Unhandled message type with action {} for process_command, skipping", action);
            Ok(())
        }
    }


}

// async fn sign_csr(
//     signing_state: &Mutex<SigningState>,
//     outbound: &MessageOutboundFacade,
//     wrapper: MessageValidated,
// ) -> Result<(), CommonError> {
//     let command: DemandeSignature = wrapper.message.deserialize()?;
//
//     if let Err(e) = validate_csr_signature_request(&command, wrapper.certificate.as_ref()) {
//         warn!("Access denied on a CSR signing request: {:?}", e);
//         return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Request denied")).await
//     }
//
//     match sign_with_certissuer(signing_state, &wrapper).await {
//         Ok(certificate) => {
//             outbound.respond(wrapper.delivery_info, certificate).await
//         },
//         Err(e) => {
//             warn!("Error signing CSR: {:?}", e);
//             outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(500, "Error signing CSR")).await
//         }
//     }
// }

/// Process the command part of the transaction (checks, validations, volatile updates),
/// calls transaction processor and then handles responses and emits events.
pub async fn process_transaction<M>(
    mongo: &M,
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    transaction: &AccountsTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in transaction")).await
    };
    match action {
        // TRANSACTION_ACTION_SAVE_CERTIFICATE | TRANSACTION_ACTION_NEW_CERTIFICATE => {
        //     save_certificate(mongo, pki, outbound, transaction, wrapper).await
        // },
        _ => {
            info!("Unknown action {} for process_transaction, skipping", action);
            Ok(())
        }
    }
}

// async fn save_certificate<M>(
//     mongo: &M,
//     pki: &dyn PkiService,
//     outbound: &MessageOutboundFacade,
//     transaction: &PkiTransactionService,
//     wrapper: MessageValidated,
// ) -> Result<(), CommonError> where M: MongoDaoTyped {
//     let transaction_value: CommandSaveCertificate = wrapper.message.deserialize()?;
//
//     let ca = match transaction_value.ca.as_ref() {
//         Some(ca) => Some(ca.as_str()),
//         None => None
//     };
//
//     // Validate the certificate (current date)
//     let pem_chain_str = transaction_value.chaine_pem.join("\n");
//     let certificate = match pki.validate_pem(pem_chain_str.as_str(), ca.clone(), None) {
//         Ok(certificate) => certificate,
//         Err(_e) => {
//             // Assume the certificate is not currently valid. Get the not-before-date to confirm.
//             let enveloppe = match EnveloppeCertificat::try_from(pem_chain_str.as_str()) {
//                 Ok(enveloppe) => enveloppe,
//                 Err(e) => {
//                     info!("Invalid certificate: {:?}", e);
//                     return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Invalid certificate")).await
//                 }
//             };
//             let not_valid_before = enveloppe.not_valid_before()?;
//             match pki.validate_pem(pem_chain_str.as_str(), ca, Some(&not_valid_before)) {
//                 Ok(certificate) => certificate,
//                 Err(e) => {
//                     info!("Invalid certificate: {:?}", e);
//                     return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Invalid certificate")).await
//                 }
//             }
//         }
//     };
//
//     // Check if certificate already exists
//     let fingerprint = match certificate.fingerprint() {
//         Ok(fingerprint) => fingerprint,
//         Err(e) => {
//             info!("Error getting fingerprint of certificate: {:?}", e);
//             return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(500, "Error getting fingerprint")).await
//         }
//     };
//
//     // Do an existing query, ideally this will only hit the index
//     let filter = doc!{ PKI_DOCUMENT_CHAMP_FINGERPRINT: &fingerprint };
//     let collection = mongo.get_collection(COLLECTION_NAME_CERTIFICATES)?;
//     if let Some(_row) = collection
//         .find_one(filter)
//         .projection(doc!{PKI_DOCUMENT_CHAMP_FINGERPRINT: true})
//         .hint(Hint::Name(PKI_DOCUMENT_CHAMP_FINGERPRINT.to_string()))
//         .await?
//     {
//         // The certificate has already been received and processed successfully - respond with OK
//         return outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
//     }
//
//     // Run transaction updates
//     let delivery_info = wrapper.delivery_info.clone();
//     //if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
//     let transaction_value = TransactionCertificat { pem: pem_chain_str, ca: transaction_value.ca };
//     if let Err(e) = transaction.process_value(
//         DOMAIN_NAME,
//         TRANSACTION_ACTION_NEW_CERTIFICATE,
//         serde_json::to_value(transaction_value)?,
//         None
//     ).await {
//         info!("Error saving certificate: {:?}", e);
//         return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error saving certificate")).await
//     }
//
//     // Success
//     outbound.respond(delivery_info, ErrorMessage::ok()).await
// }

async fn save_keymaster_certificate(
    chiffrage: &dyn ChiffrageService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    debug!("Saving keymaster certificate for encryption/fiche");
    if let Err(e) = chiffrage.add_encryption_publickey(wrapper.certificate) {
        warn!("Error saving keymaster certificate: {:?}", e);
    }
    Ok(())
}
