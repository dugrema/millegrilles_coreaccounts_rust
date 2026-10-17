use crate::external::mq::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;

pub async fn process_request<M>(
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
                REQUETE_CHARGER_USAGER => request_load_user(mongo, outbound, wrapper).await,
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

async fn request_load_user<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!();
    // let request: RequestCertificate = wrapper.message.deserialize()?;
//     let fingerprint = request.fingerprint;
//     debug!("Request for cert {}", fingerprint);
// 
//     let filter = doc!{ PKI_DOCUMENT_CHAMP_FINGERPRINT: &fingerprint};
//     let collection = mongo.get_collection_typed::<CertificateRow>(COLLECTION_NAME_CERTIFICATES)?;
//     let certificate = collection
//         .find_one(filter)
//         .hint(Hint::Name(PKI_DOCUMENT_CHAMP_FINGERPRINT.to_string()))
//         .await?;
// 
//     match certificate {
//         Some(certificate) => {
//             let response: ReponseEnveloppe = certificate.try_into()?;
//             outbound.respond(wrapper.delivery_info, response).await
//         },
//         None => outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Certificate not found")).await
//     }
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
