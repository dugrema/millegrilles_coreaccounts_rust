use crate::external::mq::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use std::sync::Mutex;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use crate::constants::*;
use crate::external::mongo::*;
use crate::flow::requests::UserAccountResponse;
use crate::models::EvenementMajCompteUsager;

pub async fn process_events(
    config: &dyn ConfigService,
    chiffrage: &dyn ChiffrageService,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => {
            info!("No action provided in event");
            return Ok(());
        }
    };
    match action {
        // EVENT_TOPOLOGY_CONFIGURATIONFILE => process_configuration_file_event(config, outbound, wrapper).await,
        EVENT_KEYMASTER_CERTIFICATE => save_keymaster_certificate(chiffrage, wrapper).await,
        _ => {
            info!("Unknown action {} for process_events, skipping", action);
            Ok(())
        }
    }
}

// async fn process_configuration_file_event(
//     config: &dyn ConfigService,
//     outbound: &MessageOutboundFacade,
//     wrapper: MessageValidated,
// ) -> Result<(), CommonError> {
//
//     let event: ConfigurationFileEvent = wrapper.message.deserialize()?;
//     if event.filename.as_str() == CONFIG_TOPOLOGY_CERTISSUER_PKI {
//         refresh_signing(signing_state, config, outbound).await?;
//     }
//
//     Ok(())
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

pub async fn emettre_maj_compte_usager<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    user_id: &str,
    action: Option<&str>
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = action.unwrap_or_else(|| EVENEMENT_MAJ_COMPTE_USAGER);

    if let Some(user_account) = load_user_by_id(mongo, user_id).await? {
        let user_account: UserAccountResponse = user_account.into();

        let routage = RoutageMessageAction::builder(
            DOMAIN_NAME,
            action,
            vec![Securite::L3Protege]
        ).build();
        outbound.emit_event(routage, &user_account).await?;

        // Event for listeners for that user_id (web apis, the user during login)
        let routage = RoutageMessageAction::builder(
            DOMAIN_NAME,
            action,
            vec![Securite::L2Prive]
        )
            .partition(user_id)
            .build();
        outbound.emit_event(routage, &user_account).await?;
    }

    Ok(())
}
