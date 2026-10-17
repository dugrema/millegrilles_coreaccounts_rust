use crate::external::mq::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use std::sync::Mutex;

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
