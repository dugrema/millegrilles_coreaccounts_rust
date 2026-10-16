use crate::external::mq::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::ConfigService;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use std::sync::Mutex;

pub async fn process_events(
    config: &dyn ConfigService,
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
        EVENT_KEYMASTER_CERTIFICATE => todo!(), // save_keymaster_certificate(chiffrage, wrapper).await,
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
