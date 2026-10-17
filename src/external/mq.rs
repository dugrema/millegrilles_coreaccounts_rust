use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::ConfigRoutingExchange;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::models::ConfigQueueV3;
use crate::constants::*;

pub const QUEUE_TTL_DEFAULT: u32 = 30_000;
pub const QUEUE_TICKER: &str = "job_ticker";
pub const QUEUE_EVENTS: &str = "events";
pub const QUEUE_REQUESTS: &str = "requests";
pub const QUEUE_COMMANDS: &str = "commands";
pub const QUEUE_TRANSACTIONS: &str = "transactions";
pub const QUEUE_BACKUP: &str = "backup";

pub const REQUETE_CHARGER_USAGER: &str = "chargerUsager";
pub const REQUETE_LISTE_USAGERS: &str = "getListeUsagers";
pub const REQUETE_USERID_PAR_NOMUSAGER: &str = "getUserIdParNomUsager";
pub const REQUETE_GET_CSR_RECOVERY_PARCODE: &str = "getCsrRecoveryParcode";
pub const REQUETE_LISTE_PROPRIETAIRES: &str = "getListeProprietaires";
pub const REQUETE_COOKIE_USAGER: &str = "getCookieUsager";
pub const REQUETE_PASSKEYS_USAGER: &str = "getPasskeysUsager";

pub const COMMANDE_SIGNER_COMPTEUSAGER: &str = "signerCompteUsager";
pub const COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE: &str = "signerCompteParProprietaire";
pub const COMMANDE_AJOUTER_CSR_RECOVERY: &str = "ajouterCsrRecovery";
pub const COMMANDE_AUTHENTIFIER_WEBAUTHN: &str = "authentifierWebauthn";
pub const COMMAND_AUTHENTICATE_TOTP: &str = "authenticateTotp";
pub const COMMANDE_GENERER_CHALLENGE: &str = "genererChallenge";
pub const COMMAND_GENERATE_OTP: &str = "generateOtp";
pub const COMMANDE_SUPPRIMER_COOKIE: &str = "supprimerCookieSession";

pub const TRANSACTION_INSCRIRE_USAGER: &str = "inscrireUsager";
pub const TRANSACTION_AJOUTER_CLE: &str = "ajouterCle";
pub const TRANSACTION_MAJ_USAGER_DELEGATIONS: &str = "majUsagerDelegations";
pub const TRANSACTION_AJOUTER_DELEGATION_SIGNEE: &str = "ajouterDelegationSignee";
pub const TRANSACTION_SUPPRIMER_CLES: &str = "supprimerCles";
pub const TRANSACTION_RESET_WEBAUTHN_USAGER: &str = "resetWebauthnUsager";
pub const TRANSACTION_REGISTER_OTP: &str = "registerOtp";


pub const EVENT_KEYMASTER_CERTIFICATE: &str = "certMaitreDesCles";

pub fn init_queues(mq: &MessagingServiceImpl) -> Result<(), CommonError> {
    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueueV3 {
            queue_name: Some(format!("{}/{}", DOMAIN_NAME_NEW, QUEUE_TICKER)),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_exclusive_queue(
        QUEUE_EVENTS.to_string(),
        ConfigQueueV3 {
            queue_name: None,
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAIN_KEYMASTER, EVENT_KEYMASTER_CERTIFICATE), exchange: Securite::L1Public },
                // ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_TOPOLOGIE, EVENT_TOPOLOGY_CONFIGURATIONFILE), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: false,     // Exclusive queue
            autodelete: true,
        })?;

    mq.add_named_queue(
        ConfigQueueV3 {
            queue_name: Some(format!("{}/{}", DOMAIN_NAME_NEW, QUEUE_REQUESTS)),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_CHARGER_USAGER), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_COOKIE_USAGER), exchange: Securite::L1Public },

                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_GET_CSR_RECOVERY_PARCODE), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_PASSKEYS_USAGER), exchange: Securite::L2Prive },

                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_LISTE_USAGERS), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_LISTE_PROPRIETAIRES), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_USERID_PAR_NOMUSAGER), exchange: Securite::L3Protege },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueueV3 {
            queue_name: Some(format!("{}/{}", DOMAIN_NAME_NEW, QUEUE_COMMANDS)),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_AUTHENTIFIER_WEBAUTHN), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_AUTHENTIFIER_WEBAUTHN), exchange: Securite::L2Prive },

                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_SUPPRIMER_COOKIE), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_SUPPRIMER_COOKIE), exchange: Securite::L2Prive },

                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMAND_GENERATE_OTP), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMAND_AUTHENTICATE_TOTP), exchange: Securite::L1Public },

                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_SIGNER_COMPTEUSAGER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_SIGNER_COMPTE_PAR_PROPRIETAIRE), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_AJOUTER_CSR_RECOVERY), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_GENERER_CHALLENGE), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueueV3 {
            queue_name: Some(format!("{}/{}", DOMAIN_NAME_NEW, QUEUE_TRANSACTIONS)),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_REGISTER_OTP), exchange: Securite::L1Public },

                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_INSCRIRE_USAGER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_AJOUTER_CLE), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_AJOUTER_DELEGATION_SIGNEE), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_SUPPRIMER_CLES), exchange: Securite::L2Prive },

                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_MAJ_USAGER_DELEGATIONS), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_RESET_WEBAUTHN_USAGER), exchange: Securite::L3Protege },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(ConfigQueueV3 {
        queue_name: Some(format!("{}/{}", DOMAIN_NAME_NEW, QUEUE_BACKUP)),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.getNombreTransactions", DOMAIN_NAME), exchange: Securite::L2Prive },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_DECLENCHER_BACKUP), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    Ok(())
}
