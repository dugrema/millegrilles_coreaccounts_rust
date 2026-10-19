use crate::auth::webauthn::DemandeSignatureCertificatWebauthn;
use crate::constants::*;
use crate::external::mongo::*;
use crate::models::*;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::constantes::{DOMAINE_PKI, Securite};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::tracing::debug;
use millegrilles_common_rust::v3::PkiService;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use serde::{Deserialize, Serialize};

pub async fn signer_demande_certificat_usager<M>(
    pki: &dyn PkiService,
    mongo: &M,
    outbound: &MessageOutboundFacade,
    compte_usager: &UserAccountRow,
    duration_days: Option<u16>,
    demande_certificat: &DemandeSignatureCertificatWebauthn
) -> Result<ReponseCertificatSigne, CommonError> where M: MongoDaoTyped {
    let nom_usager = &compte_usager.nom_usager;
    let user_id = &compte_usager.user_id;
    let certificate_response = signer_certificat_usager(
        outbound, nom_usager, user_id, demande_certificat.csr.as_str(), duration_days, Some(&compte_usager)).await?;

    // Ajouter flag tiers si active d'un autre appareil que l'origine du CSR
    debug!("commande_signer_compte_usager Activation tierce : {:?}", demande_certificat.activation_tierce);
    if let Some(true) = demande_certificat.activation_tierce {
        // Calculer fingerprint du nouveau certificat
        let pem = &certificate_response.certificat;
        let pem_string = pem.join("\n");
        let enveloppe_cert = pki.validate_pem(pem_string.as_str(), None, None)?;
        let fingerprint_pk = enveloppe_cert.fingerprint_pk()?;

        // Donne le droit a l'usager de faire un login initial et enregistrer son appareil.
        let collection_activations = mongo.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
        let filtre = doc! { FIELD_USER_ID: user_id, FIELD_FINGERPRINT_PK: &fingerprint_pk };
        let ops = doc! {
            "$set": { "certificat": pem },
            "$setOnInsert": { FIELD_DATE_CREATED: Utc::now() },
            "$currentDate": { FIELD_DATE_MODIFIED: true }
        };
        let resultat_update_activations = collection_activations
            .update_one(filtre, ops)
            .upsert(true)
            .await?;
        debug!("commande_signer_compte_usager Update activations : {:?}", resultat_update_activations);

        // Emit certificate signature event, include the new certificate
        let activation_event = EventAccountActivation { fingerprint_pk: fingerprint_pk.clone(), certificat: pem_string };
        let routage_evenement = RoutageMessageAction::builder(
            DOMAIN_NAME, "activationFingerprintPk", vec![Securite::L2Prive])
            .partition(fingerprint_pk)
            .build();
        outbound.emit_event(routage_evenement, activation_event).await?;
    } else {
        debug!("commande_signer_compte_usager Activation compte {} via meme appareil (pas tierce)", nom_usager);
    }

    Ok(certificate_response)
}

#[derive(Serialize)]
struct CommandeSignatureUsager {
    nom_usager: String,
    user_id: String,
    csr: String,
    delegation_globale: Option<String>,
    compte_prive: Option<bool>,
    delegations_version: Option<usize>,
    /// Duration in days
    duration: Option<u16>,
}

impl CommandeSignatureUsager {
    fn new(nom_usager: &str, user_id: &str, csr: &str, duration_days: Option<u16>, compte: Option<&UserAccountRow>) -> Self {
        let (compte_prive, delegation_globale, delegations_version) = match compte {
            Some(inner) => {
                (inner.compte_prive.to_owned(), inner.delegation_globale.to_owned(), inner.delegations_version.to_owned())
            },
            None => (None, None, None)
        };

        Self {
            nom_usager: nom_usager.into(),
            user_id: user_id.into(),
            csr: csr.into(),
            delegation_globale,
            compte_prive,
            delegations_version,
            duration: duration_days,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCertificatSigne {
    pub ok: bool,
    pub certificat: Vec<String>,
}

/// Signe un certificat usager sans autre forme de validation. Utilise certissuerInterne/.
pub async fn signer_certificat_usager(
    outbound: &MessageOutboundFacade,
    nom_usager: &str,
    user_id: &str,
    csr: &str,
    duration_days: Option<u16>,
    compte: Option<&UserAccountRow>
) -> Result<ReponseCertificatSigne, CommonError> {
    let nom_usager_str = nom_usager.as_ref();
    let user_id_str = user_id.as_ref();
    let csr_str = csr.as_ref();

    let commande_signature = CommandeSignatureUsager::new(nom_usager_str, user_id_str, csr_str, duration_days, compte);

    // Une erreur est survenue dans le post, fallback vers noeuds 4.secure (si presents)
    let routage = RoutageMessageAction::builder(
        DOMAINE_PKI, COMMAND_ACTION_SIGN_USER_CSR, vec![Securite::L3Protege])
        .build();
    match outbound.send_command(routage, commande_signature).await? {
        Some(response) => {
            if let (true, e) = response.is_err()? {
                return Err(CommonError::String(format!("signer_certificat_usager Error when signing new user certificate: {:?}", e)))
            }
            let response: ReponseCertificatSigne = response.message.deserialize()?;
            Ok(response)
        },
        None => Err(CommonError::Str("signer_certificat_usager No response provided to command"))
    }
}

pub async fn ajouter_fingerprint_pk_usager(
    mongo: &dyn MongoDao,
    user_id: &str,
    fingerprint_pk: &str
) -> Result<(), millegrilles_common_rust::error::Error> {
    let filtre = doc! { FIELD_USER_ID: user_id, FIELD_FINGERPRINT_PK: fingerprint_pk };
    let ops = doc! {
        "$setOnInsert": { FIELD_DATE_CREATED: bson::datetime::DateTime::now() },
        "$currentDate": { FIELD_DATE_MODIFIED: true },
    };

    let collection = mongo.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
    collection
        .update_one(filtre, ops)
        .upsert(true)
        .await?;

    Ok(())
}

pub async fn cleanup_activations(mongo: &dyn MongoDao) -> Result<(), CommonError> {
    // Activations expire after a week when not replaced by stronger method (OTP, webauthn)
    let expiration = Utc::now() - Duration::days(7);
    debug!("Cleanup expired activations as of {}", expiration);

    let expiration_bson: bson::DateTime = bson::DateTime::from_chrono(expiration);
    let filter = doc! { FIELD_DATE_CREATED: {"$lt": expiration_bson } };

    let collection = mongo.get_collection(NOM_COLLECTION_ACTIVATIONS)?;
    collection.delete_many(filter).await?;

    Ok(())
}

pub async fn cleanup_recovery(mongo: &dyn MongoDao) -> Result<(), CommonError> {
    // Recovery codes expire after 1 day when not consumed
    let expiration = Utc::now() - Duration::days(1);
    debug!("Cleanup expired recovery codes as of {}", expiration);

    let expiration_bson: bson::DateTime = bson::DateTime::from_chrono(expiration);
    let filter = doc! { FIELD_DATE_CREATED: {"$lt": expiration_bson } };

    let collection = mongo.get_collection(NOM_COLLECTION_RECOVERY)?;
    collection.delete_many(filter).await?;

    Ok(())
}
