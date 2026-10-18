use crate::external::mongo::*;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::mongodb::options::{DeleteManyModel, InsertOneModel, UpdateOneModel, WriteModel};
use millegrilles_common_rust::redis::transaction;
use millegrilles_common_rust::tracing::debug;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;
use crate::external::mq::*;

pub struct AccountsTransactionService {
    pub transaction: Arc<dyn TransactionService>,
}

impl AccountsTransactionService {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        mongo: Arc<dyn MongoDao>,
        restoring: bool,
    ) -> Self {
        let router = AccountsTransactionRouter { mongo: mongo.clone(), ignore_duplicates: restoring };
        let service = TransactionServiceImpl::new(
            config,
            format,
            mongo,
            COLLECTION_NAME_REDOLOG.to_string(),
            COLLECTION_NAME_TRACKING.to_string(),
            Box::new(router),
        );

        Self { transaction: Arc::new(service) }
    }

    pub async fn process_transaction(&self, wrapper: TransactionWrapper, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
        self.transaction.process_transaction(wrapper, session).await
    }

    pub async fn process_value(&self, domain: &str, action: &str, value: Value, session: Option<&mut ClientSession>) -> Result<String, CommonError> {
        self.transaction.process_value(domain, action, value, session).await
    }
}

struct AccountsTransactionRouter {
    mongo: Arc<dyn MongoDao>,
    ignore_duplicates: bool,
}

#[async_trait]
impl TransactionRouter for AccountsTransactionRouter {
    async fn route(
        &self,
        action: String,
        wrapper: TransactionWrapper
    ) -> Result<TransactionOperationAggregator, CommonError> {
        match action.as_str() {
            TRANSACTION_INSCRIRE_USAGER => register_user(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_AJOUTER_CLE => add_key(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_MAJ_USAGER_DELEGATIONS => update_user_delegations(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_AJOUTER_DELEGATION_SIGNEE => add_signed_delegation(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_SUPPRIMER_CLES => delete_keys(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_RESET_WEBAUTHN_USAGER => reset_user_webauthn(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_REGISTER_OTP => register_otp(self.mongo.as_ref(), wrapper).await,

            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInscrireUsager {
    pub fingerprint_pk: String,
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,
    pub securite: String,
    pub csr: Option<String>,
}

async fn register_user(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let date_created = wrapper.message.estampille.clone();
    let transaction_value: TransactionInscrireUsager = wrapper.message.deserialize()?;
    debug!("register_user {:?}", transaction_value);

    let mut aggregator = TransactionOperationAggregator::new();

    let collection = mongo.get_collection(COLLECTION_NAME_ACCOUNTS)?;
    let filter = doc! { FIELD_USERNAME: &transaction_value.nom_usager };
    let ops = doc! {
        "$set": {
            FIELD_USER_ID: &transaction_value.user_id,
        },
        "$setOnInsert": {
            FIELD_DATE_CREATED: date_created,
            FIELD_DELEGATION_VERSION: 1,
        },
        "$currentDate": { FIELD_DATE_MODIFIED: true },
    };
    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAddWebauthnKey {
    #[serde(rename="userId")]
    pub user_id: String,
    pub hostname: String,
    pub passkey: Passkey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_cles: Option<bool>,
}

async fn add_key(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let date_created = wrapper.message.estampille.clone();
    let transaction_value: TransactionAddWebauthnKey = wrapper.message.deserialize()?;

    let reset_keys = transaction_value.reset_cles.unwrap_or(false);

    let mut aggregator = TransactionOperationAggregator::new();

    let collection_webauthn = mongo.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
    let collection_totp = mongo.get_collection(NOM_COLLECTION_TOTP_CREDENTIALS)?;

    let mut ordered_models = Vec::with_capacity(3);
    // Filter by user_id (re-used)
    if reset_keys {
        let filter = doc! { FIELD_USER_ID: &transaction_value.user_id };
        let model_totp = WriteModel::DeleteMany(
            DeleteManyModel::builder()
                .namespace(collection_totp.namespace())
                .filter(filter.clone())
                .build()
        );
        ordered_models.push(model_totp);
        let model_webauthn = WriteModel::DeleteMany(
            DeleteManyModel::builder()
                .namespace(collection_webauthn.namespace())
                .filter(filter.clone())
                .build()
        );
        ordered_models.push(model_webauthn);
    }

    // Always delete the registration challenge
    let filter = doc!{
        FIELD_USER_ID: &transaction_value.user_id,
        FIELD_HOSTNAME: &transaction_value.hostname,
        FIELD_CHALLENGE_TYPE: "registration"
    };
    let collection_challenges = mongo.get_collection(NOM_COLLECTION_CHALLENGES)?;
    let model_challenges = WriteModel::DeleteMany(
        DeleteManyModel::builder()
            .namespace(collection_challenges.namespace())
            .filter(filter.clone())
            .build()
    );
    ordered_models.push(model_challenges);

    let collection_credentials = mongo.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;

    let cred_doc = doc! {
        FIELD_USER_ID: &transaction_value.user_id,
        FIELD_HOSTNAME: &transaction_value.hostname,
        FIELD_PASSKEY: bson::serialize_to_document(&transaction_value.passkey)?,
        FIELD_DATE_CREATED: date_created,
    };

    let cred_model = WriteModel::InsertOne(
        InsertOneModel::builder()
            .namespace(collection_credentials.namespace())
            .document(cred_doc)
            .build()
    );
    ordered_models.push(cred_model);

    aggregator.ordered = Some(ordered_models);

    Ok(aggregator)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionMajUsagerDelegations {
    pub compte_prive: Option<bool>,
    pub delegation_globale: Option<String>,
    #[serde(rename="userId")]
    pub user_id: String,
}

async fn update_user_delegations(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let date_created = wrapper.message.estampille.clone();
    let transaction_value: TransactionMajUsagerDelegations = wrapper.message.deserialize()?;

    let filter = doc! { FIELD_USER_ID: transaction_value.user_id.as_str() };
    let set_ops = doc! {
        FIELD_PRIVATE_ACCOUNT: transaction_value.compte_prive,
        FIELD_DELEGATION_GLOBALE: transaction_value.delegation_globale,
        FIELD_DELEGATION_DATE: date_created,
    };
    let ops = doc! {
        "$set": set_ops,
        "$inc": { FIELD_DELEGATION_VERSION: 1 },
        "$currentDate": { FIELD_DATE_MODIFIED: true},
    };
    let collection = mongo.get_collection(COLLECTION_NAME_ACCOUNTS)?;

    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransactionAjouterDelegationSignee {
    pub confirmation: MessageMilleGrillesOwned,
    #[serde(rename="userId")]
    pub user_id: Option<String>,
    pub hostname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationSigneeDelegationGlobale {
    #[serde(rename="activerDelegation")]
    pub activer_delegation: Option<bool>,
    pub challenge: String,
    #[serde(rename="nomUsager")]
    pub nom_usager: String,
    #[serde(rename="userId")]
    pub user_id: String,
}

async fn add_signed_delegation(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let date_created = wrapper.message.estampille.clone();
    let mut transaction_value: TransactionAjouterDelegationSignee = wrapper.message.deserialize()?;

    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => match transaction_value.user_id {
            Some(inner) => inner,
            None => Err(CommonError::Str("User_id missing from certificate and transaction"))?
        }
    };

    let confirmation: ConfirmationSigneeDelegationGlobale = transaction_value.confirmation.deserialize()?;

    // Le filtre agit a la fois sur le nom usager (valide par la cle) et le user_id (valide par serveur)
    let filter = doc! {
        FIELD_USER_ID: &user_id,
        FIELD_USERNAME: &confirmation.nom_usager,
    };
    let ops = doc! {
        "$set": {
            FIELD_IS_ADMIN: "proprietaire",
            FIELD_DELEGATION_DATE: date_created
        },
        "$inc": { FIELD_DELEGATION_VERSION: 1 },
        "$currentDate": { FIELD_DATE_MODIFIED: true }
    };

    let collection = mongo.get_collection(COLLECTION_NAME_ACCOUNTS)?;
    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSupprimerCles {
    #[serde(rename="userId")]
    pub user_id: String,
}

async fn delete_keys(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let transaction_value: TransactionSupprimerCles = wrapper.message.deserialize()?;
    let mut aggregator = TransactionOperationAggregator::new();
    let collection = mongo.get_collection(COLLECTION_NAME_ACCOUNTS)?;
    let filter = doc! { FIELD_USERNAME: &transaction_value.user_id };
    let ops = doc! {
        "$unset": { FIELD_WEBAUTHN: true },
        "$currentDate": { FIELD_DATE_MODIFIED: true },
    };
    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionResetWebauthnUsager {
    #[serde(rename="userId")]
    pub user_id: String,
    #[serde(rename="resetWebauthn")]
    pub reset_webauthn: Option<bool>,
    #[serde(rename="evictAllSessions")]
    pub evict_all_sessions: Option<bool>,
}

async fn reset_user_webauthn(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let transaction_value: TransactionResetWebauthnUsager = wrapper.message.deserialize()?;

    let mut aggregator = TransactionOperationAggregator::new();

    if let Some(true) = transaction_value.reset_webauthn {
        let collection = mongo.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
        let filter = doc! { FIELD_USER_ID: transaction_value.user_id.as_str() };
        let model = WriteModel::DeleteMany(
            DeleteManyModel::builder()
                .namespace(collection.namespace())
                .filter(filter)
                .build()
        );
        aggregator.ordered = Some(vec![model]);
    }

    Ok(aggregator)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransactionRegisterOtp {
    pub user_id: String,
    pub hostname: String,
    pub correlation: String,
    pub encrypted_totp_url: EncryptedDocument,
    pub reset_keys: Option<bool>,
}

async fn register_otp(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let date_created = wrapper.message.estampille.clone();
    let transaction_value: TransactionRegisterOtp = wrapper.message.deserialize()?;

    let row = TotpCredentialsRow {
        user_id: transaction_value.user_id.clone(),
        correlation: transaction_value.correlation,
        encrypted_totp_url: transaction_value.encrypted_totp_url,
        created: date_created,
    };
    let collection_totp = mongo.get_collection(NOM_COLLECTION_TOTP_CREDENTIALS)?;

    let reset_keys = transaction_value.reset_keys.unwrap_or_else(|| false);
    let mut ordered_models = Vec::with_capacity(3);
    if reset_keys {
        // Supprimer toutes les cles pour le user_id dans la collection credentials
        let filter = doc! { FIELD_USER_ID: &transaction_value.user_id };

        let collection_webauthn = mongo.get_collection(NOM_COLLECTION_WEBAUTHN_CREDENTIALS)?;
        let model = WriteModel::DeleteMany(
            DeleteManyModel::builder()
                .namespace(collection_webauthn.namespace())
                .filter(filter.clone())
                .build()
        );
        ordered_models.push(model);

        let model = WriteModel::DeleteMany(
            DeleteManyModel::builder()
                .namespace(collection_totp.namespace())
                .filter(filter.clone())
                .build()
        );
        ordered_models.push(model);
    }

    let cred_model = WriteModel::InsertOne(
        InsertOneModel::builder()
            .namespace(collection_totp.namespace())
            .document(bson::serialize_to_document(&row)?)
            .build()
    );
    ordered_models.push(cred_model);

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(ordered_models);

    Ok(aggregator)
}
