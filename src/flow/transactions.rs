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
use millegrilles_common_rust::mongodb::options::{DeleteManyModel, UpdateOneModel, WriteModel};
use serde::{Deserialize, Serialize};
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
    let transaction_value: TransactionInscrireUsager = wrapper.message.deserialize()?;

    let mut aggregator = TransactionOperationAggregator::new();

    let collection = mongo.get_collection(COLLECTION_NAME_ACCOUNTS)?;
    let filter = doc! { FIELD_USERNAME: &transaction_value.nom_usager };
    let ops = doc! {
        "$set": {
            FIELD_USER_ID: &transaction_value.user_id,
        },
        "$setOnInsert": {
            FIELD_DATE_CREATED: bson::datetime::DateTime::now(),
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

async fn add_key(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
}

async fn update_user_delegations(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
}

async fn add_signed_delegation(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
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

async fn register_otp(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
}
