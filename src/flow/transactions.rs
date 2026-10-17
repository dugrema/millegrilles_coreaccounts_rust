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

    pub async fn _process_transaction(&self, wrapper: TransactionWrapper, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
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

async fn register_user(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
    // let certificate: TransactionCertificat = wrapper.message.deserialize()?;
    //
    // let mut enveloppe = EnveloppeCertificat::try_from(certificate.pem.as_str())?;
    // if let Some(ca) = certificate.ca {
    //     enveloppe.millegrille = Some(X509::from_pem(ca.as_bytes())?);
    // }
    // let row: CertificateRow = enveloppe.try_into()?;
    //
    // let mut aggregator = TransactionOperationAggregator::new();
    // if ignore_duplicates {
    //     // Support for legacy systems with duplicates on restoration
    //     let collection = mongo.get_collection(COLLECTION_NAME_CERTIFICATES)?;
    //     let filtre_versions = doc! { PKI_DOCUMENT_CHAMP_FINGERPRINT: &row.fingerprint };
    //     let ops = doc!{"$set": bson::serialize_to_bson(&row)?};
    //     let update_model_versions = WriteModel::UpdateOne(
    //         UpdateOneModel::builder()
    //             .upsert(true)
    //             .namespace(collection.namespace())
    //             .filter(filtre_versions)
    //             .update(ops)
    //             .build()
    //     );
    //     aggregator.unordered = Some(vec![update_model_versions]);   // This really is just an insert
    // } else {
    //     // Default behavior, insert and raise Error on record duplication
    //     let doc_row = bson::serialize_to_document(&row)?;
    //     aggregator.batch_insertion(BatchInsertions::new(COLLECTION_NAME_CERTIFICATES, vec![doc_row]))?;
    // }
    //
    // Ok(aggregator)
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

async fn delete_keys(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
}

async fn reset_user_webauthn(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
}

async fn register_otp(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
}
