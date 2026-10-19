use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::tracing::debug;
use crate::external::mongo::*;

pub async fn cleanup_challenges(mongo: &dyn MongoDao) -> Result<(), CommonError> {
    // Activations expire after 10 minutes when not consumed
    let expiration = Utc::now() - Duration::minutes(10);
    debug!("Expire challenges as of {}", expiration);

    let expiration_bson: bson::DateTime = bson::DateTime::from_chrono(expiration);
    let filter = doc! { FIELD_DATE_CREATED: {"$lt": expiration_bson } };

    let collection = mongo.get_collection(NOM_COLLECTION_CHALLENGES)?;
    collection.delete_many(filter).await?;

    Ok(())
}
