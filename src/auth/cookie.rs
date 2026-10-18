use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::{base64_url, bson, chrono, openssl};
use millegrilles_common_rust::bson::doc;
use serde::{Deserialize, Serialize};
use crate::external::mongo::*;

pub async fn creer_session_cookie(
    mongo: &dyn MongoDao,
    user_id: &str,
    hostname: &str,
    duree_session: i64
) -> Result<CookieSessionRow, millegrilles_common_rust::error::Error> {
    let cookie = CookieSessionRow::new(user_id.as_ref(), hostname.as_ref(), duree_session);
    let collection = mongo.get_collection(NOM_COLLECTION_COOKIES)?;

    let ops = doc!{
        "$set": bson::serialize_to_document(&cookie)?,
        "$currentDate": { FIELD_DATE_CREATED: true },
    };

    let filter = doc!{FIELD_CHALLENGE: &cookie.challenge};
    collection
        .update_many(filter, ops)
        .upsert(true)
        .await?;

    Ok(cookie)
}
