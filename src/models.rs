use serde::Serialize;

#[derive(Serialize)]
pub struct EventAccountActivation {
    pub fingerprint_pk: String,
    pub certificat: String,
}
