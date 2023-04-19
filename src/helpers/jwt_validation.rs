use jsonwebtoken::{decode, Validation, jwk::{JwkSet}, DecodingKey, decode_header};
use serde::{Deserialize, Serialize };
use std::{time::{SystemTime, UNIX_EPOCH }, env, fmt, collections::HashMap};

//struct to hold the claims of the jwt token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  aud: String,         // Audience
  exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
  iat: usize,          // Issued at (as UTC timestamp)
  iss: String,         // Issuer
  nbf: usize,          // Not Before (as UTC timestamp)
  sub: String,         // Subject (whom token refers to)
}

#[derive(Debug, Clone, PartialEq)]
pub struct JwtError{
  component: String,
  message: String
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.component, self.message)
    }
}

pub fn fetch_jwks(url: &String) -> Result<JwkSet, JwtError> {
  let jwks_reponse =  match reqwest::blocking::get(url) {
    Ok(res) => res,
    Err(_) => return Err(JwtError{message: "Failed to fetch jwks".to_string(), component: "fetch_jwks".to_string()}),
  };
  let jwks: JwkSet = match jwks_reponse.json() {
    Ok(jwks) => jwks,
    Err(_) => return Err(JwtError{message: "Failed to parse jwks".to_string(), component: "fetch_jwks".to_string()}),
  };
  Ok(jwks)
}

pub fn jwks_to_decoding_keys(jwks: JwkSet) -> Result<HashMap<String, DecodingKey>, JwtError > {
  let mut map: HashMap<String, DecodingKey> = HashMap::new();
  for key in jwks.keys.into_iter() {
    let key_id = match &key.common.key_id {
      Some(key_id) => key_id,
      None => return Err(JwtError{message: "Key id not found in registered JWKS".to_string(), component: "jwks_to_decoding_keys".to_string()}),
    };
    let decoding_key = match DecodingKey::from_jwk(&key) {
      Ok(key) => key,
      Err(_) => return Err(JwtError{message: "Failed to create decoding key".to_string(), component: "jwks_to_decoding_keys".to_string()}),
    };
    map.insert(key_id.to_string(), decoding_key);
  };
  Ok(map)
}

pub struct JwksCache {
  /// Time in seconds since JWKS were last updated
  pub last_update: usize,
  /// Url to fetch JWKS from
  pub jwks_url: String,
  /// jwks Hashmap to store decode keys
  pub jwks_hashmap: HashMap<String, DecodingKey>,
}

impl JwksCache {
  pub fn new() -> JwksCache {
    let jwks_url: String = env::var("JWKS_URL").unwrap();
    let jwks: JwkSet = fetch_jwks(&jwks_url).unwrap();
    let jwks_hashmap = jwks_to_decoding_keys(jwks).unwrap();
    JwksCache {
      last_update: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
      jwks_url,
      jwks_hashmap
    }
  }

  pub fn update(&mut self) -> Result<(), JwtError> {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
      Ok(n) => n.as_secs() as usize,
      Err(_) => return Err(JwtError{message: "Unable to get system time.".to_string(), component: "JwksCache.update".to_string()}),
    };
    let fetched_jwks = fetch_jwks(&self.jwks_url);
    let jwks = match fetched_jwks {
      Ok(jwks) => jwks,
      Err(_) => return Err(JwtError{message: "Failed to update jwks".to_string(), component: "JwksCache.update".to_string()}),
    };
    let jwks_hashmap = match jwks_to_decoding_keys(jwks) {
      Ok(jwks_hashmap) => jwks_hashmap,
      Err(_) => return Err(JwtError{message: "Failed to update jwks hashmap".to_string(), component: "JwksCache.update".to_string()}),
    };
    self.jwks_hashmap = jwks_hashmap;
    self.last_update = now;
    Ok(())
  }

  pub fn get(&mut self, kid: &String) -> Result<&DecodingKey, JwtError> {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
      Ok(n) => n.as_secs() as usize,
      Err(_) => return Err(JwtError{message: "Unable to get system time.".to_string(), component: "JwksCache.get".to_string()}),
    };
    if now - self.last_update > 3600 {
      match self.update() {
        Ok(_) => (),
        Err(_) => (),
      };
    };
    match self.jwks_hashmap.get(kid) {
        Some(key) => Ok(key),
        None => Err(JwtError{message: "Unable to find jwk with matching KID".to_string(), component: "JwksCache.get".to_string()}),
    }
  }
}

//function to validate the jwt token
pub fn validate_jwt(jwt: String, mut key_cache: JwksCache) -> Result<Claims, JwtError> {
  let header = match decode_header(&jwt) {
    Ok(header) => header,
    Err(_) => return Err(JwtError{message: "Failed to decode jwt header".to_string(), component: "validate_jwt".to_string()}),
  };
  let kid = match header.kid {
    Some(kid) => kid,
    None => return Err(JwtError{message: "No KID found in jwt header".to_string(), component: "validate_jwt".to_string()}),
  };
  let key = match key_cache.get(&kid) {
    Ok(key) => key,
    Err(_) => return Err(JwtError{message: "Failed to get jwk from cache".to_string(), component: "validate_jwt".to_string()}),
  };
  let claims = match decode::<Claims>(&jwt, key, &Validation::default()){
    Ok(claims) => claims.claims,
    Err(_) => return Err(JwtError{message: "Failed to decode jwt".to_string(), component: "validate_jwt".to_string()}),
  };
  Ok(claims)
}

#[cfg(test)]
mod tests {

  use super::*;
  use mockito;
  use jsonwebtoken::{ jwk, Algorithm };
  use base64::{engine::general_purpose, Engine as _};

  #[test]
  fn positive_jwks_test_path () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.
    
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();    
    let jwks = JwkSet {
      keys: vec![
        jwk::Jwk { 
          common: jwk::CommonParameters {
            public_key_use:Some(jwk::PublicKeyUse::Signature),
            key_operations:Some(vec![jwk::KeyOperations::Sign]),
            algorithm:Some(Algorithm::EdDSA),
            key_id:Some("KEY123".to_string()), 
            x509_url: None, 
            x509_chain: None, 
            x509_sha1_fingerprint: None, 
            x509_sha256_fingerprint: None }, 
          algorithm: jwk::AlgorithmParameters::OctetKeyPair(jwk::OctetKeyPairParameters {
            curve: jwk::EllipticCurve::Ed25519,
            x: general_purpose::STANDARD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let result = fetch_jwks(&url);

    mock.assert();

    server.reset();

    assert_eq!(result.unwrap(), jwks);
  }

  #[test]
  fn negative_jwks_test_path_fail_parse () {
    let server = mockito::Server::new();

    let url = server.url();

    let result = fetch_jwks(&url);

    assert_eq!(result.unwrap_err(), JwtError{message: "Failed to parse jwks".to_string(), component: "fetch_jwks".to_string()});
  }

  #[test]
  fn negative_jwks_test_path_no_endpoint () {
    let result = fetch_jwks(&"url".to_string());

    assert_eq!(result.unwrap_err(), JwtError{message: "Failed to fetch jwks".to_string(), component: "fetch_jwks".to_string()});
  }
}
