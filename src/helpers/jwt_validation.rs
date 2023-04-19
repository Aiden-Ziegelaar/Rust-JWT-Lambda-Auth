use jsonwebtoken::{decode, Validation, jwk::{JwkSet}, DecodingKey, decode_header };
use serde::{Deserialize, Serialize };
use std::{time::{SystemTime, UNIX_EPOCH }, fmt, collections::HashMap };

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
      Err(_) => return Err(JwtError{message: "Failed to create decoding key".to_string(), component: "jwks_to_decoding_keys".to_string()})
    };
    map.insert(key_id.to_string(), decoding_key);
  };
  Ok(map)
}

pub struct JwksCache {
  /// Time in seconds since JWKS were last updated
  pub last_update: u64,
  /// Url to fetch JWKS from
  pub jwks_url: String,
  /// jwks Hashmap to store decode keys
  pub jwks_hashmap: HashMap<String, DecodingKey>,
}

impl JwksCache {
  pub fn new(jwks_url: String) -> JwksCache {
    let jwks: JwkSet = fetch_jwks(&jwks_url).unwrap();
    let jwks_hashmap = jwks_to_decoding_keys(jwks).unwrap();
    JwksCache {
      last_update: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
      jwks_url,
      jwks_hashmap
    }
  }

  pub fn update(&mut self) -> Result<(), JwtError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
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
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if now - self.last_update > 3600 {
      match self.update() {
        Ok(_) => (),
        Err(e) => println!("{}", e.to_string()),
      };
    };
    match self.jwks_hashmap.get(kid) {
        Some(key) => Ok(key),
        None => Err(JwtError{message: "Unable to find jwk with matching KID".to_string(), component: "JwksCache.get".to_string()}),
    }
  }
}

//function to validate the jwt token
pub fn validate_jwt(jwt: String, mut key_cache: JwksCache, validation: Validation) -> Result<Claims, JwtError> {
  let header = match decode_header(&jwt) {
    Ok(header) => header,
    Err(_) => return Err(JwtError{message: "Failed to decode jwt header".to_string(), component: "validate_jwt".to_string()}),
  };
  println!("{:?}", header);
  let kid = match header.kid {
    Some(kid) => kid,
    None => return Err(JwtError{message: "No KID found in jwt header".to_string(), component: "validate_jwt".to_string()}),
  };
  let key = match key_cache.get(&kid) {
    Ok(key) => key,
    Err(_) => return Err(JwtError{message: "Failed to get jwk from cache".to_string(), component: "validate_jwt".to_string()}),
  };
  let claims = match decode::<Claims>(&jwt, key, &validation) {
    Ok(claims) => claims.claims,
    Err(e) => {
      println!("{}", e);
      return Err(JwtError{message: "Failed to decode jwt".to_string(), component: "validate_jwt".to_string()})
    },
  };
  Ok(claims)
}

#[cfg(test)]
mod tests {

  use super::*;
  use mockito;
  use jsonwebtoken::{ jwk, Algorithm, EncodingKey, Header, encode };
  use base64::{engine::general_purpose::URL_SAFE_NO_PAD, engine::general_purpose::STANDARD, Engine as _};

  // Fetch JWKS tests

  #[test]
  fn positive_fetch_jwks_test () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
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
  fn negative_fetch_jwks_test_fail_parse () {
    let server = mockito::Server::new();

    let url = server.url();

    let result = fetch_jwks(&url);

    assert_eq!(result.unwrap_err(), JwtError{message: "Failed to parse jwks".to_string(), component: "fetch_jwks".to_string()});
  }

  #[test]
  fn negative_fetch_jwks_test_no_endpoint () {
    let result = fetch_jwks(&"url".to_string());

    assert_eq!(result.unwrap_err(), JwtError{message: "Failed to fetch jwks".to_string(), component: "fetch_jwks".to_string()});
  } 

  // JWKS to decodeing keys
  #[test]
  fn positive_jwks_to_decoding_keys_test () {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };
    let result = jwks_to_decoding_keys(jwks).unwrap();

    assert_eq!(result.len(), 1);
  }  

  #[test]
  fn negative_jwks_to_decoding_keys_test_invalid_encoding () {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: format!("{}/", STANDARD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec())),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };
    let result = jwks_to_decoding_keys(jwks);

    assert_eq!(result.err(), Some(JwtError{message: "Failed to create decoding key".to_string(), component: "jwks_to_decoding_keys".to_string()}));
  }  

  #[test]
  fn negative_jwks_to_decoding_keys_test_no_kid () {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();    
    let jwks = JwkSet {
      keys: vec![
        jwk::Jwk { 
          common: jwk::CommonParameters {
            public_key_use:Some(jwk::PublicKeyUse::Signature),
            key_operations:Some(vec![jwk::KeyOperations::Sign]),
            algorithm:Some(Algorithm::EdDSA),
            key_id: None, 
            x509_url: None, 
            x509_chain: None, 
            x509_sha1_fingerprint: None, 
            x509_sha256_fingerprint: None }, 
          algorithm: jwk::AlgorithmParameters::OctetKeyPair(jwk::OctetKeyPairParameters {
            curve: jwk::EllipticCurve::Ed25519,
            x: STANDARD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };
    let result = jwks_to_decoding_keys(jwks);

    assert_eq!(result.err(), Some(JwtError{message: "Key id not found in registered JWKS".to_string(), component: "jwks_to_decoding_keys".to_string()}));
  }

  // JWK Cache tests
  #[test]
  fn positive_jwks_cache_new_test () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let cache = JwksCache::new(url);

    mock.assert();

    server.reset();

    assert_eq!(cache.jwks_hashmap.len(), 1);
  }

  #[test]
  fn positive_jwks_cache_update_test () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let mut cache = JwksCache::new(url);

    cache.update().unwrap();

    mock.expect(2);

    server.reset();

    assert_eq!(cache.jwks_hashmap.len(), 1);
  }

  #[test]
  fn positive_jwks_cache_get_test () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let mut cache = JwksCache::new(url);

    cache.last_update = 0;

    let result = cache.get(&"KEY123".to_string());

    mock.expect(2);

    assert!(result.is_ok());

    server.reset();
  }

  #[test]
  fn negative_jwks_cache_update_test_fetch_failure () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let mut cache = JwksCache::new(url);

    cache.last_update = 0;

    cache.jwks_url = "".to_string();

    let result = cache.update();

    mock.assert();

    assert_eq!(result.err(), Some(JwtError{component: "JwksCache.update".to_string(), message: "Failed to update jwks".to_string()}));

    server.reset();
  }


  #[test]
  fn negative_jwks_cache_update_test_decode_failure () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let jwks_no_kid = JwkSet {
      keys: vec![
        jwk::Jwk { 
          common: jwk::CommonParameters {
            public_key_use:Some(jwk::PublicKeyUse::Signature),
            key_operations:Some(vec![jwk::KeyOperations::Sign]),
            algorithm:Some(Algorithm::EdDSA),
            key_id: None, 
            x509_url: None, 
            x509_chain: None, 
            x509_sha1_fingerprint: None, 
            x509_sha256_fingerprint: None }, 
          algorithm: jwk::AlgorithmParameters::OctetKeyPair(jwk::OctetKeyPairParameters {
            curve: jwk::EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let mut cache = JwksCache::new(url);

    cache.last_update = 0;

    mock.assert();

    let mock2 = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks_no_kid).unwrap())
    .create();

    let result = cache.update();

    mock2.assert();

    assert_eq!(result.err(), Some(JwtError{component: "JwksCache.update".to_string(), message: "Failed to update jwks hashmap".to_string()}));

    server.reset();
  }

  #[test]
  fn negative_jwks_cache_get_test_decode_failure () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let jwks_no_kid = JwkSet {
      keys: vec![
        jwk::Jwk { 
          common: jwk::CommonParameters {
            public_key_use:Some(jwk::PublicKeyUse::Signature),
            key_operations:Some(vec![jwk::KeyOperations::Sign]),
            algorithm:Some(Algorithm::EdDSA),
            key_id: None, 
            x509_url: None, 
            x509_chain: None, 
            x509_sha1_fingerprint: None, 
            x509_sha256_fingerprint: None }, 
          algorithm: jwk::AlgorithmParameters::OctetKeyPair(jwk::OctetKeyPairParameters {
            curve: jwk::EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let mut cache = JwksCache::new(url);

    cache.last_update = 0;

    mock.assert();

    let mock2 = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks_no_kid).unwrap())
    .create();

    let result = cache.get(&"KEY123".to_string());

    mock2.assert();

    assert!(result.is_ok());

    server.reset();
  }

  #[test]
  fn negative_jwks_cache_update_test_cache_miss () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };

    let mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let mut cache = JwksCache::new(url);

    let result = cache.get(&"KEY321".to_string());

    mock.assert();

    assert_eq!(result.err(), Some(JwtError{component: "JwksCache.get".to_string(), message: "Unable to find jwk with matching KID".to_string()}));

    server.reset();
  }

  #[test]
  fn positive_validate_jwt_test () {
    let mut server = mockito::Server::new();

    let url = server.url();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    
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
            x: URL_SAFE_NO_PAD.encode(ring::signature::KeyPair::public_key(&key_pair).as_ref().to_vec()),
            key_type: jwk::OctetKeyPairType::OctetKeyPair })
        },
      ] 
    };
    
    let signing_key  = EncodingKey::from_ed_der(&pkcs8_bytes.as_ref().to_vec());

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let jwt = encode(
      &Header {
        alg: Algorithm::EdDSA,
        kid: Some("KEY123".to_string()),
        ..Default::default()
      }, &Claims {
        aud: "https://example.com".to_string(),
        exp: (now + 60) as usize,
        iat: now as usize,
        iss: "https://example.com".to_string(),
        nbf: now as usize,
        sub: "1234567890".to_string(),
      }, &signing_key).unwrap();

    let _mock = server.mock("GET", "/")
    .with_status(200)
    .with_header("content-type", "application/json")
    .with_body(serde_json::to_string(&jwks).unwrap())
    .create();

    let cache = JwksCache::new(url);

    let result = validate_jwt(jwt, cache, Validation::new(Algorithm::EdDSA));

    match result {
      Ok(claims) => {
        assert_eq!(claims.sub, "1234567890");
      },
      Err(e) => {
        println!("Error: {}", e);
        assert!(false);
      }
    }

    server.reset();
  }


}
