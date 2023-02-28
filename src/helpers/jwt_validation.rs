use jsonwebtoken::{decode, Validation, jwk::{Jwk, JwkSet}, DecodingKey, decode_header};
use serde::{Deserialize, Serialize };
use std::{time::{SystemTime, UNIX_EPOCH }, env, fmt};

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

#[derive(Debug, Clone)]
pub struct JwtError{
  component: String,
  message: String
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.component, self.message)
    }
}

pub struct JwksCache {
  /// Most recently fetched JWKS
  pub jwks: JwkSet,
  /// Time in seconds since JWKS were last updated
  pub last_update: usize,
  /// Url to fetch JWKS from
  pub jwks_url: String,
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

impl JwksCache {
  pub fn new() -> JwksCache {
    let jwks_url: String = env::var("JWKS_URL").unwrap();
    let jwks: JwkSet = fetch_jwks(&jwks_url).unwrap();
    JwksCache {
      last_update: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize,
      jwks,
      jwks_url,
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
    self.jwks = jwks;
    self.last_update = now;
    Ok(())
  }

  pub fn get(&mut self, kid: &String) -> Result<&Jwk, JwtError> {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
      Ok(n) => n.as_secs() as usize,
      Err(_) => return Err(JwtError{message: "Unable to get system time.".to_string(), component: "JwksCache.get".to_string()}),
    };
    if now - self.last_update > 3600 {
      match self.update() {
        Ok(_) => (),
        Err(_) => println!(),
      };
    };
    match self.jwks.find(kid) {
        Some(jwk) => Ok(jwk),
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
  let jwk = match key_cache.get(&kid) {
    Ok(jwk) => jwk,
    Err(_) => return Err(JwtError{message: "Failed to get jwk from cache".to_string(), component: "validate_jwt".to_string()}),
  };
  let decoding_key = match DecodingKey::from_jwk(jwk) {
    Ok(key) => key,
    Err(_) => return Err(JwtError{message: "Failed to create decoding key".to_string(), component: "validate_jwt".to_string()}),
  };
  let claims = match decode::<Claims>(&jwt, &decoding_key, &Validation::default()){
    Ok(claims) => claims.claims,
    Err(_) => return Err(JwtError{message: "Failed to decode jwt".to_string(), component: "validate_jwt".to_string()}),
  };
  Ok(claims)
}