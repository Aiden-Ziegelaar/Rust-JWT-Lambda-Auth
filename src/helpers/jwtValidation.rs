use jsonwebtoken::{decode, Validation, jwk::{Jwk, JwkSet}};
use serde::{Deserialize, Serialize};
use std::{time::{SystemTime, UNIX_EPOCH}, env};

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

pub struct JWKSCache {
  pub jwks: Option<JwkSet>,
  pub last_update: usize,
  pub jwks_url: String,
}

impl JWKSCache {

  pub fn new() -> JWKSCache {
    JWKSCache {
      last_update: 0,
      jwks: None,
      jwks_url: env::var("JWKS_URL").unwrap(),
    }
  }

  pub fn update(&mut self) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    if now - self.last_update > 3600 {
      let jwks: JwkSet = reqwest::blocking::get(&self.jwks_url).unwrap().json().unwrap();
      self.jwks = Some(jwks);
      self.last_update = now;
    }
  }

  pub fn get(&self) {
    
  }
}

//function to validate the jwt token
pub fn validate_jwt(jwt: String) {

  let token = decode::<Claims>(&jwt, &DecodingKey::from_secret("secret".as_ref()), &Validation::default())?;
}