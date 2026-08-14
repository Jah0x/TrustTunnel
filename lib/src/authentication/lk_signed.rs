use crate::authentication::Authenticator;
use crate::{authentication, log_utils};
use base64::engine::general_purpose::{STANDARD as BASE64_ENGINE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::Utc;
use ring::hmac;
use serde::Deserialize;
use std::collections::HashMap;

const TOKEN_VERSION: &str = "ssv1";

#[derive(Clone)]
pub struct VerificationKey {
    pub key_id: String,
    pub secret: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct SignedAccessClaims {
    pub sub: String,
    pub username: String,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub epoch: Option<i64>,
    pub scope: Option<String>,
}

pub struct SignedAccessAuthenticator {
    keys: HashMap<String, Vec<u8>>,
    required_scope: Option<String>,
}

impl SignedAccessAuthenticator {
    pub fn new(keys: Vec<VerificationKey>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .map(|key| (key.key_id, key.secret))
                .collect(),
            required_scope: None,
        }
    }

    pub fn with_required_scope(mut self, scope: impl Into<String>) -> Self {
        self.required_scope = Some(scope.into());
        self
    }

    fn verify_token(&self, token: &str, username: &str) -> Option<SignedAccessClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 || parts[0] != TOKEN_VERSION {
            return None;
        }

        let key = self.keys.get(parts[1])?;
        let signing_input = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        let signature = URL_SAFE_NO_PAD.decode(parts[3]).ok()?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, key),
            signing_input.as_bytes(),
            &signature,
        )
        .ok()?;

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
        let claims: SignedAccessClaims = serde_json::from_slice(&claims_bytes).ok()?;
        if claims.username != username {
            return None;
        }

        let now = Utc::now().timestamp();
        if claims.exp <= now {
            return None;
        }
        if claims.nbf.is_some_and(|nbf| nbf > now) {
            return None;
        }
        if !self.scope_matches(claims.scope.as_deref()) {
            return None;
        }

        Some(claims)
    }

    fn scope_matches(&self, scope: Option<&str>) -> bool {
        match self.required_scope.as_deref() {
            None => true,
            Some(required) => scope
                .map(|scope| {
                    scope
                        .split_whitespace()
                        .any(|candidate| candidate == required)
                })
                .unwrap_or(false),
        }
    }
}

impl Authenticator for SignedAccessAuthenticator {
    fn authenticate(
        &self,
        source: &authentication::Source<'_>,
        _log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        let Some((username, password)) = decode_basic_auth_source(source) else {
            return authentication::Status::Reject;
        };

        if self.verify_token(&password, &username).is_some() {
            authentication::Status::Pass
        } else {
            authentication::Status::Reject
        }
    }
}

fn decode_basic_auth_source(source: &authentication::Source<'_>) -> Option<(String, String)> {
    let encoded = match source {
        authentication::Source::ProxyBasic(value) => value.as_ref(),
        authentication::Source::Sni(value) => value.as_ref(),
    };
    let decoded = BASE64_ENGINE.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn token(username: &str, key_id: &str, secret: &[u8], expires_in_seconds: i64) -> String {
        let claims = serde_json::json!({
            "sub": "tt-pair-test",
            "username": username,
            "exp": Utc::now().timestamp() + expires_in_seconds,
            "scope": "trusttunnel:connect",
        });
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{TOKEN_VERSION}.{key_id}.{claims}");
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, secret),
            signing_input.as_bytes(),
        );
        format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    fn basic_source(username: &str, password: &str) -> authentication::Source<'static> {
        authentication::Source::ProxyBasic(Cow::Owned(
            BASE64_ENGINE.encode(format!("{username}:{password}")),
        ))
    }

    fn authenticator() -> SignedAccessAuthenticator {
        SignedAccessAuthenticator::new(vec![VerificationKey {
            key_id: "lk-key-a".to_string(),
            secret: b"test-secret".to_vec(),
        }])
        .with_required_scope("trusttunnel:connect")
    }

    #[test]
    fn accepts_valid_lk_signed_password_token() {
        let password = token("alice", "lk-key-a", b"test-secret", 60);
        let source = basic_source("alice", &password);

        assert!(
            authenticator().authenticate(&source, &log_utils::IdChain::empty())
                == authentication::Status::Pass
        );
    }

    #[test]
    fn rejects_token_for_different_username() {
        let password = token("alice", "lk-key-a", b"test-secret", 60);
        let source = basic_source("bob", &password);

        assert!(
            authenticator().authenticate(&source, &log_utils::IdChain::empty())
                == authentication::Status::Reject
        );
    }

    #[test]
    fn rejects_tampered_token() {
        let mut password = token("alice", "lk-key-a", b"test-secret", 60);
        password.push('x');
        let source = basic_source("alice", &password);

        assert!(
            authenticator().authenticate(&source, &log_utils::IdChain::empty())
                == authentication::Status::Reject
        );
    }

    #[test]
    fn rejects_expired_token() {
        let password = token("alice", "lk-key-a", b"test-secret", -60);
        let source = basic_source("alice", &password);

        assert!(
            authenticator().authenticate(&source, &log_utils::IdChain::empty())
                == authentication::Status::Reject
        );
    }
}
