use crate::authentication::{
    AuthError, AuthProvider, Authenticator, ProxyBasicAuthenticator, Source, Status,
};
use crate::log_utils;
use serde::Deserialize;
use std::collections::HashMap;

/// A client descriptor
#[derive(Deserialize)]
pub struct Client {
    /// The client username
    pub username: String,
    /// The client password
    pub password: String,
}

pub struct CredentialsAuth {
    clients: HashMap<String, String>,
}

/// Backward-compatible wrapper for previous authenticator type.
pub struct RegistryBasedAuthenticator {
    inner: ProxyBasicAuthenticator,
}

impl RegistryBasedAuthenticator {
    pub fn new(clients: &[Client]) -> Self {
        Self {
            inner: ProxyBasicAuthenticator::new(Box::new(CredentialsAuth::new(clients))),
        }
    }
}

impl Authenticator for RegistryBasedAuthenticator {
    fn authenticate(&self, source: &Source<'_>, log_id: &log_utils::IdChain<u64>) -> Status {
        self.inner.authenticate(source, log_id)
    }
}

impl CredentialsAuth {
    pub fn new(clients: &[Client]) -> Self {
        Self {
            clients: clients
                .iter()
                .map(|x| (x.username.clone(), x.password.clone()))
                .collect(),
        }
    }
}

impl AuthProvider for CredentialsAuth {
    fn authenticate(&self, username: &str, password: &str) -> Result<(), AuthError> {
        match self.clients.get(username) {
            Some(expected_password) if expected_password == password => Ok(()),
            _ => Err(AuthError::InvalidCredentials),
        }
    }
}
