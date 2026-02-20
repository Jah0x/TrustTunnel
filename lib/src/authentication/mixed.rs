use crate::authentication::{AuthError, AuthProvider};

pub struct MixedAuth {
    jwt: Box<dyn AuthProvider>,
    credentials: Box<dyn AuthProvider>,
}

impl MixedAuth {
    pub fn new(jwt: Box<dyn AuthProvider>, credentials: Box<dyn AuthProvider>) -> Self {
        Self { jwt, credentials }
    }
}

impl AuthProvider for MixedAuth {
    fn authenticate(&self, username: &str, password: &str) -> Result<(), AuthError> {
        if self.jwt.authenticate(username, password).is_ok() {
            return Ok(());
        }

        self.credentials.authenticate(username, password)
    }
}
