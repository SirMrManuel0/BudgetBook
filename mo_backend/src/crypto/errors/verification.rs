#[derive(Debug)]
pub enum VerificationError {
    InvalidSignAction{
        algorithm: &'static str,
        reason: SignatureFailure,
    },
    InvalidVerification{
        algorithm: &'static str,
        reason: VerificationFailure,
    },
}

#[derive(Debug)]
pub enum VerificationFailure {
    AuthenticationFailed,
}


#[derive(Debug)]
pub enum SignatureFailure{
    AuthenticationFailed,
    KeyFailure,
    KeyGenerationFailure,
    
}