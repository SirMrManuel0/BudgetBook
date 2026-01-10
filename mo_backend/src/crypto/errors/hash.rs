#[derive(Debug)]
pub enum HashError {
    FailedRng{
        algorithm: &'static str,
        reason: HashErrorEnum,
    },
    FailedDerive{
        algorithm: &'static str,
        reason: HashErrorEnum,
    },
}

#[derive(Debug)]
pub enum HashErrorEnum {
    FailedRng,
    Unreachable,
}