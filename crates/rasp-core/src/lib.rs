use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    GeneralProcessingFailure = 1,
    InvalidCliArguments = 2,
    InvalidConfiguration = 3,
    UnsupportedArtifact = 4,
    ArtifactInspectionFailure = 5,
    PayloadInjectionFailure = 6,
    PackageReconstructionFailure = 7,
    AlignmentFailure = 8,
    SigningFailure = 9,
    VerificationFailure = 10,
    CompatibilityValidationFailure = 11,
    PayloadSignatureFailure = 12,
    MissingExternalDependency = 13,
    SecurityPolicyViolation = 14,
    RuntimeSmokeTestFailure = 15,
}

impl ExitCode {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ExitCode::Success => "success",
            ExitCode::GeneralProcessingFailure => "general processing failure",
            ExitCode::InvalidCliArguments => "invalid CLI arguments",
            ExitCode::InvalidConfiguration => "invalid configuration",
            ExitCode::UnsupportedArtifact => "unsupported artifact",
            ExitCode::ArtifactInspectionFailure => "artifact inspection failure",
            ExitCode::PayloadInjectionFailure => "payload injection failure",
            ExitCode::PackageReconstructionFailure => "package reconstruction failure",
            ExitCode::AlignmentFailure => "alignment failure",
            ExitCode::SigningFailure => "signing failure",
            ExitCode::VerificationFailure => "verification failure",
            ExitCode::CompatibilityValidationFailure => "compatibility validation failure",
            ExitCode::PayloadSignatureFailure => "payload signature failure",
            ExitCode::MissingExternalDependency => "missing external dependency",
            ExitCode::SecurityPolicyViolation => "security policy violation",
            ExitCode::RuntimeSmokeTestFailure => "runtime smoke-test failure",
        };
        f.write_str(label)
    }
}

#[derive(Debug)]
pub struct RaspError {
    exit_code: ExitCode,
    message: String,
}

impl RaspError {
    pub fn new(exit_code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }

    pub const fn exit_code(&self) -> ExitCode {
        self.exit_code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RaspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.exit_code, self.message)
    }
}

impl std::error::Error for RaspError {}

pub type RaspResult<T> = Result<T, RaspError>;

#[cfg(test)]
mod tests {
    use super::ExitCode;

    #[test]
    fn exit_codes_match_specification() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::InvalidCliArguments.code(), 2);
        assert_eq!(ExitCode::InvalidConfiguration.code(), 3);
        assert_eq!(ExitCode::RuntimeSmokeTestFailure.code(), 15);
    }
}
