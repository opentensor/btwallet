use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyFileError {
    #[error("Failed to create directory: {0}")]
    DirectoryCreation(String),
    #[error("Failed to get metadata: {0}")]
    MetadataError(String),
    #[error("File does not exist: {0}")]
    FileNotFound(String),
    #[error("File is not readable: {0}")]
    NotReadable(String),
    #[error("File is not writable: {0}")]
    NotWritable(String),
    #[error("Failed to open file: {0}")]
    FileOpen(String),
    #[error("Failed to read file: {0}")]
    FileRead(String),
    #[error("Failed to write file: {0}")]
    FileWrite(String),
    #[error("Failed to set permissions: {0}")]
    PermissionError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Invalid encryption method: {0}")]
    InvalidEncryption(String),
    #[error("Environment variable error: {0}")]
    EnvVarError(String),
    #[error("Password error: {0}")]
    PasswordError(String),
    #[error("Base64 decoding error: {0}")]
    Base64DecodeError(String),
    #[error("Base64 encoding error: {0}")]
    Base64EncodeError(String),
    #[error("Generic error: {0}")]
    Generic(String),
}

#[derive(Error, Debug)]
pub enum ConfigurationError {
    #[error("ConfigurationError: {0}")]
    Message(String),
}

#[derive(Error, Debug)]
pub enum PasswordError {
    #[error("PasswordError: {0}")]
    Message(String),
}
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("WalletError: {0}")]
    KeyGeneration(String),
    #[error("WalletError: {0}")]
    InvalidInput(String),
    #[error("WalletError: {0}")]
    KeyFileError(#[from] KeyFileError),
}
