from typing import Optional, Final

class Keypair:
    #[getter]
    ss58_address: Final[Optional[str]]
    
    #[getter]
    public_key: Final[Optional[bytes]]
    
    #[getter]
    ss58_format: Final[int]

    #[getter]
    seed_hex: Final[Optional[bytes]]

    #[getter] #[setter]
    crypto_type: int

    #[getter]
    mnemonic: Final[Optional[str]]

    #[getter]
    private_key: Final[Optional[bytes]]


    #[new]
    #[pyo3(signature = (ss58_address=None, public_key=None, private_key=None, ss58_format=42, seed_hex=None, crypto_type=1))]
    def __new__(
        ss58_address: Optional[str] = None,
        public_key: Optional[str] = None,
        private_key: Optional[str] = None,
        ss58_format: int = 42,
        seed_hex: Optional[bytes] = None,
        crypto_type: int = 1,
    ) -> 'Keypair':
        pass
        

    #[staticmethod]
    #[pyo3(signature = (n_words=12))]
    @staticmethod
    def generate_mnemonic(n_words: int = 12) -> str:
        pass

    #[staticmethod]
    @staticmethod
    def create_from_mnemonic(mnemonic: str) -> 'Keypair':
        pass


    #[staticmethod]
    @staticmethod
    def create_from_seed(seed: bytes) -> 'Keypair':
        pass


    #[staticmethod]
    @staticmethod
    def create_from_private_key(private_key: str) -> 'Keypair':
        pass


    #[staticmethod]
    @staticmethod
    def create_from_encrypted_json(json_data: str, passphrase: str) -> 'Keypair':
        pass

    #[staticmethod]
    @staticmethod
    def create_from_uri(uri: str) -> 'Keypair':
        pass

    #[pyo3(signature = (data))]
    def sign(self, data: str | bytes | list[int] | 'scalec_codec.ScaleBytes') -> bytes:
        pass

    #[pyo3(signature = (data, signature))]
    def verify(self, data: str | bytes | list[int] | 'scalec_codec.ScaleBytes', signature: str | bytes | list[int]) -> bool:
        pass
