from typing import Optional, Any, Union
from types import ModuleType

# Submodules
class config:
    class Config:
        def __init__(
            self,
            name: Optional[str] = None,
            hotkey: Optional[str] = None,
            path: Optional[str] = None,
        ) -> None: ...
        def __str__(self) -> str: ...
        @property
        def name(self) -> str: ...
        @property
        def path(self) -> str: ...
        @property
        def hotkey(self) -> str: ...

class errors:
    class KeyFileError(Exception): ...
    class ConfigurationError(Exception): ...
    class PasswordError(Exception): ...
    class WalletError(Exception): ...

class keyfile:
    class Keyfile:
        def __init__(
            self,
            path: Optional[str] = None,
            name: Optional[str] = None,
            should_save_to_env: bool = False,
        ) -> None: ...
        def __str__(self) -> str: ...
        @property
        def path(self) -> str: ...
        def exists_on_device(self) -> bool: ...
        def is_readable(self) -> bool: ...
        def is_writable(self) -> bool: ...
        def is_encrypted(self) -> bool: ...
        def check_and_update_encryption(
            self, print_result: bool = True, no_prompt: bool = False
        ) -> None: ...
        def encrypt(self, password: Optional[str] = None) -> None: ...
        def decrypt(self, password: Optional[str] = None) -> None: ...
        def env_var_name(self) -> str: ...
        def save_password_to_env(self, password: Optional[str] = None) -> None: ...
        def remove_password_from_env(self) -> None: ...
        @property
        def keypair(self) -> "Keypair": ...
        def get_keypair(self, password: Optional[str] = None) -> "Keypair": ...
        def set_keypair(
            self,
            keypair: "Keypair",
            encrypt: bool = True,
            overwrite: bool = False,
            password: Optional[str] = None,
        ) -> None: ...
        @property
        def data(self): ...
        def make_dirs(self): ...

    def serialized_keypair_to_keyfile_data(keypair: "Keypair") -> bytes: ...
    def deserialize_keypair_from_keyfile_data(keyfile_data: bytes) -> "Keypair": ...
    def validate_password(password: str) -> bool: ...
    def ask_password(validation_required: bool) -> str: ...
    def legacy_encrypt_keyfile_data(
        keyfile_data: bytes, password: Optional[str] = None
    ) -> bytes: ...
    def get_password_from_environment(env_var_name: str) -> Optional[str]: ...
    def encrypt_keyfile_data(
        keyfile_data: bytes, password: Optional[str] = None
    ) -> bytes: ...
    def decrypt_keyfile_data(
        keyfile_data: bytes,
        password: Optional[str] = None,
        password_env_var: Optional[str] = None,
    ) -> bytes: ...
    def keyfile_data_is_encrypted_nacl(keyfile_data: bytes) -> bool: ...
    def keyfile_data_is_encrypted_ansible(keyfile_data: bytes) -> bool: ...
    def keyfile_data_is_encrypted_legacy(keyfile_data: bytes) -> bool: ...
    def keyfile_data_is_encrypted(keyfile_data: bytes) -> bool: ...
    def keyfile_data_encryption_method(keyfile_data: bytes) -> str: ...

class keypair:
    class Keypair:
        def __init__(
            self,
            ss58_address: Optional[str] = None,
            public_key: Optional[Union[bytes, str]] = None,
            private_key: Optional[Union[bytes, str]] = None,
            ss58_format: int = 42,
            seed_hex: Optional[str] = None,
            crypto_type: int = 1,
        ) -> None: ...
        @staticmethod
        def generate_mnemonic(n_words: int = 12) -> str: ...
        @staticmethod
        def create_from_mnemonic(mnemonic: str) -> "Keypair": ...
        @staticmethod
        def create_from_seed(seed: Union[bytes, str]) -> "Keypair": ...
        @staticmethod
        def create_from_private_key(private_key: str) -> "Keypair": ...
        @staticmethod
        def create_from_encrypted_json(
            json_data: str, passphrase: str
        ) -> "Keypair": ...
        @staticmethod
        def create_from_uri(uri: str) -> "Keypair": ...
        def sign(self, data: Union[str, bytes]) -> bytes: ...
        def verify(
            self, data: Union[str, bytes], signature: Union[str, bytes]
        ) -> bool: ...
        @property
        def ss58_address(self) -> Optional[str]: ...
        @property
        def public_key(self) -> Optional[bytes]: ...
        @property
        def ss58_format(self) -> int: ...
        @property
        def crypto_type(self) -> int: ...
        @crypto_type.setter
        def crypto_type(self, value: int) -> None: ...

class utils:
    def is_valid_ss58_address(address: str) -> bool: ...
    def get_ss58_format(ss58_address: str) -> int: ...
    def is_valid_ed25519_pubkey(public_key: Union[str, bytes]) -> bool: ...
    def is_valid_bittensor_address_or_public_key(
        address: Union[str, bytes],
    ) -> bool: ...
    SS58_FORMAT: int

class wallet:
    class Wallet:
        def __init__(
            self,
            name: Optional[str] = None,
            hotkey: Optional[str] = None,
            path: Optional[str] = None,
            config: Optional[Any] = None,
        ) -> None: ...
        def __str__(self) -> str: ...
        @classmethod
        def add_args(cls, parser: Any, prefix: Optional[str] = None) -> Any: ...
        def to_string(self) -> str: ...
        def debug_string(self) -> str: ...
        def create_if_non_existent(
            self,
            coldkey_use_password: Optional[bool] = True,
            hotkey_use_password: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            save_hotkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
            hotkey_password: Optional[str] = None,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
        ) -> "Wallet": ...
        def create(
            self,
            coldkey_use_password: Optional[bool] = True,
            hotkey_use_password: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            save_hotkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
            hotkey_password: Optional[str] = None,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
        ) -> "Wallet": ...
        def recreate(
            self,
            coldkey_use_password: Optional[bool] = True,
            hotkey_use_password: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            save_hotkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
            hotkey_password: Optional[str] = None,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
        ) -> "Wallet": ...
        def get_coldkey(self, password: Optional[str] = None) -> "Keypair": ...
        def get_coldkeypub(self, password: Optional[str] = None) -> "Keypair": ...
        def get_hotkey(self, password: Optional[str] = None) -> "Keypair": ...
        def set_coldkey(
            self,
            keypair: "Keypair",
            encrypt: bool = True,
            overwrite: bool = False,
            save_coldkey_to_env: bool = False,
            coldkey_password: Optional[str] = None,
        ) -> None: ...
        def set_coldkeypub(
            self,
            keypair: "Keypair",
            encrypt: bool = False,
            overwrite: bool = False,
        ) -> None: ...
        def set_hotkey(
            self,
            keypair: "Keypair",
            encrypt: bool = False,
            overwrite: bool = False,
            save_hotkey_to_env: bool = False,
            hotkey_password: Optional[str] = None,
        ) -> None: ...
        @property
        def coldkey(self) -> "Keypair": ...
        @property
        def coldkeypub(self) -> "Keypair": ...
        @property
        def hotkey(self) -> "Keypair": ...
        @property
        def coldkey_file(self) -> "Keyfile": ...
        @property
        def coldkeypub_file(self) -> "Keyfile": ...
        @property
        def hotkey_file(self) -> "Keyfile": ...
        @property
        def name(self) -> str: ...
        @property
        def path(self) -> str: ...
        @property
        def hotkey_str(self) -> str: ...
        def create_coldkey_from_uri(
            self,
            uri: str,
            use_password: Optional[bool] = True,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
        ) -> None: ...
        def create_hotkey_from_uri(
            self,
            uri: str,
            use_password: Optional[bool] = True,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_hotkey_to_env: Optional[bool] = False,
            hotkey_password: Optional[str] = None,
        ) -> None: ...
        def unlock_coldkey(self) -> "Keypair": ...
        def unlock_coldkeypub(self) -> "Keypair": ...
        def unlock_hotkey(self) -> "Keypair": ...
        def new_coldkey(
            self,
            n_words: Optional[int] = 12,
            use_password: Optional[bool] = True,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
        ) -> "Wallet": ...
        def create_new_coldkey(
            self,
            n_words: Optional[int] = 12,
            use_password: Optional[bool] = True,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
        ) -> "Wallet": ...
        def new_hotkey(
            self,
            n_words: Optional[int] = 12,
            use_password: Optional[bool] = True,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_hotkey_to_env: Optional[bool] = False,
            hotkey_password: Optional[str] = None,
        ) -> "Wallet": ...
        def create_new_hotkey(
            self,
            n_words: Optional[int] = 12,
            use_password: Optional[bool] = True,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
        ) -> "Wallet": ...
        def regenerate_coldkey(
            self,
            mnemonic: Optional[str] = None,
            seed: Optional[bytes] = None,
            json: Optional[str] = None,
            use_password: Optional[bool] = True,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_coldkey_to_env: Optional[bool] = False,
            coldkey_password: Optional[str] = None,
        ) -> "Wallet": ...
        def regenerate_coldkeypub(
            self,
            ss58_address: Optional[str] = None,
            public_key: Optional[bytes] = None,
            overwrite: Optional[bool] = False,
        ) -> "Wallet": ...
        def regenerate_hotkey(
            self,
            mnemonic: Optional[str] = None,
            seed: Optional[bytes] = None,
            json: Optional[str] = None,
            use_password: Optional[bool] = False,
            overwrite: Optional[bool] = False,
            suppress: Optional[bool] = False,
            save_hotkey_to_env: Optional[bool] = False,
            hotkey_password: Optional[str] = None,
        ) -> "Wallet": ...

config: ModuleType
keyfile: ModuleType
keypair: ModuleType
utils: ModuleType
wallet: ModuleType

Config = config.Config
Keyfile = keyfile.Keyfile
Keypair = keypair.Keypair
Wallet = wallet.Wallet
