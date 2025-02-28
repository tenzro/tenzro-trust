# tenzro-trust/tenzro_trust.py

from abc import ABC, abstractmethod
import json
import os
import logging
import importlib.util
import sys
from typing import Optional, Dict, Any

# Configure logging for the module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TenzroTrustException(Exception):
    """Base exception class for all Tenzro Trust related exceptions."""
    pass

class InitializationError(TenzroTrustException):
    """Raised when initialization of a trust provider fails."""
    pass

class SigningError(TenzroTrustException):
    """Raised when a signing operation fails."""
    pass

class VerificationError(TenzroTrustException):
    """Raised when a verification operation fails."""
    pass

class ConfigurationError(TenzroTrustException):
    """Raised when configuration is invalid."""
    pass

class TenzroTrustProvider(ABC):
    """
    Abstract base class for Tenzro Trust providers, providing hardware-rooted trust for
    distributed ledger systems. Implementations can use hardware security modules (HSMs),
    trusted platform modules (TPMs), trusted execution environments (TEEs), secure enclaves,
    mobile device security elements, smart cards, and more.
    
    This serves as an evolution of blockchain, replacing network validation with hardware-based trust.
    
    Example:
        >>> # Loading a trust provider
        >>> from tenzro_trust import get_tenzro_trust
        >>> # The factory method loads the appropriate provider and initializes it
        >>> trust = get_tenzro_trust("config.json")
        >>> # Sign transaction data
        >>> signature = trust.sign(b'{"tx_id": "abc123", "amount": 100}')
        >>> # Verify the signature
        >>> is_valid = trust.verify(b'{"tx_id": "abc123", "amount": 100}', signature)
    """
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the Tenzro Trust provider with configuration settings.

        Args:
            config (Dict[str, Any]): Configuration dictionary for the specific provider type
                                   (e.g., HSM credentials, TPM device path, mobile device key ID).
        Raises:
            ConfigurationError: If configuration is invalid.
            InitializationError: If initialization fails.
            
        Example:
            >>> provider = SomeConcreteProvider()
            >>> provider.initialize({
            ...     "key_id": "signing-key-1",
            ...     "device_path": "/dev/security_device"
            ... })
        """
        pass

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """
        Sign the provided data using the hardware-rooted trust mechanism.

        Args:
            data (bytes): The data to sign (usually serialized ledger transaction data).

        Returns:
            bytes: The cryptographic signature.

        Raises:
            SigningError: If signing fails.
            
        Example:
            >>> # Sign a transaction
            >>> tx_data = b'{"sender": "wallet1", "receiver": "wallet2", "amount": 50}'
            >>> signature = provider.sign(tx_data)
        """
        pass

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verify the data against a signature using the hardware-rooted trust mechanism.

        Args:
            data (bytes): The original data to verify.
            signature (bytes): The signature to verify against.

        Returns:
            bool: True if the signature is valid, False otherwise.

        Raises:
            VerificationError: If verification process fails.
            
        Example:
            >>> # Verify a transaction signature
            >>> is_valid = provider.verify(tx_data, signature)
            >>> if is_valid:
            ...     print("Transaction signature is valid")
            ... else:
            ...     print("Invalid signature detected!")
        """
        pass

    def get_attestation(self) -> Optional[Dict[str, Any]]:
        """
        Get attestation information about the hardware trust module, if available.
        
        This optional method allows hardware providers to share attestation data that
        proves the authenticity and integrity of the hardware being used.
        
        Returns:
            Optional[Dict[str, Any]]: Hardware attestation data, or None if not supported.
            
        Example:
            >>> attestation = provider.get_attestation()
            >>> if attestation:
            ...     print(f"Hardware attestation available: {attestation['device_type']}")
            ... else:
            ...     print("No attestation data available")
        """
        # Default implementation returns None
        # Providers that support attestation should override this method
        return None

def get_tenzro_trust(config_path: str = "config.json", provider_name: str = None) -> 'TenzroTrustProvider':
    """
    Factory function to load and instantiate the appropriate Tenzro Trust provider.
    
    This function enables the framework to be extended with new hardware security providers
    by dynamically loading provider modules from either the providers package or using
    the legacy naming convention.

    Args:
        config_path (str): Path to a JSON configuration file (default: "config.json").
        provider_name (str, optional): Specific provider name to load (e.g., "hsm", "tpm", "tee").
                                      If None, uses config file.

    Returns:
        TenzroTrustProvider: An instance of the selected Tenzro Trust provider.

    Raises:
        ConfigurationError: If the provider is not found or configuration is invalid.
        ImportError: If the provider module cannot be imported.
        
    Example:
        >>> # Using configuration file
        >>> trust = get_tenzro_trust("my_config.json")
        >>> 
        >>> # Explicitly specifying a provider
        >>> trust = get_tenzro_trust(provider_name="tpm")
        >>> 
        >>> # Using environment configuration with default provider name
        >>> # (requires TENZRO_TRUST_CONFIG environment variable to be set)
        >>> trust = get_tenzro_trust()
    """
    try:
        # Load configuration from file or environment variable
        config = {}
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
        else:
            config_str = os.environ.get("TENZRO_TRUST_CONFIG", '{}')
            if config_str:
                config = json.loads(config_str)

        # Use provider_name if provided, otherwise use config
        provider = provider_name or config.get("provider", "default").lower()
        if not provider:
            raise ConfigurationError("No Tenzro Trust provider specified in config or argument")

        # Dynamically import and instantiate the provider
        try:
            provider_class = None
            provider_class_name = f"{provider.capitalize()}Provider"
            
            # Try modern package structure first
            try:
                # Check if providers package exists
                if importlib.util.find_spec("providers") is not None:
                    # Try to import from providers package
                    module_name = f"providers.{provider}"
                    module = __import__(module_name, fromlist=["TenzroTrustProvider"])
                    provider_class = getattr(module, provider_class_name)
                    logger.debug(f"Loaded provider from providers package: {module_name}")
            except (ImportError, AttributeError) as e:
                logger.debug(f"Could not load from providers package: {e}")
                
            # If not found in providers package, try legacy approach
            if provider_class is None:
                try:
                    # Legacy naming: tenzro_trust_<provider>
                    module_name = f"tenzro_trust_{provider}"
                    module = __import__(module_name, fromlist=["TenzroTrustProvider"])
                    provider_class = getattr(module, provider_class_name)
                    logger.debug(f"Loaded provider using legacy naming: {module_name}")
                except (ImportError, AttributeError) as e:
                    logger.debug(f"Could not load using legacy naming: {e}")
            
            # If still not found, raise error
            if provider_class is None:
                raise ImportError(f"Provider '{provider}' not found in providers package or with legacy naming")
            
            # Instantiate the provider
            instance = provider_class()
            
            # Initialize if config provided
            if config:
                instance.initialize(config)
                
            logger.info(f"Loaded Tenzro Trust provider: {provider}")
            return instance
            
        except ImportError as e:
            logger.error(f"Failed to import Tenzro Trust provider {provider}: {e}")
            raise ImportError(f"Cannot load Tenzro Trust provider '{provider}': {e}")
        except AttributeError as e:
            logger.error(f"Invalid Tenzro Trust provider {provider}: {e}")
            raise ConfigurationError(f"Invalid Tenzro Trust provider configuration for {provider}")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid Tenzro Trust config file: {e}")
        raise ConfigurationError(f"Invalid configuration JSON: {e}")
    except Exception as e:
        logger.error(f"Error loading Tenzro Trust: {e}")
        raise ConfigurationError(f"Failed to load Tenzro Trust: {e}")