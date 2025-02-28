# Tenzro Trust Usage Guide

This document provides detailed information on how to use the Tenzro Trust framework in your projects.

## Table of Contents

- [Tenzro Trust Usage Guide](#tenzro-trust-usage-guide)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
    - [Using pip](#using-pip)
    - [From Source](#from-source)
    - [Dependencies](#dependencies)
  - [Core Concepts](#core-concepts)
  - [Provider Configuration](#provider-configuration)
    - [Configuration File](#configuration-file)
    - [Environment Variables](#environment-variables)
    - [Direct Configuration](#direct-configuration)
  - [Using HSM Provider](#using-hsm-provider)
    - [AWS CloudHSM](#aws-cloudhsm)
    - [Google Cloud HSM](#google-cloud-hsm)
    - [Azure Key Vault HSM](#azure-key-vault-hsm)
    - [Thales HSM](#thales-hsm)
    - [Simulation Mode](#simulation-mode)
  - [Using TPM Provider](#using-tpm-provider)
    - [Linux TPM](#linux-tpm)
    - [Windows TPM](#windows-tpm)
    - [Simulation Mode](#simulation-mode-1)
  - [Using TEE Provider](#using-tee-provider)
    - [Intel SGX](#intel-sgx)
    - [ARM TrustZone](#arm-trustzone)
    - [AMD SEV](#amd-sev)
    - [Simulation Mode](#simulation-mode-2)
  - [Using Mobile Provider](#using-mobile-provider)
    - [iOS Secure Enclave](#ios-secure-enclave)
    - [Android KeyStore/StrongBox](#android-keystorestrongbox)
    - [Simulation Mode](#simulation-mode-3)
  - [Extending with Custom Providers](#extending-with-custom-providers)
  - [Hardware Attestation](#hardware-attestation)
  - [Development and Testing](#development-and-testing)
    - [Simulation Mode](#simulation-mode-4)
    - [Running Tests](#running-tests)
    - [Test with Specific Configuration](#test-with-specific-configuration)
  - [Integration with Other Frameworks](#integration-with-other-frameworks)
  - [Security Considerations](#security-considerations)

## Installation

### Using pip

```bash
pip install tenzro-trust
```

### From Source

```bash
git clone https://github.com/tenzro/tenzro-trust.git
cd tenzro-trust
pip install -e .
```

### Dependencies

Tenzro Trust requires Python 3.9 or later and depends on:
- cryptography
- pycryptodome

## Core Concepts

Tenzro Trust provides hardware-rooted trust for distributed ledger systems through a simple and consistent API:

- **Provider**: A hardware security technology implementation (HSM, TPM, TEE, etc.)
- **Initialization**: Setting up the provider with configuration
- **Signing**: Creating cryptographic signatures using hardware security
- **Verification**: Validating signatures against original data
- **Attestation**: Proving the authenticity of the hardware being used

The basic flow is:

1. Get a trust provider
2. Initialize it with configuration
3. Use it to sign data
4. Verify signatures when needed
5. Optionally, get attestation information

```python
from tenzro_trust import get_tenzro_trust

# Get a provider
trust = get_tenzro_trust(provider_name="hsm")

# Initialize it
trust.initialize({
    "hsm_type": "aws",
    "region": "us-west-2",
    "key_id": "alias/my-signing-key"
})

# Sign data
data = b'{"transaction": "data"}'
signature = trust.sign(data)

# Verify the signature
is_valid = trust.verify(data, signature)

# Get attestation
attestation = trust.get_attestation()
```

## Provider Configuration

### Configuration File

Create a JSON configuration file:

```json
{
  "provider": "hsm",
  "hsm_type": "aws",
  "region": "us-west-2",
  "key_id": "alias/my-signing-key",
  "profile": "production"
}
```

Use it in your code:

```python
trust = get_tenzro_trust(config_path="config.json")
```

### Environment Variables

Set configuration through environment variables:

```bash
export TENZRO_TRUST_CONFIG='{"provider":"hsm","hsm_type":"aws","region":"us-west-2","key_id":"alias/my-signing-key"}'
```

Use it in your code:

```python
trust = get_tenzro_trust()  # Will load from environment
```

### Direct Configuration

Provide configuration directly in the code:

```python
trust = get_tenzro_trust(provider_name="hsm")
trust.initialize({
    "hsm_type": "aws",
    "region": "us-west-2",
    "key_id": "alias/my-signing-key"
})
```

## Using HSM Provider

The HSM provider supports various Hardware Security Module types:

- Cloud HSMs (AWS, Google Cloud, Azure)
- On-premise HSMs (Thales, nCipher, etc.)
- Virtual HSMs
- Simulated mode for development

### AWS CloudHSM

```python
trust.initialize({
    "hsm_type": "aws",
    "region": "us-west-2",
    "key_id": "alias/my-signing-key",
    "profile": "production"  # Optional AWS profile
})
```

### Google Cloud HSM

```python
trust.initialize({
    "hsm_type": "google",
    "project_id": "my-project",
    "location_id": "global",
    "key_id": "my-kms-key"
})
```

### Azure Key Vault HSM

```python
trust.initialize({
    "hsm_type": "azure",
    "vault_name": "my-key-vault",
    "tenant_id": "tenant-id",
    "key_id": "my-key-name"
})
```

### Thales HSM

```python
trust.initialize({
    "hsm_type": "thales",
    "partition_name": "partition1",
    "server_ip": "192.168.1.100",
    "key_id": "signing-key-1"
})
```

### Simulation Mode

```python
trust.initialize({
    "hsm_type": "simulated",
    "key_id": "test-key-1"
})
```

## Using TPM Provider

The TPM provider uses Trusted Platform Modules (TPM 2.0) in modern computers:

### Linux TPM

```python
trust.initialize({
    "device": "/dev/tpmrm0",  # TPM resource manager
    "key_handle": "0x81000001",
    "algorithm": "RSA"
})
```

### Windows TPM

```python
trust.initialize({
    "device": "Windows",  # Special value for Windows TPM
    "key_handle": "0x81000001",
    "algorithm": "RSA"
})
```

### Simulation Mode

```python
trust.initialize({
    "simulator": True,
    "key_handle": "0x81000001",
    "algorithm": "RSA"
})
```

## Using TEE Provider

The TEE provider supports various Trusted Execution Environments:

### Intel SGX

```python
trust.initialize({
    "tee_type": "sgx",
    "enclave_file": "/path/to/enclave.signed.so",
    "key_name": "tenzro-signing-key"
})
```

### ARM TrustZone

```python
trust.initialize({
    "tee_type": "trustzone",
    "key_name": "tenzro-signing-key"
})
```

### AMD SEV

```python
trust.initialize({
    "tee_type": "sev",
    "key_name": "tenzro-signing-key"
})
```

### Simulation Mode

```python
trust.initialize({
    "tee_type": "sgx",
    "simulator": True,
    "key_name": "tenzro-signing-key"
})
```

## Using Mobile Provider

The Mobile provider uses secure elements in mobile devices:

### iOS Secure Enclave

```python
trust.initialize({
    "platform": "ios",
    "key_alias": "tenzro.signing.key",
    "auth_type": "biometric"  # biometric, pin, none
})
```

### Android KeyStore/StrongBox

```python
trust.initialize({
    "platform": "android",
    "key_alias": "tenzro.signing.key",
    "auth_type": "biometric",  # biometric, pin, none
    "strongbox": True  # Use StrongBox when available
})
```

### Simulation Mode

```python
trust.initialize({
    "platform": "ios",  # or android
    "key_alias": "tenzro.signing.key",
    "auth_type": "none",
    "simulator": True
})
```

## Extending with Custom Providers

Tenzro Trust is designed to be extended with custom providers. To create your own provider:

1. Create a new module named `tenzro_trust_<provider>` (e.g., `tenzro_trust_custom`)
2. Implement a class that inherits from `TenzroTrustProvider`
3. Name the class `<Provider>Provider` (e.g., `CustomProvider`)
4. Implement the required methods: `initialize()`, `sign()`, and `verify()`

Example:

```python
# tenzro_trust_custom.py
from tenzro_trust import TenzroTrustProvider, InitializationError, SigningError, VerificationError

class CustomProvider(TenzroTrustProvider):
    def __init__(self):
        self.initialized = False
        self.config = {}
        self.key = None
    
    def initialize(self, config):
        try:
            # Extract configuration parameters
            self.key_id = config.get("key_id")
            if not self.key_id:
                raise ConfigurationError("Key ID must be specified")
            
            # Initialize your custom hardware interface
            # ...
            
            self.initialized = True
        except Exception as e:
            raise InitializationError(f"Failed to initialize: {e}")
    
    def sign(self, data):
        if not self.initialized:
            raise SigningError("Provider not initialized")
        
        # Implement signing logic with your hardware
        # ...
        
        return signature
    
    def verify(self, data, signature):
        if not self.initialized:
            raise VerificationError("Provider not initialized")
        
        # Implement verification logic with your hardware
        # ...
        
        return is_valid
    
    def get_attestation(self):
        # Optional attestation support
        # ...
        return attestation_data
```

Then you can use your custom provider:

```python
from tenzro_trust import get_tenzro_trust

trust = get_tenzro_trust(provider_name="custom")
```

## Hardware Attestation

Attestation provides proof of the hardware security module's authenticity. Each provider can implement the `get_attestation()` method to return hardware-specific attestation data:

```python
attestation = trust.get_attestation()
if attestation:
    # Use attestation data to verify the hardware
    print(f"Provider: {attestation['provider']}")
    # Specific fields vary by provider type
```

Attestation data typically includes:
- Provider type
- Hardware information
- Firmware/software versions
- Measurements or certificates
- Timestamps

## Development and Testing

### Simulation Mode

All providers support a simulation mode for development and testing:

```python
trust.initialize({
    "hsm_type": "simulated",
    "key_id": "test-key-1"
})
```

**Warning:** Simulation mode does not provide actual hardware security and should only be used for development and testing.

### Running Tests

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run tests
pytest -v tests/
```

### Test with Specific Configuration

Create a `test_config.json` file:

```json
{
    "provider": "hsm",
    "hsm_type": "simulated",
    "key_id": "test-key-1"
}
```

Run the test helper:

```bash
python test_all_providers.py
```

## Integration with Other Frameworks

Tenzro Trust is part of the Tenzro Ledger System, which includes:

- **Tenzro Trust**: Hardware-rooted trust (this module)
- **Tenzro Crypto**: Cryptography, hashing, and encryption services
- **Tenzro Store**: Data storage for distributed ledgers
- **Tenzro Core**: Core ledger functionality

Example integrated with Tenzro Store:

```python
from tenzro_trust import get_tenzro_trust
from tenzro_store import TenzroStore

# Initialize trust provider
trust = get_tenzro_trust(provider_name="hsm")
trust.initialize({
    "hsm_type": "simulated",
    "key_id": "test-key"
})

# Initialize store
store = TenzroStore(base_dir="./ledger_data", node_id="node_1")

# Create and sign a transaction
transaction = {
    "tx_id": "tx_12345",
    "timestamp": int(time.time()),
    "sender": "wallet_a",
    "receiver": "wallet_b",
    "amount": 50.0
}

# Sign it
tx_bytes = json.dumps(transaction).encode()
signature = trust.sign(tx_bytes)

# Store transaction with signature
transaction["signature"] = signature.hex()
store.put(transaction["tx_id"], transaction)

# Later, retrieve and verify
stored_tx = store.get(transaction["tx_id"])
if stored_tx:
    # Extract and verify signature
    signature_hex = stored_tx.pop("signature")
    signature_bytes = bytes.fromhex(signature_hex)
    
    tx_bytes = json.dumps(stored_tx).encode()
    is_valid = trust.verify(tx_bytes, signature_bytes)
```

## Security Considerations

- **Key Management**: Properly manage keys in hardware security modules
- **Simulation Mode**: Never use simulation mode in production
- **Provider Selection**: Choose the appropriate provider based on security requirements
- **Configuration**: Secure your configuration files and environment variables
- **Attestation**: Use attestation to verify hardware authenticity
- **Updates**: Keep hardware firmware and software up to date
- **Access Control**: Restrict access to hardware security modules
- **Logging**: Enable logging for security events
- **Error Handling**: Properly handle and log errors
- **Backups**: Implement proper backup procedures for keys

Always follow security best practices and consult with security experts when implementing hardware-rooted trust in production systems.