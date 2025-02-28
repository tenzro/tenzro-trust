# Tenzro Trust

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

A flexible, extensible hardware-rooted trust framework for distributed ledger systems. Part of the Tenzro Ledger Framework.

## Overview

Tenzro Trust provides a unified interface for establishing trust in distributed ledger systems using hardware security as the root of trust, rather than traditional consensus mechanisms. This framework enables developers to use various hardware security technologies:

- Hardware Security Modules (HSMs)
- Trusted Platform Modules (TPMs)
- Trusted Execution Environments (TEEs)
- Secure Enclaves
- Mobile device security elements (iOS Secure Enclave, Android KeyStore)

## Features

- Abstract provider interface for consistent API across different security technologies
- Pluggable architecture for easy extension with new security providers
- Simulation mode for development and testing
- Attestation support for hardware verification
- Configuration through files or environment variables

## Installation

```bash
pip install tenzro-trust
```

For development installations:

```bash
git clone https://github.com/tenzro/tenzro-trust.git
cd tenzro-trust
pip install -e .
```

## Quick Start

```python
from tenzro_trust import get_tenzro_trust

# Initialize a trust provider (simulation mode for development)
trust = get_tenzro_trust(provider_name="hsm")
trust.initialize({
    "hsm_type": "simulated",
    "key_id": "test-key-1"
})

# Sign some transaction data
transaction = b'{"tx_id": "abc123", "sender": "wallet_1", "amount": 50.0}'
signature = trust.sign(transaction)

# Later, verify the signature
is_valid = trust.verify(transaction, signature)
print(f"Signature verification result: {is_valid}")

# Get attestation data if available
attestation = trust.get_attestation()
if attestation:
    print(f"Using hardware provider: {attestation['provider']}")
```

## Project Structure

```
tenzro-trust/
├── tenzro_trust.py              # Core class and factory function
├── providers/                   # Provider implementations
│   ├── __init__.py              # Package exports
│   ├── hsm.py                   # HSM provider
│   ├── tpm.py                   # TPM provider
│   ├── tee.py                   # TEE provider
│   └── mobile.py                # Mobile provider
├── examples/                    # Example code directory
│   ├── hsm_example.py           # HSM usage example
│   ├── tpm_example.py           # TPM usage example
│   └── ...
├── tests/                       # Test directory
│   ├── test_tenzro_trust.py     # Test cases
│   └── ...
└── ...
```

## Available Providers

### HSM Provider
Uses Hardware Security Modules for key storage and operations.

```python
from tenzro_trust import get_tenzro_trust

# Initialize with specific provider type
trust = get_tenzro_trust(provider_name="hsm")
trust.initialize({
    "hsm_type": "aws",  # aws, google, azure, thales, simulated
    "region": "us-west-2",
    "key_id": "alias/tenzro-key"
})
```

### TPM Provider
Uses Trusted Platform Modules for hardware-rooted trust.

```python
from tenzro_trust import get_tenzro_trust

trust = get_tenzro_trust(provider_name="tpm")
trust.initialize({
    "device": "/dev/tpm0",  # TPM device path (Linux)
    "key_handle": "0x81000001",
    "algorithm": "RSA"
})
```

### TEE Provider
Uses Trusted Execution Environments like Intel SGX, ARM TrustZone, etc.

```python
from tenzro_trust import get_tenzro_trust

trust = get_tenzro_trust(provider_name="tee")
trust.initialize({
    "tee_type": "sgx",  # sgx, trustzone, sev, keystone
    "enclave_file": "/path/to/enclave.signed.so",
    "key_name": "tenzro-signing-key"
})
```

### Mobile Provider
Uses mobile device security elements (iOS Secure Enclave, Android KeyStore).

```python
from tenzro_trust import get_tenzro_trust

trust = get_tenzro_trust(provider_name="mobile")
trust.initialize({
    "platform": "ios",  # ios, android
    "key_alias": "tenzro.signing.key",
    "auth_type": "biometric"  # biometric, pin, none
})
```

## Development Mode

For development purposes, all providers support simulation mode:

```python
trust = get_tenzro_trust(provider_name="hsm")
trust.initialize({
    "hsm_type": "simulated",
    "key_id": "dev-key-1"
})
```

**Warning:** Simulation mode does not provide actual hardware security and should only be used for development and testing.

## Configuration

Tenzro Trust can be configured using a JSON file:

```json
{
  "provider": "hsm",
  "hsm_type": "aws",
  "region": "us-west-2",
  "key_id": "alias/tenzro-signing-key"
}
```

Or using environment variables:

```bash
export TENZRO_TRUST_CONFIG='{"provider":"hsm","hsm_type":"aws","region":"us-west-2","key_id":"alias/tenzro-signing-key"}'
```

## Extending with Custom Providers

Creating your own provider is straightforward:

1. Create a new module in the `providers` directory (e.g., `providers/custom.py`)
2. Implement a class inheriting from `TenzroTrustProvider`
3. Name your class appropriately (e.g., `CustomProvider`)
4. Add your provider to `providers/__init__.py`

Example:

```python
# providers/custom.py
from tenzro_trust import TenzroTrustProvider, ConfigurationError

class CustomProvider(TenzroTrustProvider):
    def __init__(self):
        self.initialized = False
        # Your initialization code
    
    def initialize(self, config):
        # Your initialization code
        self.initialized = True
    
    def sign(self, data):
        # Your signing code
        return signature
    
    def verify(self, data, signature):
        # Your verification code
        return is_valid
```

Then add to `providers/__init__.py`:
```python
from .custom import CustomProvider
```

## Examples

Check out the `examples/` directory for sample code demonstrating usage of different providers.

## Documentation

For detailed documentation, see [USAGE.md](USAGE.md).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Testing

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest -v tests/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[Hilal Agil](https://github.com/hilalagil) - Tenzro Ledger System