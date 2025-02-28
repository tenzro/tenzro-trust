#!/usr/bin/env python3
# tenzro-trust/test_all_providers.py

import os
import json
import time
import sys
import argparse

from tenzro_trust import get_tenzro_trust, TenzroTrustException

def test_provider(provider_name, config, verbose=False):
    """Test a specific provider with given configuration."""
    print(f"\n=== Testing {provider_name.upper()} Provider ===")
    
    try:
        # Get provider instance
        trust = get_tenzro_trust(provider_name=provider_name)
        print(f"✓ Successfully loaded {provider_name} provider")
        
        if verbose:
            print(f"  Provider class: {trust.__class__.__name__}")
            print(f"  Provider module: {trust.__class__.__module__}")
        
        # Initialize with config
        trust.initialize(config)
        print(f"✓ Initialized {provider_name} provider with config:")
        for key, value in config.items():
            if key not in ["provider"]:  # Skip provider key
                print(f"  {key}: {value}")
        
        # Test data
        test_data = {
            "tx_id": f"test_{int(time.time())}",
            "data": "Test transaction data",
            "timestamp": time.time()
        }
        data_bytes = json.dumps(test_data).encode('utf-8')
        
        # Sign data
        signature = trust.sign(data_bytes)
        print(f"✓ Generated signature: {signature.hex()[:16]}...")
        
        # Verify signature (should succeed)
        verification = trust.verify(data_bytes, signature)
        print(f"✓ Verification result: {verification}")
        
        if not verification:
            print("❌ ERROR: Verification failed for original data")
        
        # Modify data and verify (should fail)
        modified_data = test_data.copy()
        modified_data["data"] = "Modified data"
        modified_bytes = json.dumps(modified_data).encode('utf-8')
        
        tamper_verification = trust.verify(modified_bytes, signature)
        if not tamper_verification:
            print(f"✓ Tamper detection works: Modified data verification failed as expected")
        else:
            print("❌ ERROR: Tamper detection failed, modified data verified as valid")
        
        # Get attestation
        attestation = trust.get_attestation()
        if attestation:
            print(f"✓ Attestation available:")
            for key, value in attestation.items():
                print(f"  {key}: {value}")
        else:
            print("ℹ No attestation data available")
        
        return True
        
    except TenzroTrustException as e:
        print(f"❌ Error testing {provider_name}: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error testing {provider_name}: {type(e).__name__}: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return False

def get_default_configs():
    """Get default configurations for all providers."""
    return {
        "hsm": {
            "hsm_type": "simulated",
            "key_id": "test-key-1"
        },
        "tpm": {
            "simulator": True,
            "key_handle": "0x81000001",
            "algorithm": "RSA"
        },
        "tee": {
            "tee_type": "sgx",
            "simulator": True,
            "key_name": "tenzro-test-key"
        },
        "mobile": {
            "platform": "ios",
            "key_alias": "tenzro.test.key",
            "auth_type": "none",
            "simulator": True
        }
    }

def main():
    """Test all available providers."""
    parser = argparse.ArgumentParser(description="Test Tenzro Trust providers")
    parser.add_argument("--config", "-c", help="Path to config file", default="test_config.json")
    parser.add_argument("--provider", "-p", help="Test specific provider only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show verbose output")
    args = parser.parse_args()
    
    print("Tenzro Trust Provider Test")
    print("=========================")
    print(f"Testing provider structure: {'providers package' if 'providers' in sys.modules else 'legacy modules'}")
    
    # Load test configurations
    if os.path.exists(args.config):
        with open(args.config, 'r') as f:
            all_configs = json.load(f)
            print(f"Loaded configuration from {args.config}")
    else:
        all_configs = get_default_configs()
        print("Using default configurations")
    
    # Test each provider
    results = {}
    
    if args.provider:
        # Test specific provider only
        if args.provider in all_configs:
            results[args.provider] = test_provider(args.provider, all_configs[args.provider], args.verbose)
        else:
            print(f"❌ Provider '{args.provider}' not found in configuration")
            return 1
    else:
        # Test all providers
        for provider_name, config in all_configs.items():
            results[provider_name] = test_provider(provider_name, config, args.verbose)
    
    # Print summary
    print("\n=== Test Summary ===")
    all_passed = True
    for provider, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{provider.upper()} Provider: {status}")
        if not success:
            all_passed = False
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())