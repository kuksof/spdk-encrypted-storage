#!/usr/bin/env python3
import argparse
import json
import sys
import requests


def kms_create_key(kms_url: str) -> dict:
    resp = requests.post(f"{kms_url}/keys", timeout=5)
    resp.raise_for_status()
    return resp.json()

def kms_get_dek(kms_url: str, key_id: str) -> str:
    resp = requests.get(f"{kms_url}/keys/{key_id}/dek", timeout=5)
    if resp.status_code == 404:
        raise ValueError(f"KMS: key_id={key_id} not found")
    resp.raise_for_status()

    data = resp.json()
    return data["dek_hex"]

def validate_hex_key(key_hex: str) -> None:
    if len(key_hex) % 2 != 0:
        raise ValueError(f"Invalid DEK length: {len(key_hex)} (must be even)")
    if len(key_hex) != 64:
        raise ValueError(
            f"DEK must be 32 bytes (64 hex chars) but got {len(key_hex)} hex chars"
        )

def build_spdk_config(key1_hex: str, key2_hex: str) -> dict:
    return {
        "subsystems": [
            {
                "subsystem": "bdev",
                "config": [
                    {
                        "method": "bdev_malloc_create",
                        "params": {
                            "name": "Malloc0",
                            "num_blocks": 262144,
                            "block_size": 512
                        }
                    },
                    {
                        "method": "bdev_crypto_create",
                        "params": {
                            "base_bdev_name": "Malloc0",
                            "name": "Crypto0",
                            "cipher": "AES_XTS",
                            "key": key1_hex,
                            "key2": key2_hex
                        }
                    }
                ]
            },
            {
                "subsystem": "nvmf",
                "config": [
                    {
                        "method": "nvmf_create_transport",
                        "params": {
                            "trtype": "TCP",
                            "num_shared_buffers": 4096
                        }
                    },
                    {
                        "method": "nvmf_create_subsystem",
                        "params": {
                            "nqn": "nqn.2016-06.io.spdk:crypto",
                            "serial_number": "SPDK00000001",
                            "max_namespaces": 1,
                            "allow_any_host": True
                        }
                    },
                    {
                        "method": "nvmf_subsystem_add_ns",
                        "params": {
                            "nqn": "nqn.2016-06.io.spdk:crypto",
                            "namespace": {
                                "bdev_name": "Crypto0"
                            }
                        }
                    },
                    {
                        "method": "nvmf_subsystem_add_listener",
                        "params": {
                            "nqn": "nqn.2016-06.io.spdk:crypto",
                            "listen_address": {
                                "trtype": "TCP",
                                "traddr": "127.0.0.1",
                                "trsvcid": "4420"
                            }
                        }
                    }
                ]
            }
        ]
    }

def main():
    parser = argparse.ArgumentParser(
        description="Generate SPDK JSON config with AES-XTS keys from KMS"
    )
    parser.add_argument("--kms-url", default="http://127.0.0.1:8080",
                        help="Base URL of KMS")
    parser.add_argument("--key1-id", help="Existing key_id for AES-XTS key1")
    parser.add_argument("--key2-id", help="Existing key_id for AES-XTS key2")
    parser.add_argument("--output", required=True,
                        help="Where to write config.json")
    parser.add_argument("--new-keys", action="store_true",
                        help="Create two new DEK keys in KMS")

    args = parser.parse_args()
    kms = args.kms_url

    print("[gen_spdk_config] KMS =", kms)

    if args.new_keys:
        print("[gen_spdk_crypto_config] Creating new DEKs...")
        meta1 = kms_create_key(kms)
        meta2 = kms_create_key(kms)

        key1_id = meta1["key_id"]
        key2_id = meta2["key_id"]

        key1_hex = meta1["dek_hex"]
        key2_hex = meta2["dek_hex"]

    else:
        if not args.key1_id or not args.key2_id:
            print("ERROR: Must provide --key1-id and --key2-id "
                  "if --new-keys is not used.")
            sys.exit(1)

        key1_id = args.key1_id
        key2_id = args.key2_id

        print(f"[gen_spdk_crypto_config] Fetching DEK for key1_id={key1_id}")
        key1_hex = kms_get_dek(kms, key1_id)

        print(f"[gen_spdk_crypto_config] Fetching DEK for key2_id={key2_id}")
        key2_hex = kms_get_dek(kms, key2_id)

    validate_hex_key(key1_hex)
    validate_hex_key(key2_hex)

    config = build_spdk_config(key1_hex, key2_hex)

    with open(args.output, "w") as f:
        json.dump(config, f, indent=2)

    print("\n[gen_spdk_crypto_config] Config successfully written:")
    print("  path:", args.output)
    print("  AES-XTS key1 size:", len(key1_hex) // 2, "bytes")
    print("  AES-XTS key2 size:", len(key2_hex) // 2, "bytes")
    print("  key1_id =", key1_id)
    print("  key2_id =", key2_id)
    print("Done.")


if __name__ == "__main__":
    main()