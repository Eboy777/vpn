from __future__ import annotations

from vpn_service.security.discovery_signing import generate_discovery_key_pair


def main() -> None:
    private_key, public_key = generate_discovery_key_pair()
    print(f"DISCOVERY_SIGNING_PRIVATE_KEY={private_key}")
    print(f"extension discoveryPublicKeys.v1={public_key}")


if __name__ == "__main__":
    main()
