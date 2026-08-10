from __future__ import annotations

import argparse

from vpn_service.security.admin_password import hash_admin_password


def main() -> None:
    parser = argparse.ArgumentParser(prog="vpn-admin-password-hash")
    parser.add_argument("password")
    args = parser.parse_args()
    print(hash_admin_password(args.password))


if __name__ == "__main__":
    main()
