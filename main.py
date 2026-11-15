#cd ~/red-team-agent
#source .venv/bin/activate

import getpass

from engine.orchestrator import run_full_scan


def main():
    try:
        password = getpass.getpass("LDAP password: ")
        run_full_scan(password, log=print)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")

    except Exception as error:
        print(f"\n[!] Scan failed: {error}")


if __name__ == "__main__":
    main()
