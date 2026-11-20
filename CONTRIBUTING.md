# Contributing

Contributions are welcome, especially reproducible compatibility reports for additional SBCs and microservers.

Before opening a pull request:

1. Describe the hardware, OS image and kernel version used for testing.
2. Explain whether a change affects privileged actions, network routing, firewall rules or authentication.
3. Add or update automated tests for behavior changes.
4. Run:

   ```bash
   PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
   bash -n install.sh upgrade.sh
   python3 -m py_compile agent.py web.py set_password.py configure_mfa.py
   ```

5. Never include Wi-Fi credentials, private keys, authentication files, session secrets, real public IPs or personal network identifiers in commits, screenshots or logs.

Hardware support claims must be based on testing. Do not describe an untested board as supported.
