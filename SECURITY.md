# Security Policy

NeonCore Atlas includes a real networking runtime and protocol adapter code. Please treat security reports with care.

Report vulnerabilities privately through the project maintainers. Do not file public issues for bugs that could expose credentials, traffic, local proxy listeners, routing behavior, update delivery, or platform permissions.

Security-sensitive work should include tests, clear threat assumptions, and review notes. Areas that require particular care include profile import validation, daemon IPC, update signing, local listener binding, DNS behavior, TUN/VPN boundaries, TLS configuration, and protocol adapter parsing.
