# Contributing to FALCO Guardian

Thank you for considering a contribution to FALCO Guardian.

## Project Principles

Contributions should preserve the project's defensive purpose, local-first architecture, and preference for minimal public exposure. Code must not introduce credentials, private keys, customer data, or other secrets into the repository.

## Development Workflow

1. Fork the repository and create a focused branch from the current default branch.
2. Keep each change small enough to review and explain.
3. Preserve existing configuration keys and public interfaces unless the change intentionally introduces a documented migration.
4. Run relevant syntax/build checks before opening a pull request.
5. Update documentation and `CHANGELOG.md` when behavior or configuration changes.
6. Open a pull request describing the problem, the proposed change, testing performed, and any security implications.

## Python

Keep modules readable, typed where useful, and free of generated files such as `__pycache__`. New detectors should have a narrowly defined responsibility and should avoid destructive actions by default.

## eBPF / C

Changes to the eBPF collector must preserve verifier compatibility and clearly document required kernel capabilities. Do not silently broaden privileges or network exposure.

## Security Contributions

Do not open public issues for exploitable vulnerabilities. Follow `SECURITY.md` instead.

## Licensing

By submitting a contribution, you agree that your contribution may be distributed under the repository's GNU General Public License version 2 terms.
