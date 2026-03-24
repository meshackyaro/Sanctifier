# Sanctifier 🛡️

<p align="center">
  <img src="branding/logo.png" width="300" alt="Sanctifier Logo">
</p>

**Sanctifier** is a comprehensive security and formal verification suite built specifically for [Stellar Soroban](https://soroban.stellar.org/) smart contracts. In the high-stakes environment of DeFi and decentralized applications, "code is law" only holds true if the code is secure. Sanctifier ensures your contracts are not just compiled, but *sanctified*—rigorously tested, formally verified, and runtime-guarded against vulnerabilities.

## 📂 Project Structure

```text
Sanctifier/
├── contracts/          # Soroban smart contracts (examples & templates)
├── frontend/           # Next.js Web Interface for the suite
├── tooling/            # The core Rust analysis tools
│   ├── sanctifier-cli  # CLI tool for developers
│   └── sanctifier-core # Static analysis logic
├── scripts/            # Deployment and CI scripts
└── docs/               # Documentation
```

## 🚀 Key Features

### 1. Static Sanctification (Static Analysis)
Sanctifier scans your Rust/Soroban code before deployment to detect:
*   **Authorization Gaps**: ensuring `require_auth` is present in all privileged functions.
*   **Storage Collisions**: analyzing `Instance`, `Persistent`, and `Temporary` storage keys.
*   **Resource Exhaustion**: estimating instruction counts to prevent OOG.

### 2. Runtime Guardians
A library of hook-based guards that you can integrate into your contracts:
*   Runtime invariant checks via `SanctifiedGuard`.
*   Step-by-step integration guide: [`docs/runtime-guards-integration.md`](docs/runtime-guards-integration.md)

### 3. Automated Deployment & Validation (NEW!)
Deploy runtime guard wrapper contracts to Soroban testnet with continuous validation:
*   **CLI Deployment**: One-command contract deployment with `sanctifier deploy`
*   **Bash Automation**: Production-ready scripts for testnet deployment
*   **CI/CD Integration**: GitHub Actions workflow for automated deployment and monitoring
*   **Continuous Validation**: Periodic health checks and execution metrics collection

## 📦 Installation (CLI)

```bash
cargo install --path tooling/sanctifier-cli
```

## 🛠 Usage

### Analyze a Project
Run the analysis suite on your Soroban project:

```bash
sanctifier analyze ./contracts/my-token
```

### Deploy to Soroban Testnet
Deploy runtime guard wrapper contracts with automated validation:

```bash
# Quick start (5 minutes)
sanctifier deploy contracts/runtime-guard-wrapper \
    --network testnet \
    --validate

# OR use the bash automation script
./scripts/deploy-soroban-testnet.sh --network testnet
```

See [QUICK_START.md](QUICK_START.md) for setup instructions and [SOROBAN_DEPLOYMENT.md](SOROBAN_DEPLOYMENT.md) for complete deployment guide.

## Case Studies
Sanctifier is now benchmarked against the official Soroban examples repository.
See [docs/case-studies/soroban-examples.md](docs/case-studies/soroban-examples.md) for the current baseline results and follow-up precision work.

## 🤝 Contributing
We welcome contributions from the Stellar community! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 🔎 Finding Codes
Unified finding codes (`S001`...`S007`) are documented in [docs/error-codes.md](docs/error-codes.md).

## 📄 License
MIT
