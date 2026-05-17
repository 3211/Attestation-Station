# ATTESTATION STATION

**Zero-Trust E2EE & TEE Endpoint Auditor**
*Built by Lake Boiler Labs*

---

## The Philosophy: Snitch-as-a-Service

Cloud API providers and decentralized AI networks claim to offer End-to-End Encryption (E2EE) and Trusted Execution Environment (TEE) hardware isolation. The problem is that standard web dashboards and server-side metadata can lie. If you are handling mission-critical, private data, trusting a provider's own "Verified" green checkmark is a failure of operational security.

**Attestation Station** is an uncompromising, stateless local proxy auditor. It does not ask for trust; it demands cryptographic proof. 

By running this utility locally on your own hardware, it acts as an independent forensic appraiser:
1. It intercepts the E2EE handshake to verify your ephemeral keys and the server's public identity.
2. It parses the raw binary hardware quote (e.g., Intel TDX) to ensure the model is running inside a genuine, un-tampered secure enclave without debug flags enabled.
3. It decrypts the streaming AES-256-GCM token payload locally, proving mathematically that no middleman intercepted or cached the data in transit.

If the infrastructure is clean, it passes. If the hardware layout deviates from standard bare-metal configurations (such as utilizing custom decentralized orchestration wrappers), the tool exposes the discrepancy.

---

## CRITICAL: Target URL Architecture

The target URLs and model IDs provided in the interface are **examples only**, currently modeled after Venice's E2EE routing structure at the time of publication (e.g., `https://api.venice.ai/api/v1`). 

**You must input the exact, fully-qualified URL path required by your specific TEE provider.** Different providers, decentralized networks, and localized clusters utilize wildly different API versioning and routing namespaces. Attestation Station does not perform hidden string manipulation or "magic" URL formatting behind the scenes to fix lazy inputs. If you point the auditor at the wrong namespace, the cryptographic handshake will fail and throw a 404 or 502 error. Know your target's infrastructure before running the audit.

---

## Installation & Execution

Attestation Station is designed to be cloned and run strictly on your local machine to ensure zero-trust contamination. 

### Manual Execution
```bash
git clone [repository-url]
cd attestation-station
npm install
npm start
```

### Windows Quick Start
A convenience batch file is provided for Windows users. Double-click `start_attestation.bat` or run it from the terminal:
```cmd
start_attestation.bat
```

---
