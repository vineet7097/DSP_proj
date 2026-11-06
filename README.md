# Privacy-Preserving Credential Security Auditor
**Subject:** Data Security & Privacy (DSP) Mini-Project  
**Author:** Vineet  

A command-line security auditing engine that evaluates password strength using Information Theory (Shannon Entropy) and verifies exposure in public breaches via a $k$-Anonymity model.

---

## Key Features & Theoretical Foundations

### 1. Data Security: Shannon Entropy ($H$)
Rather than using simple regular expressions, password complexity is calculated using Shannon Entropy:
$$H = L \times \log_2(R)$$
- **$L$**: Password length  
- **$R$**: Active character pool cardinality (up to 95 printable ASCII symbols)  
- Measures search space resistance ($2^H$) against GPU brute-force attacks.
- Identifies common base patterns and leet-speak substitutions (`@` $\to$ `a`, `0` $\to$ `o`).

### 2. Data Privacy: $k$-Anonymity Verification
- Generates a local SHA-1 digest of the target credential.
- Transmits only the first 5 hexadecimal characters (routing prefix) over TLS.
- Retrieves an anonymity bucket from the breach database containing colliding hash suffixes.
- Matches the remaining 35 characters locally on the client machine.
- **Privacy Guarantee:** The actual password and its full hash are never transmitted over the network.

---

## Installation & Setup

```bash
git clone <https://github.com/vineet7097/DSP_proj.git>
cd Breach-Checker
pip install -r requirements.txt