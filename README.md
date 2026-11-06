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


Poore project ko step-by-step, ekdum simple aur real-life engine code level par samajhte hain ki **DSP Audit** andar se kaise kaam karta hai:

---

## 1. Project Ka Core Aim (Ye Software Banaya Kyun Hai?)

Aaj kal cybersecurity mein sabse bada issue hai **Credential Exposure**. Users simple passwords rakhte hain ya ek hi password har jagah reuse karte hain.

Jab aap Google par koi normal "Password Checker" website kholte ho aur apna password type karte ho, toh risk ye rehta hai ki aapka plaintext password unke server par chala jata hai.

**DSP Audit** iska ek **Local, Transparent aur Privacy-First** solution hai. Ye do kaam karta hai:

1. **Password kitna strong hai** (Math aur Entropy se calculate karta hai).
2. **Password leak hua hai ya nahi** (Internet par plain password bheje bina check karta hai).

---

## 2. DSP Audit Ke 2 Main Pillars (Kaam Kaise Karta Hai?)

```
                     ┌─────────────────────────────────────────┐
                     │          Input: "P@ssword123"           │
                     └────────────────────┬────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  │                                               │
                  ▼                                               ▼
     [Pillar 1: Complexity Analysis]                [Pillar 2: Privacy Leak Check]
     • Character Pool & Length                      • SHA-1 Hash Local Generation
     • Shannon Entropy Math                         • Prefix (First 5 chars) sent to API
     • Brute-Force Crack Time                       • Local Hash Matching (k-Anonymity)
                  │                                               │
                  └───────────────────────┬───────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │       Detailed Audit Report Generated   │
                     └─────────────────────────────────────────┘

```

---

### **Pillar 1: Information Theory Complexity Analysis**

Yahan password ki mathematical strength check hoti hai bina kisi prediction ya guessing ke:

1. **Character Pool Size ($R$):**
* Password mein kis type ke characters hain: Lowercase ($26$), Uppercase ($26$), Numbers ($10$), Special symbols ($32$).
* Agar koi "abc" likhega toh pool size $26$ hoga. Agar "Abc1!" likhega toh pool size $26+26+10+32 = 94$ hoga.


2. **Shannon Entropy Formula ($H$):**
* Mathematics ke Information Theory ka formula use hota hai:

$$H = L \times \log_2(R)$$


* Jahan $L$ = Password length, $R$ = Character Pool Size.
* Result **bits** mein aata hai. E.g., $60+$ bits entropy matlab mathematically continuous attack withstand kar sakta hai.


3. **Predictable Pattern Vulnerabilities:**
* Standard words check karna (e.g., `admin`, `password`, `123456`).
* Common substitutions check karna (e.g., `@` ko `a` ki jagah likhna).


4. **Brute-Force Crack Time Estimate:**
* Total possible combinations = $R^L$.
* Aagay fast computer (e.g., $10^{10}$ guesses per second) se calculate karna ki password crack hone mein kitne seconds/years lagenge.



---

### **Pillar 2: Privacy-Preserving Leak Verification ($k$-Anonymity)**

Ye tumhare project ki sabse main highlight hai.

Suppose user ne password dala: `Secret123`

1. **Local Hashing:**
* Code local system par hi Python ki `hashlib` se `Secret123` ka **SHA-1 Hash** generate karta hai:
`SHA-1("Secret123")` $\rightarrow$ `67C6A05F02D02B6D553757F3A536F3D416B19020`


2. **$k$-Anonymity SHA-1 Prefixing:**
* Poocha Hash API ko **nahi** bheja jata.
* Sirf pehle **5 characters** (`67C6A`) HaveIBeenPwned breach API ko bheje jaate hain.


3. **Server Response:**
* Breach Intelligence Database us 5-character prefix se match hone wale hazaron thousands compromised hashes ka response (suffixes) wapas bhejta hai.


4. **Local Matching:**
* Application baki bache 35 characters ko local system par comparison karti hai.
* Agar exact match mil jata hai, toh application bata deti hai ki *"Ye password X number of data breaches mein leak ho chuka hai!"*



> **Key Privacy Guarantee:** Target password real-world server tak ya internet traffic mein **kabhi bhi plaintext format mein nahi jata**.

---

## 3. System Modes & Output

User project ko do tariqon se chala sakta hai:

* **Single Password Audit:** Live terminal ya Streamlit dashboard par ek single password check karna.
* **Batch-File Audit:** Pehle se banni CSV/Text file upload karke hazaron credentials ko ek saath scan karke summary risk report CSV download karna.

---

### **Ek Line Mein Summary:**

> **DSP Audit** ek local Python security auditor hai jo **Shannon Entropy** se password ki mathematical strength batata hai aur **SHA-1 $k$-Anonymity** se zero-knowledge privacy guarantee ke sath leaked passwords check karta hai.
