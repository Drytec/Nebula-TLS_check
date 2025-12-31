# Nebula-TLS_check

Nebula-TLS_check is an interactive terminal-based TLS/SSL security scanner written in Go.  
It allows you to analyze domains, detect SSL/TLS vulnerabilities, calculate security scores, and classify domains through a state-driven CLI interface.

The application is fully Dockerized and can be executed on any platform without installing Go or additional dependencies.

Based on V2 of https://github.com/ssllabs/ssllabs-scan.git

---

## 🔐 Features

- **Interactive CLI interface** with state-based navigation
- **TLS/SSL certificate and protocol scanning** using SSL Labs API
- **Vulnerability detection** (POODLE, Heartbleed, BEAST, etc.)
- **Protocol and cipher suite analysis**
- **Global domain scoring** based on grades, vulnerabilities, and protocols
- **Domain classification** (SECURE / ACCEPTABLE / WEAK / INSECURE / UNKNOWN)
- **History tracking** of previously verified domains
- **Fully containerized** with Docker for cross-platform execution

---

## 🧠 Application Flow

Nebula-TLS_check operates as a **state-based interactive program**:
```
Input Domain → Scanning → Results → Menu → (repeat or exit)
```

### Available Menu Options:
1. **Scan another domain** - Analyze a new domain
2. **Show results again** - Display last scan results
3. **View domains verified** - See history of scanned domains
4. **Exit** - Close the application

After each scan, the menu allows continuous usage without restarting the program.

---

## 🚀 Installation & Usage

### Prerequisites
- **Docker** installed on your system
  - [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
  - [Docker for Linux](https://docs.docker.com/engine/install/)
  - [Docker Desktop for macOS](https://docs.docker.com/desktop/install/mac-install/)

---

## 🐳 Docker Usage (Recommended)

### 1. Clone the Repository
```bash
git clone https://github.com/Drytec/Nebula-TLS_check.git
cd Nebula-TLS_check
```

### 2. Build the Docker Image

**Linux/macOS:**
```bash
sudo docker build -t nebula-tls-check .
```

**Windows (PowerShell/CMD):**
```cmd
docker build -t nebula-tls-check .
```

> **Note:** On Windows, `sudo` is not needed. Run PowerShell or CMD as Administrator if you encounter permission issues.

### 3. Run the Container

**Linux/macOS:**
```bash
sudo docker run -it --rm nebula-tls-check
```

**Windows (PowerShell/CMD):**
```cmd
docker run -it --rm nebula-tls-check
```

**Flags explanation:**
- `-it` - Interactive terminal mode
- `--rm` - Automatically remove container after exit
- `nebula-tls-check` - Image name

---

## 💻 Running Without Docker

If you have Go installed locally (Go 1.16+):

### 1. Clone the Repository
```bash
git clone https://github.com/Drytec/Nebula-TLS_check.git
cd Nebula-TLS_check
```

### 2. Install Dependencies
```bash
go mod download
```

### 3. Run the Application

**Linux/macOS:**
```bash
go run ./program
```

**Windows (PowerShell/CMD):**
```cmd
go run ./program
```

### 4. Build Executable (Optional)

**Linux/macOS:**
```bash
cd program
go build -o nebula-tls-check
./nebula-tls-check
```

**Windows:**
```cmd
cd program
go build -o nebula-tls-check.exe
nebula-tls-check.exe
```

---

## 📊 Example Usage
```
Enter domain to scan: wikipedia.org

Scanning: wikipedia.org

Host: wikipedia.org
State: READY
Vulns Detected: []
Vulns Score: 100
Endpoints Grade: map[A:0 A+:2 B:0 C:0 D:0 E:0 F:0 M:0 T:0]
Grades Score: 100
Protocols Supported: map[TLS:1.2:2]
Protocols Score: 100
Domain Score: 100
Domain Classification: SECURE

Options:
1) Scan another domain
2) Show results again
3) View domains verified
4) Exit
> 1

Enter domain to scan: example.com
```

---

## 🏗️ Project Structure
```
Nebula-TLS_check/
├── program/             # Source code directory
│   ├── main.go         # Entry point and state machine
│   ├── menu.go         # Menu and display functions
│   ├── ssl_scanner.go  # SSL Labs API integration
│   ├── scoring.go      # Scoring and classification logic
│   └── types.go        # Data structures
├── Dockerfile          # Container configuration
├── go.mod              # Go module definition
├── go.sum              # Dependency checksums
└── README.md           # This file
```

---

## 🎯 Scoring System

The application calculates a **global security score** (0-100) based on three components:

### 1. **Vulnerabilities Score** (0-100)
Detects known SSL/TLS vulnerabilities:
- POODLE
- Heartbleed
- DROWN
- FREAK
- Logjam
- OpenSSL CCS Injection

Each vulnerability reduces the score proportionally.

### 2. **Grade Score** (0-100)
Based on SSL Labs letter grades for all endpoints:
- **A+** = 100 points
- **A** = 90 points
- **B** = 80 points
- **C** = 65 points
- **D** = 40 points
- **E, F, M, T** = 0 points

### 3. **Protocol Score** (0-100)
Evaluates supported TLS/SSL protocols:
- **TLS 1.3** - Highest security (100 points)
- **TLS 1.2** - Good security (100 points)
- **TLS 1.1** - Deprecated (-20 points)
- **TLS 1.0** - Deprecated (-20 points)
- **SSL 3.0** - Critical vulnerability (-40 points)
- **SSL 2.0** - Extreme vulnerability (-100 points)

### Final Classification

| Score Range | Classification | Description |
|-------------|----------------|-------------|
| **90-100** | 🟢 **SECURE** | Excellent security posture |
| **75-89** | 🟡 **ACCEPTABLE** | Decent security, minor improvements needed |
| **60-74** | 🟠 **WEAK** | Notable security issues detected |
| **0-59** | 🔴 **INSECURE** | Critical security vulnerabilities |
| **N/A** | ⚪ **UNKNOWN** | Domain unreachable or scan failed |

---

## 🛠️ Troubleshooting

### Docker Issues

#### **Linux: Permission Denied**
If you get `permission denied` errors with Docker:
```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the group changes
newgrp docker

# Or logout and login again
```

Alternatively, always use `sudo` before docker commands:
```bash
sudo docker run -it --rm nebula-tls-check
```

#### **Windows: Docker not starting**
- Ensure **WSL2** is installed and updated
- Enable **virtualization** in BIOS settings
- Run **Docker Desktop as Administrator**
- Check if Hyper-V is enabled (Windows Pro/Enterprise)

#### **macOS: Docker Desktop issues**
- Ensure Docker Desktop is running
- Check system resources (memory, disk space)
- Try restarting Docker Desktop

---

### Common Errors

#### **"Cannot connect to the Docker daemon"**

**Linux:**
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

**Windows/macOS:**
- Start Docker Desktop application
- Wait for the whale icon to stop animating

---

#### **"no Go files in /home/user/Truora"**

This happens when running Go commands from the wrong directory. The source files are in the `program/` subdirectory.

**Solution:**
```bash
# From project root
go run ./program

# Or navigate to the program directory
cd program
go run .
```

---

#### **"Rate limit exceeded" from SSL Labs API**

SSL Labs API has rate limits to prevent abuse:
- **Overall:** Limited number of concurrent assessments

**Solution:**
- Avoid rapid consecutive scans
---

#### **"Domain unreachable" or "ERROR" status**

Possible causes:
- Domain doesn't exist
- Domain doesn't support HTTPS
- Firewall blocking SSL Labs servers
- Temporary network issues

**Solution:**
- Verify the domain has a valid SSL/TLS certificate
- Try adding `https://` prefix if needed
- Wait and try again later

---

## 🧪 Testing the Application

### Quick Test Domains

Try these domains to see different security scores:
```bash
# Excellent security (A+ grade)
wikipedia.org
github.com

# Good security (A grade)
google.com
amazon.com

# Lower grades (for testing scoring system)
badssl.com
expired.badssl.com
```

---

### Development Guidelines
- Follow Go best practices and conventions
- Add comments for complex logic
- Test thoroughly before submitting
- Update documentation for new features

---

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

---

## 👤 Author

**Drytec**  
GitHub: [@Drytec](https://github.com/Drytec)

---

## 🙏 Acknowledgments

- [SSL Labs API](https://www.ssllabs.com/ssltest/) for providing the security assessment service
- Go community for excellent libraries and tools

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security assessment purposes only**.

- Always obtain **proper authorization** before scanning domains you don't own
- Respect SSL Labs' [Terms of Service](https://www.ssllabs.com/about/terms.html)
- Do not use for malicious purposes or unauthorized penetration testing
- The authors are not responsible for misuse of this tool

---

**Happy Scanning! 🔒**