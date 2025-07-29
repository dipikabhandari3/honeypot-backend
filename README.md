
````markdown
# 🐝 Honeypot Management API

A Spring Boot-based honeypot management system designed to simulate vulnerable endpoints, detect various types of attacks (SQL Injection, XSS, Brute Force, etc.), and log attack events with geolocation and severity.

## 🚀 Features

- Simulated vulnerable endpoints to attract attackers
- Detection of common attack types:
  - SQL Injection
  - XSS
  - Command Injection
  - Directory Traversal
  - Malware Upload
  - Brute Force Login
  - Unauthorized Access
- Attack logging with IP, user agent, and geolocation
- Returns fake but believable blog and post data

---

## 🧰 Technologies

- Java 17+
- Spring Boot 3.x
- Lombok
- Jakarta Servlet
- Maven Wrapper
- SLF4J for logging

---

## 📦 Prerequisites

- Java JDK 17 or higher
- Git
- Maven (optional, only if not using `./mvnw`)

---

## 🛠️ Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/honeypot-management.git
cd honeypot-management
````

### 2. Build the Project

#### Option A: Using Maven Wrapper (recommended)

```bash
./mvnw clean install
```

#### Option B: Using Local Maven

```bash
mvn clean install
```

### 3. Run the Application

#### Option A: Using Maven Wrapper

```bash
./mvnw spring-boot:run
```

#### Option B: Using Local Maven

```bash
mvn spring-boot:run
```

The application will start on:

```
http://localhost:8080
```

---

## 🌐 API Endpoints

| Method | Endpoint                                 | Description                                                   |
| ------ | ---------------------------------------- | ------------------------------------------------------------- |
| `GET`  | `/api/honeypot/getAllBlogs`              | Returns fake blog data. Detects SQL injection patterns.       |
| `POST` | `/api/honeypot/login`                    | Simulates login. Detects brute force and common credentials.  |
| `POST` | `/api/honeypot/posts`                    | Accepts user post. Detects XSS and command injection.         |
| `GET`  | `/api/honeypot/posts/{id}`               | Returns fake post by ID. Detects directory traversal.         |
| `POST` | `/api/honeypot/upload?file=filename.ext` | Simulates file upload. Detects malware signatures.            |
| `GET`  | `/api/honeypot/admin`                    | Fake admin panel. Always denied. Records unauthorized access. |
| `GET`  | `/api/honeypot/config.php`               | Fake config file. Always denied.                              |
| `GET`  | `/api/honeypot/wp-admin/**`              | Simulated WordPress admin path. Always denied.                |

---

## 📁 Project Structure

```
src/
└── main/
    ├── java/com/example/honeypotmanagement/
    │   ├── controller/       # Main REST controller
    │   ├── service/          # Attack detection + GeoLocation service
    │   ├── model/            # AttackEvent model
    │   ├── enums/            # AttackType and Severity
    └── resources/
        └── application.yml   # Application config (optional)
```

---

## 📌 Notes

* This application is **for research, demo, and education purposes only.**
* Do **not** deploy this in production without strong safeguards.
* Fake responses are crafted to simulate a real environment and attract attacker behavior.

---

## 🛡️ Example Attack Log Data

```json
{
  "attackType": "SQL_INJECTION",
  "sourceIp": "192.168.1.10",
  "targetEndpoint": "/api/honeypot/getAllBlogs",
  "userAgent": "curl/7.68.0",
  "payload": "SQL injection in getAllBlogs",
  "severity": "CRITICAL",
  "geolocation": "Chicago, US"
}
```

---

## 🧪 Testing

You can test endpoints using:

* Postman or Curl
* Browser (for GET requests)
* Angular frontend (CORS enabled for `http://localhost:4200`)

---

## 📄 License

MIT License - for academic and personal use.

---

## 🙋 Contact

For feedback, issues, or contributions, open an issue.

```

