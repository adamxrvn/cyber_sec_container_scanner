# CyberSecScanner

CyberSecScanner is a distributed system designed to identify, manage, and report vulnerabilities in software applications or infrastructure. This project operates as a combination of microservices, each dedicated to specific responsibilities like scanning for vulnerabilities, managing database models, and triggering alerts for critical findings.

## Table of Contents

1. [Features](#features)
2. [Architecture Overview](#architecture-overview)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Project Structure](#project-structure)
6. [Configuration](#configuration)


---

## Features

- **Vulnerability Scanning:** Automated scanning for software vulnerabilities using the `scanning_service`.
- **Alerting System:** Notification system that triggers alerts for detected vulnerabilities or security incidents.
- **Database Management:** Manages storage of vulnerability data and schemas.
- **Modular Components:** Built with modular service-based architecture for flexibility and scalability.

---

## Architecture Overview

The system is built using a microservices architecture and comprises the following services:

### 1. `Scanning Service`
- Responsible for executing the vulnerability scans.
- Includes models and schemas for scan data.
- Utilizes dependencies specified in `requirements.txt`.

### 2. `Vulnerabilities Management Service`
- Handles storage, updates, and retrieval of vulnerability data.
- Backed by a database for persistence using `SQLAlchemy`.

### 3. `Alert Service`
- Sends out notifications and alerts based on triggered events.
- Ensures awareness of critical vulnerabilities.

---

## Installation

Follow these steps to set up the project.

### 1. Clone the Repository

```bash
git clone <repository-url>
cd CyberSecScanner
```

### 2. Install Dependencies

Each service has its own requirements file. Navigate to each service directory and install the dependencies:

```bash
cd scanning_service
pip install -r requirements.txt
```

Repeat for other services (`vulnerabilities_management`, etc.) as needed.

### 3. Set Up Docker (Optional)

Use the provided `Dockerfile` to containerize the services. Example:

```bash
cd scanning_service
docker build -t scanning-service .
docker run -p 5000:5000 scanning-service
```

---

## Usage

1. Start each service.
2. Configure the `ingress.yaml` if deploying to a Kubernetes cluster.
3. Access the APIs provided by each service for scanning, alerts, or managing vulnerabilities.
4. Check logs for any errors or debugging purposes when services communicate.

---

## Project Structure

```plaintext
CyberSecScanner/
│
├── scanning_service/
│   ├── app.py                # Main application logic for scanning
│   ├── models.py             # Database models for vulnerabilities
│   ├── schemas.py            # API schemas for parsing and validating data
│   ├── requirements.txt      # Python dependencies for scanning service
│   ├── Dockerfile            # Dockerfile for containerizing scanning service
│   └── ...
│
├── vulnerabilities_management/
│   ├── app.py                # Main application logic for vulnerability management
│   ├── models.py             # Database models for vulnerability data
│   └── ...
│
├── alert_service/
│   ├── app.py                # Main application logic for sending alerts
│   └── ...
│
├── ingress.yaml              # Kubernetes ingress configuration file
├── readme.md                 # Readme documentation for the project
└── ...
```

---

## Configuration

### Environment Variables

Each service supports various environment variables for configuration. Example values can include:

- `DATABASE_URL`: URL for the database connection.
- `ALERT_SERVICE_PORT`: Port to run the alert service.
- `SCANNING_SERVICE_API_KEY`: API key for secure usage of scanning service.

### Kubernetes Deployment

- Modify the `ingress.yaml` file with domain and paths.
- Use it with `kubectl` for deploying services.

```bash
kubectl apply -f ingress.yaml
```

---

