# 🚀 Backend Engineer Home Assignment: Container Security Scanner

Welcome to the "Container Security Scanner Challenge!"  
Your mission: build a robust backend service that scans Docker container images for vulnerabilities using Trivy, stores the results, and provides a clean API to query security data.

---

## 🎯 Objective

Build a complete backend service that:
- Periodically scans container images for CVE vulnerabilities using Trivy
- Stores scan results in a database of your choice
- Exposes a REST API for querying vulnerability data

---

## 📋 Your Tasks

### 1. 🔍 Image Scanner Service

Build a background service that scans these 10 container images:

1. `nginx:1.19`
2. `postgres:12`
3. `redis:6.0`
4. `node:14-alpine`
5. `python:3.8-slim`
6. `alpine:3.12`
7. `ubuntu:20.04`
8. `mysql:8.0`
9. `mongo:4.4`
10. `httpd:2.4`

**Requirements:**
- Scan each image **every 15 minutes**
- Extract CVE information: CVE ID, severity, package name, installed version, fixed version
- Handle scan failures gracefully (image not found, Trivy errors, etc.)
- Store results in your database

### 2. 🗄️ Database Design

Design and implement a database schema to store:
- Images (name, tag, last scan timestamp, scan status)
- CVEs (CVE ID, severity level, description/title)
- The relationship between images and their CVEs
- Package/dependency information

**Choose any database:** PostgreSQL, MySQL, MongoDB, SQLite, etc.

### 3. 🌐 REST API

Implement the following endpoints:

#### **GET /api/cves/:cve_id/images**
Returns all images affected by a specific CVE, including package details.

#### **GET /api/images/:image_name/:tag/cves**
Returns all CVEs found in a specific image with severity filter.

**Query Parameters:**
- `severity`: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)

#### **GET /api/images**
List all scanned images with summary statistics (total CVEs by severity).

#### **GET /api/cves**
List all unique CVEs found across all images with severity filter.

**Query Parameters:**
- `severity`: Filter by severity level

#### **GET /health**
Health check endpoint.

---

## 📦 Deliverables

### **A working codebase:**
- Clean structure (scanner service, API layer, database layer, etc.)
- Instructions to run locally (README with prerequisites, setup, and run commands)
- API endpoint documentation with example requests
- Database schema description or diagram

---

## 🚢 Submission

- Create a fork of this repository and give access to your fork
- Ensure the application can be set up and run locally with clear instructions

---

Have fun! For all questions and clarifications – don't hesitate to reach out 🙂  
Good luck! 🚀
