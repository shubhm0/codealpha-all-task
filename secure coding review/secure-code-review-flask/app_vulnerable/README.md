# TeamNotes (Vulnerable Target Application)

> ⚠️ **CRITICAL SECURITY WARNING**
> **THIS APPLICATION IS INTENTIONALLY VULNERABLE.**
> It was designed strictly for academic coursework, secure code review exercises, and static analysis demonstration.
> **DO NOT DEPLOY THIS APPLICATION TO PRODUCTION OR EXPOSE IT TO THE INTERNET / PUBLIC NETWORKS.**

---

## Overview

**TeamNotes** is a lightweight Python/Flask web application designed to look like a junior developer's initial prototype for a internal team note-sharing portal. It allows users to register, log in, manage personal notes, upload document attachments, search notes, view public user profiles, and manage system resources via an admin dashboard.

However, the codebase contains **14 critical security vulnerabilities** intentionally introduced for code auditing and security analysis coursework.

---

## Intentionally Included Vulnerabilities Summary

- **# VULN-01**: SQL Injection (Unsanitized string concatenation in SQL queries for login & search)
- **# VULN-02**: Broken Access Control / IDOR (Note viewing and deletion routes lack ownership checks)
- **# VULN-03**: Missing Authorization Check (Admin dashboard accessible by non-admin authenticated users)
- **# VULN-04**: Insecure Cryptographic Storage (User passwords stored as unsalted MD5 hashes)
- **# VULN-05**: Hardcoded Credentials & Secrets (Secret key and database config hardcoded in source)
- **# VULN-06**: Reflected Cross-Site Scripting (XSS) (Unescaped search query rendered via Jinja `| safe`)
- **# VULN-07**: Server-Side Template Injection (SSTI) (User profile bio string passed directly into `render_template_string`)
- **# VULN-08**: Path Traversal (File download endpoint accepts relative path sequences like `../`)
- **# VULN-09**: Unrestricted File Upload (File uploads permit arbitrary extensions, MIME types, and sizes)
- **# VULN-10**: Insecure Deserialization (`pickle` object deserialization used for cookie session handling)
- **# VULN-11**: Debugger Enabled in Production (`debug=True` active and custom exception handlers exposing tracebacks)
- **# VULN-12**: Missing CSRF Protection (State-changing POST endpoints lack CSRF token verification)
- **# VULN-13**: Weak Session Cookie Flags (`HttpOnly=False`, `Secure=False`, `SameSite=None`)
- **# VULN-14**: Vulnerable & Outdated Dependencies (Outdated Flask, Werkzeug, Jinja2, PyYAML versions pinned)

---

## Local Execution Instructions

1. Navigate to the application directory:
   ```bash
   cd app_vulnerable
   ```
2. Create and activate a virtual environment (Python 3.9+ recommended):
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application locally:
   ```bash
   python app.py
   ```
5. Open your browser and navigate to `http://127.0.0.1:5000`.

Default test accounts created automatically on database initialization:
- **Admin**: Username: `admin` | Password: `admin123`
- **Standard User**: Username: `alice` | Password: `password123`
