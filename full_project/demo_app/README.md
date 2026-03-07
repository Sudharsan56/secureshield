# 🛡️ SecureShield — Flask Demo App

A live web demo showing SecureShield blocking real web attacks in your browser.

## 🚀 Run Locally in 3 Steps

```bash
# 1. Go into this folder
cd demo_app

# 2. Install Flask
pip install flask

# 3. Start the server
python app.py
```

Then open your browser and go to: **http://localhost:5000**

---

## 📸 What You'll See

- **Home Page** — Live URL scanner with one-click attack test buttons
- **Blocked Page** — Shown when a real attack URL is detected (HTTP 403)
- **Report Page** — Full log of every attack detected at `/report`

---

## 🧪 Test URLs to Try

| Type | Test URL |
|---|---|
| ✅ Safe | `https://example.com/search?q=python+tutorial` |
| 💉 SQL Injection | `https://example.com/login?user=admin'--` |
| ⚡ XSS | `https://example.com/page?x=<script>alert(1)</script>` |
| 📂 Path Traversal | `https://example.com/file?path=../../etc/passwd` |
| 💻 Command Injection | `https://example.com/ping?host=localhost;ls` |

---

## 🔗 Deploy Online (Free)

You can host this demo for free on **Render.com** or **Railway.app**:

1. Push this folder to GitHub
2. Connect your GitHub to [render.com](https://render.com)
3. Set start command: `python app.py`
4. Your live link will be: `https://secureshield-demo.onrender.com`

---

## 📦 Library Source

The core library lives in `../secureshield/`

```
pip install secureshield
```
