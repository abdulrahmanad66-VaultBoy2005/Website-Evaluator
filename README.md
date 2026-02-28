# 🔒 Website Evaluator

A powerful web application that helps users identify phishing websites, scams, and malicious URLs using Google Safe Browsing API, intelligent heuristic analysis, and community reviews.

![Website Evaluator Demo](https://via.placeholder.com/800x400.png?text=Website+Evaluator+Demo)

## ✨ Live Demo

**[🌐 Click here to try the live app](https://your-app.up.railway.app)** (Add your Railway URL here once deployed)

---

## 🎯 Features

### 🛡️ **Dual-Layer Security Check**
- **Google Safe Browsing API** - Checks URLs against Google's database of 1M+ known malicious sites
- **Heuristic Analysis Engine** - Detects new/emerging scams using 15+ smart rules
  - Suspicious TLD detection (.xyz, .top, .club, .work, etc.)
  - Brand impersonation detection (fake PayPal, Amazon, banks)
  - URL structure analysis (IP addresses, long URLs, special characters)
  - SSL/HTTPS verification
  - Website age estimation with month display

### 👥 **Community Reviews**
- Users can share their experiences with websites
- 5-star rating system
- Read others' reviews before visiting suspicious sites
- IP-based tracking to prevent spam
- Average rating display for quick trust assessment
- Real-time updates

### 🎨 **User-Friendly Interface**
- Clean, modern UI with gradient design
- Color-coded results (GREEN, BLUE, YELLOW, ORANGE, RED)
- **Dark mode toggle** for comfortable viewing
- Mobile-responsive design
- One-click example URLs for testing
- Smooth animations and transitions

---

## 📊 **Risk Scoring System**

| Score | Color | Meaning | User Advice |
|-------|-------|---------|-------------|
| 0-9 | 🟢 GREEN | Safe - Legitimate website | "This website appears legitimate and safe to use" |
| 10-29 | 🔵 BLUE | Low Risk - Minor concerns | "Minor issues but probably safe" |
| 30-49 | 🟡 YELLOW | Caution - Some concerns | "Some suspicious characteristics" |
| 50-69 | 🟠 ORANGE | Suspicious - Strong scam indicators | "Shows strong signs of being a scam" |
| 70-100 | 🔴 RED | Dangerous - Confirmed malicious | "Do not visit! Multiple warning signs" |

---

## 🏗️ **Technology Stack**

| Layer | Technology |
|-------|------------|
| **Backend** | Java 17, Spring Boot 3.1.5 |
| **Database** | MySQL 8.0 with JPA/Hibernate |
| **External API** | Google Safe Browsing API |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Build Tool** | Maven |
| **Deployment** | Railway (Cloud) |
| **Security** | Input validation, Rate limiting, IP tracking |

---

## 📁 **Project Structure**
