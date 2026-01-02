# Personal-Trading-Journal
A clean, fast, self-hosted trading journal built with Flask.

Designed for traders who want to keep a structured, private, and detailed record of their trades, thoughts, and progress — without subscriptions or third-party cloud services.
<img width="1917" height="911" alt="Screenshot 2025-12-30 214058" src="https://github.com/user-attachments/assets/39266a10-025b-4f6f-8460-506679a1450d" />

- **Full trade logging** with support for partial closes and parent/child trade relationships
- Accurate R-multiple calculation across multiple partial exits
- Daily, weekly, and monthly journal entries with calendar overview
- Comprehensive analytics: win rate, expectancy, average R:R, trade duration, long/short bias, monthly performance charts
- Built-in knowledge base (articles, PDFs, videos)
- Image gallery with multi-image posts
- Sticky notes (pinned, colored) and simple todo/ticker lists
- Secure login, CSRF protection, rate limiting, bcrypt password hashing
- Could be run locally or on your NAS — your data never leaves your machine

### Quick Start

git clone https://github.com/yourusername/sts-trading-journal.git
cd sts-trading-journal
pip install -r requirements.txt
python app.py

Open your browser: http://127.0.0.1:5000

Default credentials
Email: admin@admin.com
Password: 12345678
(Change immediately after first login)

### Why I built this
I wanted a journal that:

Stays 100% private and offline
Doesn't provide PnL, think purely in RR
Feels instant even with thousands of trades
Works in the way I want it
Handles partial closes correctly
Looks clean and works reliably
Doesn't have a lot of features that just distract

### Contributing
Pull requests and suggestions are very welcome.
There are still a lot of bugs inside and I work on it when I find it but this is a hobby project.

