# Personal-Trading-Journal
A clean, fast, self-hosted trading journal built with Flask.

Designed for traders who want to keep a structured, private, and detailed record of their trades, thoughts, and progress — without subscriptions or third-party cloud services.
<img width="1919" height="912" alt="Screenshot 2026-01-02 155417" src="https://github.com/user-attachments/assets/8dde95c7-8efe-4daf-9e9b-1610a513785c" />
<img width="1918" height="914" alt="image" src="https://github.com/user-attachments/assets/28e22060-6c53-402e-83b4-6f0af53511e8" />

Journalling per trade, including reason of the trade and feedback. This is complemented with a image of TA which can be enlarged. On the right side the trade details from the index page are visible. 
<img width="1902" height="915" alt="image" src="https://github.com/user-attachments/assets/03166edf-5c74-4794-94e4-068adcb641e4" />

Trades automatically getting inserted into calendar with win or loss per day. 
<img width="1918" height="915" alt="image" src="https://github.com/user-attachments/assets/d373b0a4-d908-4f6e-9e09-627e8d2c08b5" />
Per day, week or month a journal can be created with week and month journals synced to all connected days. 
<img width="1918" height="916" alt="image" src="https://github.com/user-attachments/assets/4fb3e300-69b4-4c23-b1fd-c6932d49342b" />
Analytics page to see the statitics of your executed trades
<img width="1918" height="912" alt="image" src="https://github.com/user-attachments/assets/83c49243-f782-421c-ba2f-3b68a9aaebef" />




- Full trade logging with support for partial closes and parent/child trade relationships
- Accurate R-multiple calculation across multiple partial exits
- Daily, weekly, and monthly journal entries with calendar overview
- Comprehensive analytics: win rate, expectancy, average R:R, trade duration, long/short bias, monthly performance charts
- Built-in knowledge base (articles, PDFs, videos)
- Image gallery with multi-image posts
- Sticky notes (pinned, colored) and simple todo/ticker lists
- Secure login, CSRF protection, rate limiting, bcrypt password hashing (This application is created to run locally and has partial protection for the internet, if you want to open it to the internet consider adding more security) (No https at the moment since I run it over a VPN)
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

- Stays 100% private and offline
- Doesn't provide PnL, think purely in RR
- Feels instant even with thousands of trades
- Works in the way I want it in my style
- Handles partial closes correctly
- Looks clean and works reliably
- Doesn't have a lot of features that just distract

### Contributing
Pull requests and suggestions are very welcome.
There are still a lot of bugs inside and I work on it when I find it but this is a hobby project.

