# STS Trading Journal 
# Lightning fast, faster than most other tradesystems

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, g
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from functools import wraps, lru_cache
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
import pandas as pd
from datetime import datetime
import io
import math
from datetime import datetime, timedelta, date
import configparser
import re
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

from PIL import Image
import io
import time

import calendar
import logging
from logging.handlers import RotatingFileHandler
import json

app = Flask(__name__)
csrf = CSRFProtect(app)

handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=5)  # 10MB per file, keep 5 backups
handler.setLevel(logging.DEBUG)  # Capture everything
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)  # Set Flask to debug level

logging.basicConfig(handlers=[handler], level=logging.DEBUG)

app.config['SESSION_COOKIE_SAMESITE'] = "Strict"
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['WTF_CSRF_TIME_LIMIT'] = 86400
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=7)])
    submit = SubmitField('Login')

config = configparser.ConfigParser()
config.read('config.ini')
app.secret_key = config['flask']['secret_key']
bcrypt = Bcrypt(app)
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':  # Detect AJAX
        return jsonify({'success': False, 'message': 'Invalid or missing CSRF token. Please refresh and try again.'}), 400
    else:  
        flash('Invalid or missing CSRF token. Please try again.', 'error')
        return redirect(request.url), 400

DATABASE = 'data10.db'
app.config['UPLOAD_FOLDER']= 'static/uploads'
KNOWLEDGE_UPLOAD_FOLDER = 'static/uploads/knowledge'
os.makedirs(KNOWLEDGE_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4', 'webm', 'ogg'}
app.config["MAX_CONTENT_LENGTH"] = 1024*1024*1024
app.config['PERMANENT_SESSION_LIFETIME'] = 14400

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
@limiter.limit("5 per minute") 

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    
    if form.validate_on_submit(): 
        email = form.email.data
        password = form.password.data

        email_regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        if not re.match(email_regex, email):
            flash('Please enter a valid email address.', 'error')
            return render_template('login.html', form=form)  
        
        if len(password) < 7:
            flash('Password must be at least 7 characters long.', 'error')
            return render_template('login.html', form=form)

        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        user = cursor.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = email
            print("Redirecting to:", url_for('index', _external=True))
            return redirect(url_for('index', _external=True))
        else:
            flash('Invalid credentials', 'error')
            return render_template('login.html', form=form)  
    

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def migrate_gallery_table():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gallery'")
    if not cursor.fetchone():
        print("Gallery table does not exist yet. Skipping migration.")
        conn.close()
        return
 
    cursor.execute("SELECT id, image_path FROM gallery")
    rows = cursor.fetchall()
    updated = False
    for row in rows:
        image_path = row['image_path']
        if image_path:  # Skip if null/empty
            try:
                json.loads(image_path)  # If it's already valid JSON, skip
            except json.JSONDecodeError:
                json_paths = json.dumps([image_path])
                cursor.execute("UPDATE gallery SET image_path = ? WHERE id = ?", (json_paths, row['id']))
                updated = True
    
    conn.commit()
    conn.close()
    if updated:
        print("Gallery table migrated to support multi-images in image_path.")
    else:
        print("Gallery table already supports multi-images.")
    
     
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    migrate_gallery_table()
   

    cursor.execute('''CREATE TABLE IF NOT EXISTS trades (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    symbol TEXT NOT NULL, 
                    open_time TEXT,
                    close_time TEXT,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    sort TEXT NOT NULL,
                    open_price REAL,
                    close_price REAL,
                    risk REAL,
                    SL REAL,
                    TP REAL,
                    RR REAL,
                    reason TEXT,
                    feedback TEXT,
                    reason_image TEXT,
                    feedback_image TEXT,
                    parent_id INTEGER)''')

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_id ON trades(parent_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_open_time ON trades(open_time)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON trades(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_symbol ON trades(symbol)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sort ON trades(sort)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_id ON trades(parent_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_open ON trades(parent_id, open_time DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_parent_status ON trades(parent_id, status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_close_time ON trades(close_time)")

   

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS journal_entries(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   date DATE NOT NULL,
                   entry_type TEXT NOT NULL CHECK(entry_type IN('daily', 'weekly', 'monthly')),
                   content TEXT,
                   week_start_date DATE,
                   month_start_date DATE,
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='journal_entries'")
    row = cursor.fetchone()
    if row and "'monthly'" not in row[0]: 
        cursor.execute("ALTER TABLE journal_entries RENAME TO journal_entries_old")
        cursor.execute('''CREATE TABLE journal_entries(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date DATE NOT NULL,
                    entry_type TEXT NOT NULL CHECK(entry_type IN('daily', 'weekly', 'monthly')),
                    content TEXT,
                    week_start_date DATE,
                    month_start_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute("INSERT INTO journal_entries SELECT * FROM journal_entries_old") 
        cursor.execute("DROP TABLE journal_entries_old")
        print("Migrated journal_entries table: Added 'monthly' to CHECK constraint.")
    conn.commit() 

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_journal_date ON journal_entries(date)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_journal_type ON journal_entries(entry_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_journal_week ON journal_entries(week_start_date)")

    ##todo
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS todos1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_type TEXT NOT NULL, -- 'ticker' or 'todo'
            content TEXT NOT NULL,
            completed INTEGER DEFAULT 0
        )
    ''')
    ###notes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT NOT NULL,
            color TEXT DEFAULT 'yellow',
            pinned INTEGER DEFAULT 0, 
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            image_url TEXT DEFAULT NULL
        )
    ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS gallery (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    image_path TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_gallery_title ON gallery(title)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_gallery_description ON gallery(description)")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS knowledge_articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT,
            tags TEXT,
            featured_image TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
            type TEXT
        )
    ''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_title ON knowledge_articles(title)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge_articles(category)")



    user_count = cursor.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if user_count == 0:
        default_email = 'admin@admin.com'
        default_password = '12345678'
        hashed = generate_password_hash(default_password)
        cursor.execute('INSERT INTO users (email, password) VALUES (?,?)', (default_email, hashed))

    conn.commit()
     




def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, timeout=30.0, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL;")
        g.db.execute("PRAGMA synchronous=NORMAL;")
        g.db.execute("PRAGMA cache_size=-64000;")   # 64MB cache
        g.db.execute("PRAGMA foreign_keys=ON;")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_parent_rr_with_partials(parent, partials):
    total_realized_r = 0.0
    total_risk_closed = 0.0

    def r_multiple(sort, open_price, close_price, SL):
        if None in (open_price, close_price, SL):
            return 0.0
        try:
            if sort == 'SHORT':
                return (open_price - close_price) / (SL - open_price)
            elif sort == 'LONG':
                return (close_price - open_price) / (open_price - SL)
            else:
                return 0.0
        except ZeroDivisionError:
            return 0.0

    for partial in partials:
        if partial['status'] == 'CLOSED' and partial['close_price'] is not None and partial['risk'] is not None:
            r_mult = r_multiple(parent['sort'], partial['open_price'] or parent['open_price'], partial['close_price'], parent['SL'])
            total_realized_r += r_mult * partial['risk']
            total_risk_closed += partial['risk']

    parent_risk = parent['risk'] if parent['risk'] is not None else 0.0
    if parent['status'] == 'CLOSED' and parent['close_price'] is not None and parent_risk > 0:
        r_mult = r_multiple(parent['sort'], parent['open_price'], parent['close_price'], parent['SL'])
        total_realized_r += r_mult * parent_risk
        total_risk_closed += parent_risk

    if total_risk_closed == 0:
        return None

    return round(total_realized_r / total_risk_closed, 2)

def parse_time(s):
    if not s:
        return None
    s = s.replace('T', ' ').strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None
def compress_image(file, max_width=2000, quality=100):  #
    try:
        file.seek(0)  
        img = Image.open(file)
        file.seek(0)  
        original_format = img.format.lower() if img.format else 'jpeg'

        if original_format in ['jpg', 'jpeg'] and img.width <= max_width:
            file.seek(0)  # Return original untouched
            logging.info("Skipping compression for JPEG (no resize needed)")
            return file

        resized = False
        if img.width > max_width:
            ratio = max_width / float(img.width)
            new_height = int(float(img.height) * ratio)
            img = img.resize((max_width, new_height), Image.LANCZOS)
            resized = True
        
        output = io.BytesIO()
        
        if original_format in ['jpg', 'jpeg']:
            img.save(output, format='JPEG', quality=quality, optimize=True)
        elif original_format == 'png':
            img.save(output, format='PNG', optimize=True, compress_level=5)  
        else:

            img.save(output, format='PNG', optimize=True, compress_level=5)
        
        output.seek(0)
        return output
    except Exception as e:
        logging.error(f"Image compression failed: {e}")
        file.seek(0)  
        return file  
    
init_db()


@app.route('/')
@login_required
def index():
    date_filter = request.args.get('date_filter', 'last30')
    search_query = request.args.get('search', '').strip()
    
    # Pagination (highly recommended!)
    page = request.args.get('page', 1, type=int)
    per_page = 30
    offset = (page - 1) * per_page

    conn = get_db()
    params = []
    now = datetime.now()

    conditions = ["parent_id IS NULL"]
    
    # Date filters
    if date_filter == 'today':
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'week':
        start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=6, hours=23, minutes=59, seconds=59)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'month':
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = (start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])
        
    elif date_filter == 'year':
        start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        end = now.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
        conditions.append("open_time >= ? AND open_time <= ?")
        params.extend([start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S')])

    elif date_filter == 'last30':
        start = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
        conditions.append("open_time >= ?")
        params.append(start.strftime('%Y-%m-%d %H:%M:%S'))    

    # Search
    if search_query:
        search_param = f"%{search_query}%"
        search_conditions = [
            "symbol LIKE ?", "status LIKE ?", "sort LIKE ?", "type LIKE ?",
            "CAST(open_price AS TEXT) LIKE ?", "CAST(close_price AS TEXT) LIKE ?",
            "reason LIKE ?", "feedback LIKE ?"
        ]
        conditions.append(f"({' OR '.join(search_conditions)})")
        params.extend([search_param] * len(search_conditions))

    where_clause = " AND ".join(conditions)

    parent_query = f"SELECT * FROM trades WHERE {where_clause} ORDER BY id DESC"
    parents = conn.execute(parent_query, params).fetchall()[:500]

    # === Fetch partials for all parents in ONE query ===
    parent_ids = [p['id'] for p in parents]
    partials_by_parent = {}


    # 2. Fetch ALL partials in ONE query (only if needed)
    if parent_ids:
        placeholders = ','.join(['?'] * len(parent_ids))
        partials_query = "SELECT *, parent_id FROM trades WHERE parent_id IN (" + placeholders + ")"
        partial_rows = conn.execute(partials_query, parent_ids).fetchall()
        
        for row in partial_rows:
            pid = row['parent_id']
            if pid not in partials_by_parent:
                partials_by_parent[pid] = []
            partials_by_parent[pid].append(dict(row))

    # Process parents and calculate RR
    processed_parents = []
    for parent_row in parents:
        parent = dict(parent_row)
        partials = partials_by_parent.get(parent['id'], [])
        
        if partials:
            parent['calculated_RR'] = calculate_parent_rr_with_partials(parent, partials)
        else:
            parent['calculated_RR'] = parent['RR']

        if parent['status'] == 'CLOSED' and partials:
            total_closed_risk = sum(p['risk'] or 0 for p in partials if p['status'] == 'CLOSED')
            parent['risk'] = total_closed_risk or parent['risk']

        processed_parents.append(parent)



    @lru_cache(maxsize=12)
    def get_monthly_rr_cached(year_month: str):
        result = conn.execute("""
            SELECT COALESCE(SUM(RR), 0) FROM trades 
            WHERE parent_id IS NULL AND status = 'CLOSED' 
              AND strftime('%Y-%m', close_time) = ?
        """, (year_month,)).fetchone()
        return result[0]

    monthly_rr = get_monthly_rr_cached(datetime.now().strftime('%Y-%m'))

     

    return render_template(
        'index.html',
        trades=processed_parents,
        partials_by_parent=partials_by_parent,
        monthly_rr=monthly_rr,
        page=page,
        date_filter=date_filter,
        search=search_query or None
    )




@app.route('/journal', methods=['GET', 'POST'])
@app.route('/journal/<date_str>', methods=['GET', 'POST'])
@login_required
def journal(date_str=None):
    #print(f"Journal called with date_str: {date_str}, method: {request.method}")

    if request.method == 'POST':
        #print("POST request received")
        date_str = request.form.get('date')
        entry_type = request.form.get('entry_type')
        content = request.form.get('content', '').strip()
        #print(f"Form data - date: {date_str}, type: {entry_type}, content length: {len(content)}")
        
        try:
            journal_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if entry_type == 'weekly':
                week_start = journal_date - timedelta(days=journal_date.weekday())

            elif entry_type == 'monthly':
                month_start = journal_date.replace(day=1)
            else:
                week_start = None
                month_start = None 
        except ValueError:
            flash('Invalid date format', 'error')
            return redirect(url_for('journal'))
        
        conn = get_db()
        
        try:
            if entry_type == 'daily':
                existing = conn.execute("""
                    SELECT id FROM journal_entries 
                    WHERE date = ? AND entry_type = 'daily'
                """, (date_str,)).fetchone()
            elif entry_type == 'weekly':  
                existing = conn.execute("""
                    SELECT id FROM journal_entries 
                    WHERE week_start_date = ? AND entry_type = 'weekly'
                """, (week_start.isoformat(),)).fetchone()

            elif entry_type == 'monthly':
                existing = conn.execute("""
                    SELECT id FROM journal_entries 
                    WHERE month_start_date = ? AND entry_type = 'monthly'
                """, (month_start.isoformat(),)).fetchone()
            
            if existing:
                conn.execute("""
                    UPDATE journal_entries 
                    SET content = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                """, (content, existing['id']))

            else:
                if entry_type == 'daily':
                    conn.execute("""
                        INSERT INTO journal_entries (date, entry_type, content) 
                        VALUES (?, ?, ?)
                    """, (date_str, entry_type, content))
                elif entry_type == 'weekly':  
                    conn.execute("""
                        INSERT INTO journal_entries (date, entry_type, content, week_start_date) 
                        VALUES (?, ?, ?, ?)
                    """, (date_str, entry_type, content, week_start.isoformat()))
                elif entry_type == 'monthly':
                    conn.execute("""
                        INSERT INTO journal_entries (date, entry_type, content, month_start_date) 
                        VALUES (?, ?, ?, ?)
                    """, (date_str, entry_type, content, month_start.isoformat()))

            
            conn.commit()
            flash(f'{entry_type.title()} journal saved!', 'success')
        except Exception as e:
            print(f"Database error: {e}")
            flash('Error saving journal entry', 'error')

             
        
        return redirect(url_for('journal', date_str=date_str))
    
    if date_str:
        #print(f"Showing daily view for {date_str}")
        try:
            journal_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            week_start = journal_date - timedelta(days=journal_date.weekday())
            month_start = journal_date.replace(day=1)  
        except ValueError:
            flash('Invalid date format', 'error')
            return redirect(url_for('journal'))
        
 
        conn = get_db()

        trades = conn.execute("""
            SELECT * FROM trades
            WHERE parent_id IS NULL 
            AND DATE(open_time) = ?
            ORDER BY open_time
        """, (date_str,)).fetchall()

        daily_entry = conn.execute("""
            SELECT * FROM journal_entries 
            WHERE date = ? AND entry_type = 'daily'
        """, (date_str,)).fetchone()
        
        weekly_entry = conn.execute("""
            SELECT * FROM journal_entries 
            WHERE week_start_date = ? AND entry_type = 'weekly'
        """, (week_start.isoformat(),)).fetchone()

        monthly_entry = conn.execute("""
            SELECT * FROM journal_entries 
            WHERE month_start_date = ? AND entry_type = 'monthly'
        """, (month_start.isoformat(),)).fetchone()
        
         
        
        return render_template('daily_journal.html',
                             date=journal_date,
                             date_str=date_str,
                             week_start=week_start,
                             trades=trades,
                             daily_entry=daily_entry,
                             weekly_entry=weekly_entry,
                             monthly_entry=monthly_entry)
    

    year = int(request.args.get('year', datetime.now().year))
    month = int(request.args.get('month', datetime.now().month))

    cal = calendar.monthcalendar(year, month)
    month_name = calendar.month_name[month]
    

    conn = get_db()

    trades_query = f"""
        SELECT DATE(open_time) as trade_date, COUNT(*) as trade_count,
               SUM(CASE WHEN RR > 0 THEN 1 ELSE 0 END) as wins,
               SUM(CASE WHEN RR < 0 THEN 1 ELSE 0 END) as losses
        FROM trades
        WHERE parent_id IS NULL 
        AND strftime('%Y-%m', open_time) = ?
        GROUP BY DATE(open_time)
    """
    trades_data = {}
    for row in conn.execute(trades_query, (f"{year:04d}-{month:02d}",)):
        trades_data[row['trade_date']] = {
            'count': row['trade_count'],
            'wins': row['wins'],
            'losses': row['losses']
        }

    journal_query = """
        SELECT date, entry_type, 
               CASE WHEN LENGTH(content) > 0 THEN 1 ELSE 0 END as has_content
        FROM journal_entries 
        WHERE strftime('%Y-%m', date) = ?
    """
    journal_data = {}
    for row in conn.execute(journal_query, (f"{year:04d}-{month:02d}",)):
        date_str_loop = row['date']
        if date_str_loop not in journal_data:
            journal_data[date_str_loop] = {}
        journal_data[date_str_loop][row['entry_type']] = row['has_content']
    

    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1
    
    return render_template('journal.html', 
                         calendar_data=cal,
                         year=year, 
                         month=month,
                         month_name=month_name,
                         trades_data=trades_data,
                         journal_data=journal_data,
                         prev_year=prev_year,
                         prev_month=prev_month,
                         next_year=next_year,
                         next_month=next_month,
                         today=date.today().isoformat())
@app.route('/analytics', methods=['GET', 'POST'])
@login_required
def analytics():
    conn = get_db()
    period = request.args.get('period', 'monthly') 
    now = datetime.now()
    end_date = None


    if period == 'monthly':
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == 'last_month':
        first_of_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_end = first_of_this_month - timedelta(days=1)
        start_date = last_month_end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_date = last_month_end.replace(hour=23, minute=59, second=59, microsecond=999999)
    elif period=='yearly':
        start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        start_date=None

    date_filter, params = get_date_filter(start_date, end_date)

    try:
        types = ['HTF', 'MTF', 'LTF']
        sql = 'SELECT COUNT(*) as count FROM trades WHERE parent_id IS NULL'
        if date_filter.strip():
            sql += " " + date_filter
        total_trades_result = conn.execute(sql, params).fetchone()
        total_trades = total_trades_result['count'] if total_trades_result else 0

        sql='''SELECT type, COUNT(*) as count FROM trades WHERE parent_id IS NULL GROUP BY type'''
        if date_filter.strip():
            sql += " " + date_filter
        trades_per_type = conn.execute(sql, params).fetchall()
        trades_per_type_dict = {row['type']: row['count'] for row in trades_per_type}
        trades_per_type_complete = {t: trades_per_type_dict.get(t, 0) for t in types}


        #Win Rate RR
        sql = '''
            SELECT id, RR FROM trades
            WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL
        '''
        if date_filter.strip():
            sql += " " + date_filter
        closed_trades_query = conn.execute(sql, params).fetchall()
        
        closed_trades_count = len(closed_trades_query)
        winning_trades_count = sum(1 for trade in closed_trades_query if trade['RR'] > 0)
        breakeven_count = sum(1 for trade in closed_trades_query if trade['RR'] == 0)
        losing_trades_count = closed_trades_count - winning_trades_count - breakeven_count
        
        win_rate = (winning_trades_count / closed_trades_count * 100) if closed_trades_count > 0 else 0

        sql = '''
            SELECT type,
                COUNT(*) as closed_count,
                SUM(CASE WHEN RR > 0 THEN 1 ELSE 0 END) as win_count,
                SUM(CASE WHEN RR = 0 THEN 1 ELSE 0 END) as breakeven_count,
                SUM(CASE WHEN RR < 0 THEN 1 ELSE 0 END) as loss_count
            FROM trades
            WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL
            GROUP BY type
        '''
        if date_filter.strip():
            sql += " " + date_filter
        type_stats = conn.execute(sql, params).fetchall()

        type_stats_dict = {}
        for row in type_stats:
            type_stats_dict[row['type']] = {
                'closed_count': row['closed_count'],
                'win_count': row['win_count'],
                'breakeven_count': row['breakeven_count'],
                'loss_count': row['loss_count'],
                'win_rate': (row['win_count'] / row['closed_count'] * 100) if row['closed_count'] > 0 else 0
            }

        types = ['HTF', 'MTF', 'LTF']
        for t in types:
            if t not in type_stats_dict:
                type_stats_dict[t] = {
                    'closed_count': 0,
                    'win_count': 0,
                    'breakeven_count': 0,
                    'loss_count': 0,
                    'win_rate': 0
                }
        

        #Average Trade Duration 
        sql = '''
            SELECT open_time, close_time FROM trades
            WHERE parent_id IS NULL AND status = 'CLOSED'
            AND open_time IS NOT NULL AND close_time IS NOT NULL
        '''
        if date_filter.strip():
            sql += " " + date_filter
        closed_trades_for_duration = conn.execute(sql, params).fetchall()

        duration_sum = 0
        duration_count = 0
        for trade in closed_trades_for_duration:
            open_dt = parse_time(trade['open_time'])
            close_dt = parse_time(trade['close_time'])
            if open_dt and close_dt and close_dt > open_dt:
                duration_sum += (close_dt - open_dt).total_seconds()
                duration_count += 1
        
        avg_trade_duration_seconds = (duration_sum / duration_count) if duration_count > 0 else 0
        avg_trade_duration_days = avg_trade_duration_seconds / (86400) #seconds in a day

        #Long/Short Ratio
        sql_long = 'SELECT COUNT(*) as count FROM trades WHERE parent_id IS NULL AND sort = "LONG"'
        if date_filter.strip():
            sql_long += " " + date_filter
        long_trades_count = conn.execute(sql_long, params).fetchone()['count']

        sql_short = 'SELECT COUNT(*) as count FROM trades WHERE parent_id IS NULL AND sort = "SHORT"'
        if date_filter.strip():
            sql_short += " " + date_filter
        short_trades_count = conn.execute(sql_short, params).fetchone()['count']
        
        total_long_short = long_trades_count + short_trades_count
        if total_long_short > 0:
            long_ratio = (long_trades_count / total_long_short * 100)
            short_ratio = (short_trades_count / total_long_short * 100)
            long_short_ratio = "{long_ratio:.1f}% Long / {short_ratio:.1f}% Short"
        else:
            long_ratio = 0
            short_ratio = 0
            long_short_ratio = "N/A"

        sql = '''
            SELECT type, sort, COUNT(*) as count
            FROM trades
            WHERE parent_id IS NULL
            GROUP BY type, sort
        '''
        if date_filter.strip():
            sql += " " + date_filter
        results = conn.execute(sql, params).fetchall()
        types = ['HTF', 'MTF', 'LTF']
        sorts = ['LONG', 'SHORT']

        long_short_per_type = {t: {'long_count': 0, 'short_count': 0} for t in types}

        for row in results:
            t = row['type']
            s = row['sort']
            if t in types and s in sorts:
                if s == 'LONG':
                    long_short_per_type[t]['long_count'] = row['count']
                elif s == 'SHORT':
                    long_short_per_type[t]['short_count'] = row['count']


        #Total RR for closed trades in period for index
        sql = '''
            SELECT SUM(RR) as total_rr FROM trades
            WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL
        '''
        if date_filter.strip():
            sql += " " + date_filter
        total_rr_result = conn.execute(sql, params).fetchone()
        total_rr = total_rr_result['total_rr'] if total_rr_result and total_rr_result['total_rr'] is not None else 0
        sql = '''
            SELECT type, SUM(RR) as total_rr
            FROM trades
            WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL
            GROUP BY type
        '''
        if date_filter.strip():
            sql += " " + date_filter
        results = conn.execute(sql, params).fetchall()
        types = ['HTF', 'MTF', 'LTF']
        total_rr_per_type = {t: 0 for t in types}

        for row in results:
            t = row['type']
            if t in types:
                total_rr_per_type[t] = row['total_rr'] if row['total_rr'] is not None else 0


    #Highest RR
        sql_max_rr = '''
        WITH filtered_data AS (
            SELECT rr
            FROM trades
            WHERE parent_id IS NULL 
            AND symbol IS NOT NULL 
            AND rr > 0  -- Only consider wins (rr > 0)
        )
        SELECT MAX(rr) AS max_rr  
        FROM filtered_data
        '''
        if date_filter.strip():
            sql += " " + date_filter
        max_rr_results = conn.execute(sql_max_rr, params).fetchall()

        if not max_rr_results: 
            highest_rr = "N/A"
        else:
            max_rr_value = max_rr_results[0]['max_rr']
            highest_rr = "{:.2f}".format(max_rr_value) if max_rr_value is not None else "N/A"


        #average RR
        average_rr = total_rr/closed_trades_count if closed_trades_count > 0 else 0

        #median RR
        sql_median_rr = '''
            WITH ordered_rr AS (
                SELECT rr FROM trades WHERE parent_id IS NULL 
                AND symbol IS NOT NULL 
                
                ORDER BY rr),
            count_rr AS (
                SELECT COUNT(*) as total FROM ordered_rr),
            ranked_rr AS (
                SELECT 
                    rr,
                    ROW_NUMBER() OVER (ORDER BY rr) as row_num
                FROM ordered_rr)
            SELECT 
                AVG(rr) as median_rr
            FROM ranked_rr, count_rr
            WHERE 
                (total % 2 = 1 AND row_num = (total + 1) / 2)
                OR (total % 2 = 0 AND row_num IN (total/2, total/2 + 1))
            '''
        if date_filter.strip():
            sql += " " + date_filter
        result = conn.execute(sql_median_rr, params).fetchone()
        if result and result['median_rr'] is not None:
            median_rr = "{:.2f}".format(result['median_rr'])

        else:
            median_rr =  "N/A"

        #most used symbol
        sql_most_ticker = '''
        WITH symbol_counts AS (
            SELECT symbol, COUNT(*) as cnt
            FROM trades
            WHERE parent_id IS NULL AND symbol IS NOT NULL
            GROUP BY symbol
        ),
        max_cnt AS (
            SELECT MAX(cnt) as max_cnt FROM symbol_counts
        )
        SELECT symbol, cnt
        FROM symbol_counts
        WHERE cnt = (SELECT max_cnt FROM max_cnt)
        '''
        most_ticker_results = conn.execute(sql_most_ticker, params).fetchall()

        if len(most_ticker_results) > 1:
            most_used_ticker = "N/A"
        else:
            most_used_ticker = most_ticker_results[0]['symbol'] if most_ticker_results else "N/A"

        ##rr graph
        rr_labels = []
        rr_values = []

        if period == 'monthly':
            year = now.year
            month = now.month
            num_days = calendar.monthrange(year, month)[1]
            rr_labels = [f"{year}-{month:02d}-{day:02d}" for day in range(1, num_days+1)]
            sql = """
                SELECT DATE(close_time) as day, SUM(RR) as rr_sum
                FROM trades
                WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL
                AND strftime('%Y-%m', close_time) = :month
                GROUP BY day
                ORDER BY day
            """
            params_graph = {'month': f"{year}-{month:02d}"}
            day_rr = {row['day']: row['rr_sum'] for row in conn.execute(sql, params_graph)}
            rr_values = [float(day_rr.get(label, 0) or 0) for label in rr_labels]

        elif period == 'yearly':
            year = now.year
            rr_labels = [calendar.month_abbr[m] for m in range(1, 13)]
            sql = """
                SELECT strftime('%m', close_time) as month, SUM(RR) as rr_sum
                FROM trades
                WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL
                AND strftime('%Y', close_time) = :year
                GROUP BY month
                ORDER BY month
            """
            params_graph = {'year': str(year)}
            month_rr = {int(row['month']): row['rr_sum'] for row in conn.execute(sql, params_graph)}
            rr_values = [float(month_rr.get(m, 0) or 0) for m in range(1, 13)]

        else:
            sql = """
                SELECT close_time, RR FROM trades
                WHERE parent_id IS NULL AND status = 'CLOSED' AND RR IS NOT NULL
                ORDER BY close_time DESC LIMIT 30
            """
            rr_labels = []
            rr_values = []
            for row in conn.execute(sql):
                rr_labels.append(row['close_time'][:10])  
                rr_values.append(float(row['RR'] or 0))
            rr_labels.reverse()
            rr_values.reverse()
        


        analytics_data = {
            'total_trades': total_trades,
            'win_count': winning_trades_count,
            'loss_count': losing_trades_count,
            'breakeven_count': breakeven_count,
            'win_rate': win_rate,
            'avg_trade_duration': avg_trade_duration_days,
            'long_count': long_trades_count,
            'short_count': short_trades_count,
            'long_ratio': long_ratio,
            'short_ratio': short_ratio,
            'long_short_ratio': long_short_ratio,
            'total_rr': total_rr,
            'highest_rr': highest_rr,
            'average_rr': average_rr,
            'median_rr': median_rr,
            'most_used_ticker': most_used_ticker,
            'trades_per_type': trades_per_type_complete,
            'type_stats': type_stats_dict,
            'long_short_per_type': long_short_per_type,
            'total_rr_per_type': total_rr_per_type,
            'rr_labels': rr_labels,
            'rr_values': rr_values
        }

    except Exception as e:

        analytics_data = {
            'total_trades': 0,
            'win_count': 0,
            'loss_count': 0,
            'breakeven_count': 0,
            'win_rate': 0,
            'avg_trade_duration': 0,
            'long_count': 0,
            'short_count': 0,
            'long_ratio': 0,
            'short_ratio': 0,
            'long_short_ratio': "N/A",
            'highest_rr': "N/A",
            'average_rr': 0,
            'median_rr': "N/A",
            'most_used_ticker': "N/A"
        }

    return render_template('analytics.html', analytics_data=analytics_data, period=period)

@app.route('/rules', methods=['GET', 'POST'])
@login_required
def rules():
    return render_template('rules.html')

@app.route('/todo', methods=['GET', 'POST'])
@login_required
def todo():
    conn = get_db()

    if request.method == 'POST':
        action = request.form.get('action')
        list_type = request.form.get('list_type')
        todo_id = request.form.get('todo_id')
        content = request.form.get('content', '').strip()

        if action == 'add' and content and list_type in ['ticker', 'todo']:
            if list_type == 'ticker':
                content = content.upper()
            conn.execute('INSERT INTO todos1 (list_type, content) VALUES (?, ?)', (list_type, content))
        elif action == 'edit' and todo_id and content:
            conn.execute('UPDATE todos1 SET content=? WHERE id=?', (content, todo_id))
        elif action == 'delete' and todo_id:
            conn.execute('DELETE FROM todos1 WHERE id=?', (todo_id,))
        elif action == 'toggle' and todo_id:
            todo = conn.execute('SELECT completed FROM todos1 WHERE id=?', (todo_id,)).fetchone()
            if todo:
                new_status = 0 if todo['completed'] else 1
                conn.execute('UPDATE todos1 SET completed=? WHERE id=?', (new_status, todo_id))
        conn.commit()

    tickers = conn.execute('SELECT * FROM todos1 WHERE list_type="ticker" ORDER BY id').fetchall()
    todos = conn.execute('SELECT * FROM todos1 WHERE list_type="todo" ORDER BY id').fetchall()
     
    return render_template('todo.html', tickers=tickers, todos=todos)

@app.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    conn = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        note_id = request.form.get('id')
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        color = request.form.get('color', 'yellow')

        if action == 'create' and content:
            conn.execute('INSERT INTO notes1 (title, content, color) VALUES (?, ?, ?)',
                         (title, content, color))
            conn.commit()
            flash('Note created!', 'success')
            
        elif action == 'edit' and note_id and content:
            conn.execute('UPDATE notes1 SET title=?, content=?, color=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                         (title, content, color, note_id))
            conn.commit()
            flash('Note updated!', 'success')
            
        elif action == 'delete' and note_id:
            conn.execute('DELETE FROM notes1 WHERE id=?', (note_id,))
            conn.commit()
            flash('Note deleted!', 'success')
            
        elif action == 'pin' and note_id:
            pinned = 1 if request.form.get('pinned') == '0' else 0
            conn.execute('UPDATE notes1 SET pinned=? WHERE id=?', (pinned, note_id))
            conn.commit()

    search = request.args.get('search', '').strip()
    search_condition = ''
    params = []
    if search:
        search_condition = 'WHERE (title LIKE ? OR content LIKE ?)'
        search_param = f'%{search}%'
        params = [search_param, search_param]

    notes_list = conn.execute(f'''
        SELECT * FROM notes1 
        {search_condition}
        ORDER BY pinned DESC, updated_at DESC
    ''', params).fetchall()
     

    pinned_notes = [note for note in notes_list if note['pinned']]
    other_notes = [note for note in notes_list if not note['pinned']]

    return render_template('notes.html', pinned_notes=pinned_notes, other_notes=other_notes, search=search)



@app.route('/gallery', methods=['GET', 'POST'])
@login_required
def gallery():
    conn = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            images = request.files.getlist('images')
            
            if not title:
                flash('Title is required', 'error')
                 
                return redirect(url_for('gallery'))  
            
            if not images or any(not allowed_file(img.filename) for img in images if img.filename):
                flash('Invalid image file(s)', 'error')
                 
                return redirect(url_for('gallery')) 
            image_paths = []
            for image in images:
                if image.filename == '': continue
                filename = secure_filename(image.filename)
                filename = f"gallery_{int(time.time())}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(filepath)
                image_paths.append(filename)
            
            if not image_paths:
                flash('At least one image required', 'error')
                 
                return redirect(url_for('gallery')) 
            
            json_paths = json.dumps(image_paths)
            conn.execute('INSERT INTO gallery (title, description, image_path) VALUES (?, ?, ?)',
                         (title, description, json_paths))
            conn.commit()
            flash('Post added successfully!', 'success')
             
            return redirect(url_for('gallery'))
        
        elif action == 'edit':
            img_id = request.form.get('id')
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            if img_id and title:
                conn.execute('UPDATE gallery SET title=?, description=? WHERE id=?',
                             (title, description, img_id))
                conn.commit()
                flash('Post updated successfully!', 'success')
                 
                return redirect(url_for('gallery'))
            else:
                flash('Invalid edit data', 'error')
                 
                return redirect(url_for('gallery'))  
        
        elif action == 'delete':
            img_id = request.form.get('id')
            if img_id:
                img = conn.execute('SELECT image_path FROM gallery WHERE id=?', (img_id,)).fetchone()
                if img and img['image_path']:
                    try:
                        paths = json.loads(img['image_path'])
                    except json.JSONDecodeError:
                        paths = [img['image_path']]
                    for path in paths:
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], path))
                        except OSError:
                            pass
                conn.execute('DELETE FROM gallery WHERE id=?', (img_id,))
                conn.commit()
                flash('Post deleted successfully!', 'success')
                 
                return redirect(url_for('gallery'))
            else:
                flash('Invalid delete request', 'error')
                 
                return redirect(url_for('gallery'))  
       
        flash('Invalid action', 'error')
         
        return redirect(url_for('gallery'))

    search = request.args.get('search', '').strip()
    search_condition = ''
    params = []
    if search:
        search_condition = 'WHERE (title LIKE ? OR description LIKE ?)'
        search_param = f'%{search}%'
        params = [search_param, search_param]
    
    images_rows = conn.execute(f'''
        SELECT * FROM gallery
        {search_condition}
        ORDER BY created_at DESC
    ''', params).fetchall()
    
    images = [] 
    for row in images_rows:
        try:
            paths = json.loads(row['image_path']) if row['image_path'] else []
        except json.JSONDecodeError:
            paths = [row['image_path']] if row['image_path'] else []
        images.append({
            'id': row['id'],
            'title': row['title'],
            'description': row['description'],
            'image_path': paths,
            'created_at': row['created_at']
        })
    
     
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'images': images})
    
    return render_template('gallery.html', images=images, search=search)


@app.route('/knowledge', methods=['GET', 'POST'])
@app.route('/knowledge/<int:article_id>', methods=['GET', 'POST'])
@login_required
def knowledge(article_id=None):
    conn = get_db()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        action = request.form.get('action') or request.args.get('action')
        
        if action == 'get_article':
            article = conn.execute('SELECT * FROM knowledge_articles WHERE id = ?', 
                                  (request.args.get('id'),)).fetchone()
            if article:
                 
                return jsonify({
                    'id': article['id'],
                    'title': article['title'],
                    'content': article['content'],
                    'category': article['category'],
                    'tags': article['tags'],
                    'featured_image': article['featured_image'],
                    'type': article['type'] or 'document',  # Fallback
                    'created_at': article['created_at'][:10] if article['created_at'] else '',
                    'updated_at': article['updated_at'][:10] if article['updated_at'] else ''
                })
             
            return jsonify({'error': 'Article not found'}), 404
        
        elif action == 'delete':
            try:
                del_article_id = request.form.get('id')
                article = conn.execute('SELECT featured_image FROM knowledge_articles WHERE id = ?', 
                                      (del_article_id,)).fetchone()
                
                if article and article['featured_image']:
                    try:
                        os.remove(os.path.join(KNOWLEDGE_UPLOAD_FOLDER, article['featured_image']))
                    except OSError:
                        pass
                
                conn.execute('DELETE FROM knowledge_articles WHERE id = ?', (del_article_id,))
                conn.commit()
                 
                return jsonify({'success': True})
            except Exception as e:
                 
                return jsonify({'success': False, 'error': str(e)}), 500
        
        elif action == 'edit':
            try:
                edit_article_id = request.form.get('id')
                title = request.form.get('title', '').strip()
                content = request.form.get('content', '')
                category = request.form.get('category', '')
                tags = request.form.get('tags', '')
                entry_type = request.form.get('type', 'document')
                
                if not title:
                    return jsonify({'success': False, 'error': 'Title is required'}), 400
                
                conn.execute('''
                    UPDATE knowledge_articles 
                    SET title=?, content=?, category=?, tags=?, type=?, updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                ''', (title, content, category, tags, entry_type, edit_article_id))
                conn.commit()
                 
                return jsonify({'success': True})
            except Exception as e:
                 
                return jsonify({'success': False, 'error': str(e)}), 500

    if request.method == 'POST' and not request.headers.get('X-Requested-With'):
        action = request.form.get('action')
        entry_type = request.form.get('type', 'document')  
        
        if action in ['upload', 'edit']:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '')
            category = request.form.get('category', '')
            tags = request.form.get('tags', '')
            
            if not title:
                flash('Title is required', 'error')
                 
                return redirect(url_for('knowledge'))
            
            file = request.files.get('file')
            filename = None
            if file and file.filename:
                file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
                allowed_extensions = {'pdf', 'mp4', 'webm', 'ogg', 'avi', 'mov', 'png', 'jpg', 'jpeg', 'gif'}
                if file_ext not in allowed_extensions:
                    flash('Invalid file type', 'error')
                     
                    return redirect(url_for('knowledge'))
                
                filename = secure_filename(file.filename)
                timestamp = int(time.time())
                filename = f"{timestamp}_{filename}"
                filepath = os.path.join(KNOWLEDGE_UPLOAD_FOLDER, filename)
                os.makedirs(KNOWLEDGE_UPLOAD_FOLDER, exist_ok=True)
                
                try:
                    with open(filepath, 'wb') as f:
                        while True:
                            chunk = file.stream.read(1024 * 1024)  
                            if not chunk:
                                break
                            f.write(chunk)
                except Exception as e:
                    flash(f'Upload failed: {str(e)}', 'error')
                     
                    return redirect(url_for('knowledge'))
            
            if action == 'upload':
                created_at = datetime.utcnow().isoformat()
                conn.execute('''
                    INSERT INTO knowledge_articles (title, content, category, tags, featured_image, created_at, type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (title, content, category, tags, filename, created_at, entry_type))
                conn.commit()
                flash('Entry added successfully!', 'success')
            
            elif action == 'edit' and article_id:
                sql = '''
                    UPDATE knowledge_articles 
                    SET title=?, content=?, category=?, tags=?, type=?, updated_at=CURRENT_TIMESTAMP
                '''
                params = [title, content, category, tags, entry_type]
                if filename:  
                    old_article = conn.execute('SELECT featured_image FROM knowledge_articles WHERE id=?', (article_id,)).fetchone()
                    if old_article and old_article['featured_image']:
                        try:
                            os.remove(os.path.join(KNOWLEDGE_UPLOAD_FOLDER, old_article['featured_image']))
                        except OSError:
                            pass
                    sql += ', featured_image=?'
                    params.append(filename)
                sql += ' WHERE id=?'
                params.append(article_id)
                conn.execute(sql, params)
                conn.commit()
                flash('Entry updated successfully!', 'success')
            
             
            return redirect(url_for('knowledge'))

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    query = 'SELECT * FROM knowledge_articles WHERE 1=1'
    params = []

    if search:
        query += ' AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)'
        search_param = f'%{search}%'
        params.extend([search_param, search_param, search_param])

    if category_filter:
        query += ' AND category LIKE ?'
        params.append(f'%{category_filter}%')

    query += ' ORDER BY created_at DESC'

    articles = conn.execute(query, params).fetchall()

    categories_result = conn.execute('''
        SELECT category FROM knowledge_articles 
        WHERE category IS NOT NULL AND category != ''
    ''').fetchall()

    all_categories = set()
    for row in categories_result:
        all_categories.update(c.strip() for c in row['category'].split(',') if c.strip())

    categories = sorted(all_categories)

    selected_article = None
    if article_id:
        selected_article = conn.execute('SELECT * FROM knowledge_articles WHERE id = ?', 
                                       (article_id,)).fetchone()

    articles_list = []
    for article in articles:
        article_dict = {
            'id': article['id'],
            'title': article['title'],
            'content': article['content'],
            'category': article['category'],
            'tags': article['tags'],
            'featured_image': article['featured_image'],
            'created_at': article['created_at'],
            'type': article['type'] or 'document'  
        }
        articles_list.append(article_dict)

  
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'articles': articles_list})

    return render_template('knowledge.html', 
                           articles=articles_list,
                           categories=categories,
                           search=search,
                           selected_category=category_filter,
                           selected_article=selected_article)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    APP_VERSION = datetime.now().strftime('%B %d, %Y')
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    user = cursor.execute('SELECT * FROM users LIMIT 1').fetchone()

    if request.method == 'POST':
        if 'new_email' in request.form:
            new_email = request.form['new_email']
            cursor.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user['id']))
            conn.commit()
            flash('Email updated successfully!', 'success')
            session['username'] = new_email
            return redirect(url_for('settings'))
        elif 'current_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            
            if not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            else:
                hashed = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, user['id']))
                conn.commit()
                flash('Password changed successfully!', 'success')
            return redirect(url_for('settings'))
        
    
    return render_template('settings.html', user=user, app_version=APP_VERSION)

@app.route('/toggle_theme', methods=['POST'])
@login_required
def toggle_theme():
    current = session.get('theme', 'light')
    session['theme'] = 'dark' if current == 'light' else 'light'
    return redirect(request.referrer or url_for('index'))

@app.route('/add', methods=['POST'])
@login_required
def add_trade():
    
    symbol = request.form.get('symbol', '').upper()
    open_time = request.form.get('open_time', '').replace('T', ' ').strip()
    close_time = request.form.get('close_time', '').replace('T', ' ').strip()
    type = request.form.get('type', '')
    status = request.form.get('status', '').upper()
    sort = request.form.get('sort', '').upper()
    open_price = request.form.get('open_price')
    close_price = request.form.get('close_price')
    risk = request.form.get('risk')
    SL = request.form.get('SL')
    TP = request.form.get('TP')
    reason = request.form.get('reason')
    feedback = request.form.get('feedback')

    open_dt = parse_time(open_time)
    close_dt = parse_time(close_time)
    if open_dt and close_dt and close_dt < open_dt:
        flash('Close time cannot be before open time.', 'error')
        return redirect(url_for('index'))

    open_price = float(open_price) if open_price else None
    close_price= float(close_price) if close_price else None
    risk = float(risk) if risk else None
    SL = float(SL) if SL else None
    TP = float(TP) if TP else None
    
    RR = ((close_price-open_price)/(open_price-SL)) if (close_price is not None) else None

    sql = '''INSERT INTO trades (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

    with get_db() as conn:
        conn.execute(sql, (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback))    
        conn.commit()
     
    flash('Trade added!', 'success')
    return redirect(url_for('index'))


@app.route('/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_trade(user_id):
    try: 

        conn = get_db()
        current = conn.execute('SELECT * FROM trades WHERE id=?', (user_id,)).fetchone()
        if current is None:
            return {'success': False, 'message': 'Trade not found'}

        symbol = request.form.get('symbol', '').upper()
        open_time = request.form.get('open_time', '')
        close_time = request.form.get('close_time', '')
        type = request.form.get('type', '')
        status = request.form.get('status', '').upper()
        sort = request.form.get('sort', '').upper()
        open_price = request.form.get('open_price')
        close_price = request.form.get('close_price')
        risk = request.form.get('risk')
        SL = request.form.get('SL')
        TP = request.form.get('TP')
        reason = request.form.get('reason')
        feedback = request.form.get('feedback')

        symbol = symbol if symbol else current['symbol']
        open_time = open_time if open_time else current['open_time']
        close_time = close_time if close_time else current['close_time']
        type = type if type else current['type']
        status = status if status else current['status']
        sort = sort if sort else current['sort']
        reason = reason if reason else current['reason']
        feedback = feedback if feedback else current['feedback']

        open_price = float(open_price) if open_price else current['open_price']
        close_price = float(close_price) if close_price else current['close_price']
        risk = float(risk) if risk else current['risk']
        SL = float(SL) if SL else current['SL']
        TP = float(TP) if TP else current['TP']

        open_dt = parse_time(open_time)
        close_dt = parse_time(close_time)
        if open_dt and close_dt and close_dt < open_dt:
            return {'success': False, 'message': 'Close time cannot be before open time.'}

        if current['parent_id']:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (current['parent_id'],)).fetchone()
            if parent:
                old_risk = current['risk'] if current['risk'] is not None else 0
                new_risk = risk if risk is not None else 0
                risk_diff = new_risk - old_risk
                
                parent_new_risk = (parent['risk'] if parent['risk'] is not None else 0) + risk_diff
                
                if parent_new_risk <= 0 and parent['status'] != 'CLOSED':
                    from datetime import datetime
                    parent_close_time = datetime.now().strftime('%Y-%m-%d %H:%M')
                    parent_status = 'CLOSED'
                else:
                    parent_close_time = parent['close_time']
                    parent_status = parent['status']
                
                if parent_new_risk <= 0 and parent['status'] != 'CLOSED':
                    conn.execute('''
                        UPDATE trades SET risk=?, status=?, close_time=? WHERE id=?
                    ''', (max(0, parent_new_risk), parent_status, parent_close_time, parent['id']))
                else:
                    conn.execute('''
                        UPDATE trades SET risk=? WHERE id=?
                    ''', (parent_new_risk, parent['id']))

        if current['parent_id']:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (current['parent_id'],)).fetchone()
            if parent and close_price is not None and parent['SL'] is not None:
                if parent['sort'] == 'LONG':
                    RR = ((close_price - open_price) / (open_price - parent['SL']))
                elif parent['sort'] == 'SHORT':
                    RR = ((open_price - close_price) / (parent['SL'] - open_price))
                else:
                    RR = current['RR']
            else:
                RR = current['RR']
        else:
            RR = ((close_price-open_price)/(open_price-SL)) if (close_price is not None and SL is not None and open_price is not None) else current['RR']

        conn.execute('''UPDATE trades SET symbol=?, open_time=?, close_time=?, type=?, status=?, sort=?, open_price=?, close_price=?, risk=?, SL=?, TP=?, RR=?, reason=?, feedback=? WHERE id=?''', 
                    (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback, user_id))
        
        if current['parent_id']:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (current['parent_id'],)).fetchone()
            if parent:
                all_partials = conn.execute('SELECT * FROM trades WHERE parent_id=?', (parent['id'],)).fetchall()
                parent_rr = calculate_parent_rr_with_partials(parent, all_partials)
                #print("Parent RR recalculated:", parent_rr)
                conn.execute(f'UPDATE trades SET RR=? WHERE id=?', (parent_rr, parent['id']))
        
        conn.commit()
         
        return {'success': True}
    
    except Exception as e:
        return {'success': False, 'message': str(e)}
    
@app.route('/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_trade(user_id):

    with get_db() as conn:
        trade = conn.execute('SELECT * FROM trades WHERE id=?', (user_id,)).fetchone()
        if not trade:
            flash('Trade not found.', 'error')
            return redirect(url_for('index'))

        parent_id = trade['parent_id']

        conn.execute('DELETE FROM trades WHERE id=?', (user_id,))

        if parent_id:
            parent = conn.execute('SELECT * FROM trades WHERE id=?', (parent_id,)).fetchone()
            if parent:
                all_partials = conn.execute('SELECT * FROM trades WHERE parent_id=?', (parent_id,)).fetchall()
                parent_rr = calculate_parent_rr_with_partials(parent, all_partials)
                conn.execute('UPDATE trades SET RR=? WHERE id=?', (parent_rr, parent_id))

        conn.commit()
    flash('Trade deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/import', methods=['POST'])
@login_required
def import_trades():
    if 'import_file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('index'))
    file = request.files['import_file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('index'))
    if not file.filename.endswith('.xlsx'):
        flash('Only .xlsx files are supported', 'error')
        return redirect(url_for('index'))
    try:
        df = pd.read_excel(file)
        required_columns = ['symbol', 'open_time', 'status', 'sort', 'open_price', 'risk']
        allowed_columns = [
            'id', 'symbol', 'open_time', 'close_time', 'type', 'status', 'sort', 'open_price', 'close_price', 'risk',
            'SL', 'TP', 'RR', 'reason', 'feedback', 'reason_image', 'feedback_image', 'parent_id'
        ]
        missing = [col for col in required_columns if col not in df.columns]
        if missing:
            flash("Missing required columns: {', '.join(missing)}", 'error')
            return redirect(url_for('index'))
        
        df = df[[col for col in allowed_columns if col in df.columns]]

        for col in allowed_columns:
            if col not in df.columns:
                df[col] = None

        def excel_date_to_str(val):
            if pd.isnull(val):
                return None
            if isinstance(val, float) or isinstance(val, int):
                try:
                    return pd.to_datetime('1899-12-30') + pd.to_timedelta(val, 'D')
                except Exception:
                    return None
            try:
                dt = pd.to_datetime(val, errors='coerce')
                if pd.isnull(dt):
                    return None
                return dt.strftime('%Y-%m-%d %H:%M')
            except Exception:
                return None

        for col in ['open_time', 'close_time']:
            if col in df.columns:
                df[col] = df[col].apply(excel_date_to_str)
        
        df = df[
            df['symbol'].notnull() & (df['symbol'].astype(str).str.strip() != '') &
            df['sort'].notnull() & (df['sort'].astype(str).str.strip() != '')
        ]

        numeric_cols = ['risk', 'SL', 'TP', 'pnl', 'RR']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
                df[col] = df[col].apply(lambda x: int(x) if pd.notnull(x) and float(x).is_integer() else (float(x) if pd.notnull(x) else None))

        if 'parent_id' in df.columns:
            df['parent_id'] = pd.to_numeric(df['parent_id'], errors='coerce')
        else:
            df['parent_id'] = None

        df['excel_id'] = df['id'] 

        parents_df = df[df['parent_id'].isnull()].copy()
        partials_df = df[df['parent_id'].notnull()].copy()

        parents_df = parents_df.sort_values(by='excel_id', ascending=True)
        partials_df = partials_df.sort_values(by='excel_id', ascending=True)

        conn = get_db()
        conn.execute('PRAGMA foreign_keys = ON')
        parent_id_map = {}
        parent_count = 0
        partial_count = 0
        

        for _, row in parents_df.iterrows():
            excel_id = row['excel_id']
            if pd.isnull(excel_id):
                continue
            excel_id = int(excel_id)
            cursor = conn.execute('''
                INSERT INTO trades (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback, reason_image, feedback_image, parent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                row['symbol'], row['open_time'], row['close_time'], row['type'], row['status'], row['sort'],
                row['open_price'], row['close_price'], row['risk'], row['SL'], row['TP'], row['RR'], row['reason'], row['feedback'], row['reason_image'], row['feedback_image'], None
            ))
            db_id = cursor.lastrowid
            parent_id_map[excel_id] = db_id
            parent_count += 1

        for _, row in partials_df.iterrows():
            old_parent_id = row['parent_id']
            if pd.isnull(old_parent_id):
                continue
            old_parent_id = int(old_parent_id)
            db_parent_id = parent_id_map.get(old_parent_id)
            if db_parent_id is None:
                continue 
            conn.execute('''
                INSERT INTO trades (symbol, open_time, close_time, type, status, sort, open_price, close_price, risk, SL, TP, RR, reason, feedback, reason_image, feedback_image, parent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                row['symbol'], row['open_time'], row['close_time'], row['type'], row['status'], row['sort'],
                row['open_price'], row['close_price'], row['risk'], row['SL'], row['TP'],  row['RR'], row['reason'], row['feedback'], row['reason_image'], row['feedback_image'], db_parent_id
            ))
            partial_count += 1

        conn.commit()
         
        
        total_imported = parent_count + partial_count
        flash(f'Imported {total_imported} trades successfully! ({parent_count} parent trades, {partial_count} partial trades)', 'success')
    except Exception as e:
        flash(f'Import failed: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export_trades():
    conn = get_db()
    df = pd.read_sql_query('SELECT * FROM trades ORDER BY id DESC', conn)
     

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Trades')
    output.seek(0)

    return send_file(output, download_name="trades_export.xlsx", as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/partial_close_inline/<int:parent_id>', methods=['POST'])
@login_required
def partial_close_inline(parent_id):
    with get_db() as conn:
        parent_trade = conn.execute('SELECT * FROM trades WHERE id=?', (parent_id,)).fetchone()
        if parent_trade is None:
            flash('Parent trade not found', 'error')
            return redirect(url_for('index'))

        risk = request.form.get('risk')
        status = request.form.get('status', '').upper()
        risk = float(risk) if risk else None

        reason = request.form.get('reason', '')
        feedback = request.form.get('feedback', '')

        if status not in ('OPEN', 'CLOSED'):
            flash('Invalid status', 'error')
            return redirect(url_for('index'))

        if risk is None or risk <= 0:
            flash('Risk must be provided and > 0', 'error')
            return redirect(url_for('index'))

        if status == 'OPEN':
            open_price = request.form.get('open_price')
            open_time = request.form.get('open_time')
            open_price = float(open_price) if open_price else None
            close_price = None
            close_time = None

            if open_price is None:
                flash('Open price is required for OPEN partial', 'error')
                return redirect(url_for('index'))

            RR = 0.0

            new_parent_risk = (parent_trade['risk'] if parent_trade['risk'] is not None else 0.0) + risk
            new_parent_status = parent_trade['status']
            parent_close_time = parent_trade['close_time']

        else:  
            close_price = request.form.get('close_price')
            close_time = request.form.get('close_time')
            close_price = float(close_price) if close_price else None
            open_price = parent_trade['open_price']
            open_time = None  

            if close_price is None:
                flash('Close price is required for CLOSED partial', 'error')
                return redirect(url_for('index'))

            if parent_trade['sort'] == 'LONG':
                if parent_trade['SL'] is not None:
                    denom = open_price - parent_trade['SL']
                    RR = ((close_price - open_price) / denom) if denom != 0 else 0.0
                else:
                    RR = 0.0
            elif parent_trade['sort'] == 'SHORT':
                if parent_trade['SL'] is not None:
                    denom = parent_trade['SL'] - open_price
                    RR = ((open_price - close_price) / denom) if denom != 0 else 0.0
                else:
                    RR = 0.0
            else:
                RR = 0.0

            old_parent_risk = parent_trade['risk'] if parent_trade['risk'] is not None else 0.0
            new_parent_risk = old_parent_risk - risk

            if new_parent_risk <= 0:
                new_parent_status = 'CLOSED'
                parent_close_time = parent_trade['close_time'] or datetime.now().strftime('%Y-%m-%d %H:%M')
            else:
                new_parent_status = parent_trade['status']
                parent_close_time = parent_trade['close_time']

        conn.execute('''
            INSERT INTO trades (
                symbol, open_time, close_time, type, status, sort,
                open_price, close_price, risk, SL, TP, RR,
                reason, feedback, parent_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            parent_trade['symbol'],
            open_time,
            close_time,
            parent_trade['type'],
            status,
            parent_trade['sort'],
            open_price,
            close_price,
            risk,
            parent_trade['SL'],
            parent_trade['TP'],
            RR,
            reason,
            feedback,
            parent_id
        ))

        if status == 'CLOSED' and new_parent_risk <= 0:
            conn.execute('''
                UPDATE trades
                SET risk = ?, status = ?, close_time = ?
                WHERE id = ?
            ''', (
                max(0.0, new_parent_risk),
                new_parent_status,
                parent_close_time,
                parent_id
            ))
        else:
            conn.execute('''
                UPDATE trades
                SET risk = ?, status = ?
                WHERE id = ?
            ''', (
                new_parent_risk,
                new_parent_status,
                parent_id
            ))

        updated_parent = conn.execute('SELECT * FROM trades WHERE id=?', (parent_id,)).fetchone()
        all_partials = conn.execute('SELECT * FROM trades WHERE parent_id=?', (parent_id,)).fetchall()

        parent_rr = calculate_parent_rr_with_partials(updated_parent, all_partials)

        conn.execute('UPDATE trades SET RR=? WHERE id=?', (parent_rr, parent_id))

        conn.commit()

    flash('Partial trade added!', 'success')
    return redirect(url_for('index'))


@app.route('/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user_detail(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM trades WHERE id = ?', (user_id,)).fetchone()

    if user is None:
        flash('Not found', 'error')
         
        return redirect(url_for('index'))

    if request.method == 'POST':
        reason = request.form.get('reason', user['reason'])
        feedback = request.form.get('feedback', user['feedback'])

        delete_reason = request.form.get('delete_reason_image') == 'true'
        delete_feedback = request.form.get('delete_feedback_image') == 'true'
  
        reason_image = request.files.get('reason_image')
        feedback_image = request.files.get('feedback_image')
 
        reason_image_filename = user['reason_image']
        feedback_image_filename = user['feedback_image']

        if delete_reason:
            if user['reason_image']:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['reason_image']))
                except OSError:
                    pass  
            reason_image_filename = None
  
        elif reason_image and reason_image.filename != '':
            if not allowed_file(reason_image.filename):
                flash('Invalid reason image file extension', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if reason_image.content_type not in ['image/jpeg', 'image/png']:
                flash('Invalid reason image MIME type', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            try:
                reason_image.seek(0) 
                test_img = Image.open(reason_image)  
                reason_image.seek(0)  
            except Exception as e:
                flash('Faulty or corrupt reason image file', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if user['reason_image']: 
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['reason_image']))
                except OSError:
                    pass
            filename = secure_filename(reason_image.filename)
            filename = f"{int(time.time())}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            reason_image.save(filepath)
            reason_image_filename = filename

        if delete_feedback:
            if user['feedback_image']:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['feedback_image']))
                except OSError:
                    pass 
            feedback_image_filename = None

        elif feedback_image and feedback_image.filename != '':
            if not allowed_file(feedback_image.filename):
                flash('Invalid feedback image file extension', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if feedback_image.content_type not in ['image/jpeg', 'image/png']:
                flash('Invalid feedback image MIME type', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            try:
                feedback_image.seek(0)  
                test_img = Image.open(feedback_image)  
                feedback_image.seek(0)  
            except Exception as e:
                flash('Faulty or corrupt feedback image file', 'error')
                return redirect(url_for('user_detail', user_id=user_id))  
            if user['feedback_image']:  
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['feedback_image']))
                except OSError:
                    pass
            filename = secure_filename(feedback_image.filename)
            filename = f"{int(time.time())}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            feedback_image.save(filepath) 
            feedback_image_filename = filename

        conn.execute('''UPDATE trades SET reason = ?, feedback = ?, reason_image = ?, feedback_image = ? WHERE id = ?''', 
                    (reason, feedback, reason_image_filename, feedback_image_filename, user_id))
        conn.commit()
         
        flash('Changes saved successfully!', 'success')
        return redirect(url_for('user_detail', user_id=user_id))  

     
    return render_template('user_detail.html', user=user)

@app.route('/statistics')
@login_required
def statistics():
    conn = get_db()
    return render_template('statistics.html', stats=stats_data)

def smart_price(value):
    try:
        if value is None:
            return ""
        val = float(value)
        if val == 0:
            return "0"
        abs_val = abs(val)
        if abs_val < 1e-6:
            return f"{val:.2e}"

        if abs_val < 0.01:
            prec = 8
        elif abs_val < 1:
            prec = 6
        elif abs_val < 10:
            prec = 5
        elif abs_val < 1000:
            prec = 3
        elif abs_val < 10000:
            prec = 2
        elif abs_val < 100000:
            prec = 1
        else:
            prec = 0

        formatted = f"{val:.{prec}f}"
        formatted = formatted.rstrip('0').rstrip('.') if '.' in formatted else formatted
        return formatted
    except Exception:
        return str(value)


app.jinja_env.filters['smart_price'] = smart_price

def get_date_filter(start_date=None, end_date=None):
    if start_date and end_date:
        return "AND close_time BETWEEN :start_date AND :end_date", {
            "start_date": start_date,
            "end_date": end_date
        }
    elif start_date:
        return "AND close_time >= :start_date", {"start_date": start_date}
    elif end_date:
        return "AND close_time <= :end_date", {"end_date": end_date}
    else:
        return "", {}





if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=True)
