import os
import re
import random
import secrets
import socket
import sqlite3
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, g, Response, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_PATH = os.path.join(BASE_DIR, 'lustro.db')
SECRET_FILE = os.path.join(BASE_DIR, '.secret_key')
ALLOWED_EXTENSIONS = {'exe', 'jar', 'zip', 'rar', 'msi'}

# Стартовые значения статистики (автоматически растут от реальных данных в БД)
BASE_USERS_OFFSET = 500
BASE_DOWNLOADS_OFFSET = 483
BASE_BUILDS_OFFSET = 7

DEFAULT_ADMIN_USER = 'admin'
DEFAULT_ADMIN_PASS = os.environ.get('LUSTRO_ADMIN_PASS', 'Lustr0#Admin!94xQ$27')

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
DISPOSABLE_DOMAINS = {
    'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
    'yopmail.com', 'trashmail.com', 'throwawaymail.com', 'sharklasers.com',
    'getnada.com', 'dispostable.com', 'fakeinbox.com', 'maildrop.cc'
}

SUBSCRIPTION_PLANS = {
    'free': {
        'name': 'FREE',
        'label': 'Игрок',
        'rank': 0,
        'price': '0 ₽',
        'color': '#a1a1aa',
        'features': [
            'Доступ к стабильным релизам Lustro',
            'Базовый буст FPS и оптимизация чанков',
            'Личный кабинет и уникальный UID',
            'Локальное сохранение конфигов'
        ]
    },
    'plus': {
        'name': 'LUSTRO+',
        'label': 'Подписка PLUS',
        'rank': 1,
        'price': '249 ₽ / мес',
        'color': '#facc15',
        'features': [
            'Всё из тарифа FREE',
            'Доступ к закрытым BETA-билдам раньше всех',
            'Золотой плащ Lustro и значок в табе',
            'До 15 облачных конфигов',
            'Приоритетная поддержка в Discord'
        ]
    },
    'ultra': {
        'name': 'LUSTRO ULTRA',
        'label': 'Подписка ULTRA',
        'rank': 2,
        'price': '499 ₽ / мес',
        'color': '#fb923c',
        'features': [
            'Всё из тарифа LUSTRO+',
            'Доступ к ранним ALPHA-сборкам клиента',
            'Анимированные крылья, аура и кастомный плащ',
            'Безлимит облачных профилей и обмен по коду',
            'Роль ULTRA и закрытый чат с разработчиками'
        ]
    },
    'lifetime': {
        'name': 'LIFETIME',
        'label': 'Навсегда',
        'rank': 3,
        'price': '1 990 ₽',
        'color': '#38bdf8',
        'features': [
            'Все возможности ULTRA навсегда без продлений',
            'Уникальный алмазно-золотой префикс в клиенте',
            'Пожизненный доступ ко всем будущим версиям',
            'Именная благодарность в титрах клиента'
        ]
    }
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def load_secret_key():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'r', encoding='utf-8') as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(SECRET_FILE, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = load_secret_key()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 МБ


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def domain_exists(domain):
    """Проверяет существование почтового домена через DNS и MX-запись."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(2.5)
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        pass
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)

    # Запасная проверка MX-записи через nslookup (на случай доменов без A-записи)
    try:
        result = subprocess.run(
            ['nslookup', '-type=mx', domain],
            capture_output=True,
            text=True,
            timeout=2.5
        )
        out = (result.stdout or '').lower()
        if 'mail exchanger' in out or 'mx preference' in out or 'приоритет mx' in out:
            return True
    except Exception:
        pass
    return False


def verify_email_address(email):
    email = (email or '').strip().lower()
    if not EMAIL_REGEX.match(email):
        return False, 'Некорректный формат email (пример: steve@gmail.com).'

    domain = email.split('@', 1)[1]
    if domain in DISPOSABLE_DOMAINS:
        return False, 'Временные (одноразовые) почтовые сервисы запрещены.'

    if not domain_exists(domain):
        return False, f'Почтовый домен «{domain}» не существует или не принимает письма.'

    return True, 'Почта прошла проверку.'


def get_active_plan(user):
    if not user:
        return 'free', ''
    plan = user['sub_plan'] or 'free'
    until = user['sub_until'] or ''
    if plan == 'free':
        return 'free', ''
    if plan == 'lifetime' or until == 'Навсегда':
        return plan, 'Навсегда'
    if until:
        try:
            exp_dt = datetime.strptime(until, '%d.%m.%Y %H:%M')
            if exp_dt < datetime.now():
                return 'free', ''
        except ValueError:
            pass
    return plan, until


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            sub_plan TEXT DEFAULT 'free',
            sub_until TEXT DEFAULT '',
            last_ip TEXT DEFAULT '127.0.0.1',
            created_at TEXT NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS builds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            mc_version TEXT DEFAULT '1.16.5 - 1.21.4',
            min_plan TEXT DEFAULT 'free',
            changelog TEXT,
            filename TEXT NOT NULL,
            file_size TEXT DEFAULT '—',
            downloads INTEGER DEFAULT 0,
            uploaded_at TEXT NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS promo_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            plan TEXT NOT NULL,
            duration_days INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            used_by TEXT DEFAULT '',
            used_at TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS download_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            build_version TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            downloaded_at TEXT NOT NULL
        )
    ''')

    # Миграция старой БД при обновлении
    user_cols = {r['name'] for r in cur.execute('PRAGMA table_info(users)').fetchall()}
    for col, ddl in [
        ('is_banned', 'INTEGER DEFAULT 0'),
        ('last_ip', "TEXT DEFAULT '127.0.0.1'"),
        ('sub_plan', "TEXT DEFAULT 'free'"),
        ('sub_until', "TEXT DEFAULT ''")
    ]:
        if col not in user_cols:
            cur.execute(f'ALTER TABLE users ADD COLUMN {col} {ddl}')

    build_cols = {r['name'] for r in cur.execute('PRAGMA table_info(builds)').fetchall()}
    for col, ddl in [
        ('mc_version', "TEXT DEFAULT '1.16.5 - 1.21.4'"),
        ('file_size', "TEXT DEFAULT '—'"),
        ('min_plan', "TEXT DEFAULT 'free'")
    ]:
        if col not in build_cols:
            cur.execute(f'ALTER TABLE builds ADD COLUMN {col} {ddl}')

    admin = cur.execute('SELECT * FROM users WHERE username = ?', (DEFAULT_ADMIN_USER,)).fetchone()
    if not admin:
        cur.execute(
            '''INSERT INTO users
               (username, email, password_hash, is_admin, is_banned, sub_plan, sub_until, last_ip, created_at)
               VALUES (?, ?, ?, 1, 0, 'lifetime', 'Навсегда', '127.0.0.1', ?)''',
            (
                DEFAULT_ADMIN_USER,
                'admin@lustro.gg',
                generate_password_hash(DEFAULT_ADMIN_PASS),
                datetime.now().strftime('%d.%m.%Y %H:%M')
            )
        )
    elif check_password_hash(admin['password_hash'], 'admin123'):
        cur.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (generate_password_hash(DEFAULT_ADMIN_PASS), admin['id'])
        )

    conn.commit()
    conn.close()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.context_processor
def inject_globals():
    return {
        'SUBSCRIPTION_PLANS': SUBSCRIPTION_PLANS,
        'get_active_plan': get_active_plan
    }


@app.before_request
def load_current_user():
    g.user = None
    g.plan = 'free'
    g.plan_until = ''
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if not user or user['is_banned']:
            session.clear()
            if user and user['is_banned']:
                flash('Ваш аккаунт заблокирован администратором.', 'error')
        else:
            g.user = user
            g.plan, g.plan_until = get_active_plan(user)
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user:
            flash('Для доступа войдите или зарегистрируйтесь на сайте.', 'warning')
            return redirect(url_for('auth', mode='register'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.user or not g.user['is_admin']:
            flash('Доступ разрешён только администратору.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


@app.route('/captcha.svg')
def captcha_svg():
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    code = ''.join(random.choice(alphabet) for _ in range(5))
    session['captcha_code'] = code

    noise_rects = []
    for _ in range(26):
        x = random.randint(0, 174)
        y = random.randint(0, 50)
        size = random.choice([4, 6, 8])
        col = random.choice(['#27272a', '#3f3f46', '#422006', '#713f12'])
        noise_rects.append(f'<rect x="{x}" y="{y}" width="{size}" height="{size}" fill="{col}" opacity="0.7"/>')

    noise_lines = []
    for _ in range(4):
        x1, y1 = random.randint(0, 40), random.randint(5, 50)
        x2, y2 = random.randint(140, 180), random.randint(5, 50)
        col = random.choice(['#facc15', '#a16207', '#52525b'])
        noise_lines.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="2" opacity="0.55"/>')

    chars_svg = []
    for idx, ch in enumerate(code):
        x = 22 + idx * 31 + random.randint(-3, 3)
        y = 39 + random.randint(-5, 5)
        rot = random.randint(-14, 14)
        fill = random.choice(['#facc15', '#fde047', '#fef08a', '#fbbf24'])
        chars_svg.append(
            f'<text x="{x}" y="{y}" fill="{fill}" font-family="monospace" font-weight="900" '
            f'font-size="28" transform="rotate({rot} {x} {y})" stroke="#09090b" stroke-width="1.2">{ch}</text>'
        )

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="180" height="56" viewBox="0 0 180 56" shape-rendering="crispEdges">
        <rect width="180" height="56" fill="#121216"/>
        {''.join(noise_rects)}
        {''.join(noise_lines)}
        {''.join(chars_svg)}
    </svg>'''

    resp = Response(svg, mimetype='image/svg+xml')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp


@app.route('/api/check-email')
def api_check_email():
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'ok': False, 'message': 'Введите email.'})

    ok, msg = verify_email_address(email)
    if not ok:
        return jsonify({'ok': False, 'message': msg})

    conn = get_db()
    exists = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    if exists:
        return jsonify({'ok': False, 'message': 'Этот email уже зарегистрирован в базе.'})

    return jsonify({'ok': True, 'message': 'Email существует и свободен!'})


@app.route('/')
def index():
    conn = get_db()
    latest_build = conn.execute('SELECT * FROM builds ORDER BY id DESC LIMIT 1').fetchone()
    recent_builds = conn.execute('SELECT * FROM builds ORDER BY id DESC LIMIT 4').fetchall()
    real_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    real_downloads = conn.execute('SELECT COALESCE(SUM(downloads), 0) FROM builds').fetchone()[0]
    real_builds = conn.execute('SELECT COUNT(*) FROM builds').fetchone()[0]
    conn.close()

    display_users = BASE_USERS_OFFSET + max(0, real_users - 1)
    display_downloads = BASE_DOWNLOADS_OFFSET + real_downloads
    display_builds = BASE_BUILDS_OFFSET + real_builds

    return render_template(
        'index.html',
        latest_build=latest_build,
        recent_builds=recent_builds,
        display_users=display_users,
        display_downloads=display_downloads,
        display_builds=display_builds
    )


@app.route('/subscriptions')
def subscriptions():
    return render_template('subscriptions.html')


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if g.user:
        return redirect(url_for('profile'))

    mode = request.args.get('mode', 'login')

    if request.method == 'POST':
        action = request.form.get('action')
        captcha_input = request.form.get('captcha', '').strip().upper()
        expected_captcha = session.pop('captcha_code', None)

        if not expected_captcha or captcha_input != expected_captcha:
            flash('Неверно введён код с картинки (капча). Попробуйте ещё раз.', 'error')
            return redirect(url_for('auth', mode=action or mode))

        conn = get_db()
        ip = get_client_ip()

        if action == 'register':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm_password', '')

            if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
                flash('Никнейм: 3–20 символов (латиница, цифры, _).', 'error')
                conn.close()
                return redirect(url_for('auth', mode='register'))

            email_ok, email_msg = verify_email_address(email)
            if not email_ok:
                flash(email_msg, 'error')
                conn.close()
                return redirect(url_for('auth', mode='register'))

            if len(password) < 8:
                flash('Пароль должен быть минимум 8 символов.', 'error')
                conn.close()
                return redirect(url_for('auth', mode='register'))

            if password != confirm:
                flash('Пароли не совпадают.', 'error')
                conn.close()
                return redirect(url_for('auth', mode='register'))

            try:
                cur = conn.cursor()
                cur.execute(
                    '''INSERT INTO users
                       (username, email, password_hash, is_admin, is_banned, sub_plan, sub_until, last_ip, created_at)
                       VALUES (?, ?, ?, 0, 0, 'free', '', ?, ?)''',
                    (
                        username,
                        email,
                        generate_password_hash(password),
                        ip,
                        datetime.now().strftime('%d.%m.%Y %H:%M')
                    )
                )
                conn.commit()
                session['user_id'] = cur.lastrowid
                session['username'] = username
                session['is_admin'] = 0
                conn.close()
                flash(f'Аккаунт {username} создан! Теперь можно скачать клиент Lustro.', 'success')
                return redirect(url_for('profile'))
            except sqlite3.IntegrityError:
                flash('Такой никнейм или email уже занят.', 'error')
                conn.close()
                return redirect(url_for('auth', mode='register'))

        elif action == 'login':
            login_input = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            user = conn.execute(
                'SELECT * FROM users WHERE username = ? OR email = ?',
                (login_input, login_input.lower())
            ).fetchone()

            if user and check_password_hash(user['password_hash'], password):
                if user['is_banned']:
                    conn.close()
                    flash('Этот аккаунт заблокирован администратором.', 'error')
                    return redirect(url_for('auth', mode='login'))

                conn.execute('UPDATE users SET last_ip = ? WHERE id = ?', (ip, user['id']))
                conn.commit()
                conn.close()

                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                flash(f'С возвращением, {user["username"]}!', 'success')
                return redirect(url_for('admin' if user['is_admin'] else 'profile'))
            else:
                conn.close()
                flash('Неверный логин или пароль.', 'error')
                return redirect(url_for('auth', mode='login'))

    return render_template('auth.html', mode=mode)


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из аккаунта.', 'success')
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db()

    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == 'password':
            old_pass = request.form.get('old_password', '')
            new_pass = request.form.get('new_password', '')
            if not check_password_hash(g.user['password_hash'], old_pass):
                flash('Текущий пароль неверен.', 'error')
            elif len(new_pass) < 8:
                flash('Новый пароль должен быть не короче 8 символов.', 'error')
            else:
                conn.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(new_pass), g.user['id'])
                )
                conn.commit()
                flash('Пароль успешно изменён.', 'success')

        elif form_type == 'redeem_key':
            code = request.form.get('promo_code', '').strip().upper()
            key_row = conn.execute('SELECT * FROM promo_keys WHERE code = ?', (code,)).fetchone()
            if not key_row:
                flash('Ключ активации не найден.', 'error')
            elif key_row['used_by']:
                flash('Этот ключ уже был активирован ранее.', 'error')
            else:
                plan = key_row['plan']
                days = key_row['duration_days']
                if plan == 'lifetime' or days <= 0:
                    until_str = 'Навсегда'
                else:
                    until_str = (datetime.now() + timedelta(days=days)).strftime('%d.%m.%Y %H:%M')

                conn.execute(
                    'UPDATE users SET sub_plan = ?, sub_until = ? WHERE id = ?',
                    (plan, until_str, g.user['id'])
                )
                conn.execute(
                    'UPDATE promo_keys SET used_by = ?, used_at = ? WHERE id = ?',
                    (g.user['username'], datetime.now().strftime('%d.%m.%Y %H:%M'), key_row['id'])
                )
                conn.commit()
                plan_title = SUBSCRIPTION_PLANS.get(plan, {}).get('name', plan.upper())
                flash(f'Ключ активирован! Выдана подписка {plan_title} ({until_str}).', 'success')

        conn.close()
        return redirect(url_for('profile'))

    builds = conn.execute('SELECT * FROM builds ORDER BY id DESC LIMIT 10').fetchall()
    my_downloads = conn.execute(
        'SELECT * FROM download_logs WHERE user_id = ? ORDER BY id DESC LIMIT 10',
        (g.user['id'],)
    ).fetchall()
    conn.close()

    return render_template('profile.html', builds=builds, my_downloads=my_downloads)


@app.route('/download')
@app.route('/download/<int:build_id>')
@login_required
def download(build_id=None):
    conn = get_db()
    if build_id:
        build = conn.execute('SELECT * FROM builds WHERE id = ?', (build_id,)).fetchone()
    else:
        build = conn.execute('SELECT * FROM builds ORDER BY id DESC LIMIT 1').fetchone()

    if not build:
        conn.close()
        flash('Клиент пока не загружен администратором. Загляните чуть позже.', 'warning')
        return redirect(url_for('index'))

    # Проверка требуемого уровня подписки для билда
    req_plan = build['min_plan'] or 'free'
    user_rank = SUBSCRIPTION_PLANS.get(g.plan, SUBSCRIPTION_PLANS['free'])['rank']
    req_rank = SUBSCRIPTION_PLANS.get(req_plan, SUBSCRIPTION_PLANS['free'])['rank']

    if not g.user['is_admin'] and user_rank < req_rank:
        conn.close()
        req_name = SUBSCRIPTION_PLANS[req_plan]['name']
        flash(f'Этот билд доступен только для подписки {req_name} и выше.', 'warning')
        return redirect(url_for('subscriptions'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], build['filename'])
    if not os.path.exists(file_path):
        conn.close()
        flash('Файл билда отсутствует на сервере.', 'error')
        return redirect(url_for('index'))

    conn.execute('UPDATE builds SET downloads = downloads + 1 WHERE id = ?', (build['id'],))
    conn.execute(
        '''INSERT INTO download_logs (user_id, username, build_version, ip_address, downloaded_at)
           VALUES (?, ?, ?, ?, ?)''',
        (
            g.user['id'],
            g.user['username'],
            build['version'],
            get_client_ip(),
            datetime.now().strftime('%d.%m.%Y %H:%M')
        )
    )
    conn.commit()
    conn.close()

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        build['filename'],
        as_attachment=True
    )


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    conn = get_db()

    if request.method == 'POST':
        version = request.form.get('version', '').strip()
        mc_version = request.form.get('mc_version', '1.16.5 - 1.21.4').strip()
        min_plan = request.form.get('min_plan', 'free')
        changelog = request.form.get('changelog', '').strip()
        file = request.files.get('client_file')

        if min_plan not in SUBSCRIPTION_PLANS:
            min_plan = 'free'

        if not version or not file or file.filename == '':
            flash('Укажите версию и выберите файл клиента.', 'error')
            conn.close()
            return redirect(url_for('admin'))

        if not allowed_file(file.filename):
            flash('Разрешённые форматы: .exe, .jar, .zip, .rar, .msi', 'error')
            conn.close()
            return redirect(url_for('admin'))

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = f"{timestamp}_{secure_filename(file.filename)}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
        file.save(save_path)
        size_str = format_size(os.path.getsize(save_path))

        conn.execute(
            '''INSERT INTO builds (version, mc_version, min_plan, changelog, filename, file_size, uploaded_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (version, mc_version, min_plan, changelog, safe_name, size_str, datetime.now().strftime('%d.%m.%Y %H:%M'))
        )
        conn.commit()
        conn.close()
        flash(f'Билд {version} ({size_str}) загружен на сайт!', 'success')
        return redirect(url_for('admin'))

    q = request.args.get('q', '').strip()
    if q:
        like_q = f'%{q}%'
        users = conn.execute(
            'SELECT * FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id DESC',
            (like_q, like_q)
        ).fetchall()
    else:
        users = conn.execute('SELECT * FROM users ORDER BY id DESC').fetchall()

    builds = conn.execute('SELECT * FROM builds ORDER BY id DESC').fetchall()
    keys = conn.execute('SELECT * FROM promo_keys ORDER BY id DESC LIMIT 25').fetchall()
    logs = conn.execute('SELECT * FROM download_logs ORDER BY id DESC LIMIT 20').fetchall()
    total_downloads = conn.execute('SELECT COALESCE(SUM(downloads), 0) FROM builds').fetchone()[0]
    subs_count = conn.execute("SELECT COUNT(*) FROM users WHERE sub_plan != 'free'").fetchone()[0]
    conn.close()

    return render_template(
        'admin.html',
        builds=builds,
        users=users,
        keys=keys,
        logs=logs,
        search_q=q,
        total_downloads=total_downloads,
        subs_count=subs_count
    )


@app.route('/admin/delete/<int:build_id>', methods=['POST'])
@admin_required
def delete_build(build_id):
    conn = get_db()
    build = conn.execute('SELECT * FROM builds WHERE id = ?', (build_id,)).fetchone()
    if build:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], build['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        conn.execute('DELETE FROM builds WHERE id = ?', (build_id,))
        conn.commit()
        flash(f'Билд {build["version"]} удалён.', 'success')
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/subscription', methods=['POST'])
@admin_required
def grant_subscription(user_id):
    plan = request.form.get('plan', 'free')
    days_raw = request.form.get('days', '30')

    if plan not in SUBSCRIPTION_PLANS:
        flash('Некорректный тариф.', 'error')
        return redirect(url_for('admin'))

    if plan == 'free':
        until_str = ''
    elif plan == 'lifetime' or days_raw == 'forever':
        until_str = 'Навсегда'
    else:
        try:
            days = max(1, int(days_raw))
        except ValueError:
            days = 30
        until_str = (datetime.now() + timedelta(days=days)).strftime('%d.%m.%Y %H:%M')

    conn = get_db()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        conn.execute(
            'UPDATE users SET sub_plan = ?, sub_until = ? WHERE id = ?',
            (plan, until_str, user_id)
        )
        conn.commit()
        plan_name = SUBSCRIPTION_PLANS[plan]['name']
        flash(f'Игроку {user["username"]} установлен тариф {plan_name} ({until_str or "базовый"}).', 'success')
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/keys/create', methods=['POST'])
@admin_required
def create_key():
    plan = request.form.get('plan', 'plus')
    days_raw = request.form.get('days', '30')

    if plan not in ('plus', 'ultra', 'lifetime'):
        plan = 'plus'

    days = 0 if (plan == 'lifetime' or days_raw == 'forever') else max(1, int(days_raw))
    part = lambda: ''.join(random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(4))
    code = f"LUSTRO-{part()}-{part()}-{part()}"

    conn = get_db()
    conn.execute(
        '''INSERT INTO promo_keys (code, plan, duration_days, created_by, created_at)
           VALUES (?, ?, ?, ?, ?)''',
        (code, plan, days, g.user['username'], datetime.now().strftime('%d.%m.%Y %H:%M'))
    )
    conn.commit()
    conn.close()
    flash(f'Создан ключ активации: {code}', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/keys/delete/<int:key_id>', methods=['POST'])
@admin_required
def delete_key(key_id):
    conn = get_db()
    conn.execute('DELETE FROM promo_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    flash('Ключ удалён.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/ban', methods=['POST'])
@admin_required
def toggle_ban(user_id):
    if user_id == g.user['id']:
        flash('Нельзя заблокировать самого себя.', 'error')
        return redirect(url_for('admin'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_state = 0 if user['is_banned'] else 1
        conn.execute('UPDATE users SET is_banned = ? WHERE id = ?', (new_state, user_id))
        conn.commit()
        flash(f'Пользователь {user["username"]} {"заблокирован" if new_state else "разблокирован"}.', 'success')
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@admin_required
def toggle_role(user_id):
    if user_id == g.user['id']:
        flash('Нельзя снять права с самого себя.', 'error')
        return redirect(url_for('admin'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_role = 0 if user['is_admin'] else 1
        conn.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_role, user_id))
        conn.commit()
        flash(f'Роль пользователя {user["username"]} изменена.', 'success')
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/change-password', methods=['POST'])
@admin_required
def admin_change_password():
    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')

    if not check_password_hash(g.user['password_hash'], current_pw):
        flash('Текущий пароль администратора неверен.', 'error')
        return redirect(url_for('admin'))
    if len(new_pw) < 10:
        flash('Новый пароль администратора должен быть минимум 10 символов.', 'error')
        return redirect(url_for('admin'))

    conn = get_db()
    conn.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (generate_password_hash(new_pw), g.user['id'])
    )
    conn.commit()
    conn.close()
    flash('Пароль администратора обновлён.', 'success')
    return redirect(url_for('admin'))


init_db()

if __name__ == '__main__':
    print("=" * 56)
    print("  LUSTRO MINECRAFT PORTAL ЗАПУЩЕН")
    print("  Сайт:   http://127.0.0.1:5000")
    print(f"  Админ:  {DEFAULT_ADMIN_USER} / {DEFAULT_ADMIN_PASS}")
    print("=" * 56)
    app.run(debug=True, host='127.0.0.1', port=5000)