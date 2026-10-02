"""
PROPAGENT ZERO — AI-Powered Property Verification & Fraud Detection
Main Application Server (Flask)
Verify. Detect. Protect.
"""

import os
import random
import json
import secrets
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

from models.database import init_db, get_db_connection, log_audit
from services.hash_service import (
    compute_sha256_for_file, verify_document_hash, simulate_tampering, restore_clean_file,
    safe_upload_path
)
from services.document_verifier import run_full_property_verification
from services.duplicate_detector import scan_all_duplicates, find_duplicates_for_property
from services.risk_engine import calculate_property_risk
from services.explainable_ai import explain_property_risk
from services.qr_service import generate_qr_svg, generate_qr_data_uri

DEMO_MODE = os.environ.get('DEMO_MODE', '1').lower() in ('1', 'true', 'yes')
API_KEY = os.environ.get('API_KEY', 'realsafe_demo_api_key_2026')

app = Flask(__name__)
if not DEMO_MODE:
    secret = os.environ.get('SECRET_KEY')
    if not secret:
        raise RuntimeError("CRITICAL SECURITY ERROR: SECRET_KEY environment variable must be explicitly defined when DEMO_MODE=0.")
    app.secret_key = secret
else:
    app.secret_key = os.environ.get('SECRET_KEY', 'realsafe_cyber_secret_key_2026_demo')

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '0') == '1'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB max upload

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
FORBIDDEN_EXTENSIONS = {'exe', 'bat', 'cmd', 'sh', 'py', 'js', 'vbs', 'msi', 'ps1', 'php', 'phtml', 'dll', 'so', 'com', 'scr'}

def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS and ext not in FORBIDDEN_EXTENSIONS

# --- SECURITY, CSRF & ROLE DECORATORS ---

@app.errorhandler(400)
def handle_400(e):
    return render_template('400.html'), 400

@app.errorhandler(403)
def handle_403(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def handle_404(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def handle_500(e):
    # Conceals internal traceback from public visitors
    return render_template('500.html'), 500

@app.errorhandler(413)
def handle_413(e):
    flash("Uploaded document exceeds the 16MB file size security limit.", "danger")
    return redirect(request.referrer or url_for('documents')), 413

def get_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

@app.context_processor
def inject_template_globals():
    return {
        'csrf_token': get_csrf_token,
        'demo_mode': DEMO_MODE,
        'current_user_id': session.get('user_id'),
        'current_user_name': session.get('user_name'),
        'current_user_role': session.get('user_role')
    }

@app.before_request
def security_and_csrf_protect():
    # 1. API endpoint protection: requires active session OR valid X-API-Key
    if request.path.startswith('/api/'):
        if 'user_id' in session:
            return
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if key and secrets.compare_digest(key, API_KEY):
            return
        return jsonify({
            'error': 'Unauthorized',
            'message': 'API access requires an active session or valid X-API-Key.'
        }), 401

    # 2. CSRF protection on mutating web requests
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        session_token = session.get('_csrf_token')
        if not session_token or not token or not secrets.compare_digest(token, session_token):
            return render_template('400.html', error_message="CSRF validation failed: Missing or invalid CSRF token."), 400

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please sign in to access this resource.", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please sign in to access this resource.", "warning")
                return redirect(url_for('login', next=request.url))
            if session.get('user_role') not in roles:
                flash(f"Access denied: Action requires {' or '.join(roles)} privileges.", "danger")
                return render_template('403.html', required_roles=roles), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- ROLE SWITCHING & AUTHENTICATION ---

@app.route('/switch_role/<role>', methods=['POST'])
@login_required
def switch_role(role):
    """Instant persona switch for evaluation and hackathon presentations."""
    if not DEMO_MODE:
        abort(404)
    if role not in ('seller', 'buyer', 'admin'):
        abort(400)

    if role == 'seller':
        session['user_id'] = 'USR-1001'
        session['user_name'] = 'Arun Kumar'
        session['user_role'] = 'seller'
        flash("Switched persona to Arun Kumar (Seller). You can manage properties and initiate buyer transfers.", "info")
    elif role == 'buyer':
        session['user_id'] = 'USR-1002'
        session['user_name'] = 'Priya Ramesh'
        session['user_role'] = 'buyer'
        flash("Switched persona to Priya Ramesh (Buyer). You can inspect Passports and run Pre-Transaction Safety Checks.", "info")
    else:
        session['user_id'] = 'USR-1000'
        session['user_name'] = 'Vikram Sundar (Admin)'
        session['user_role'] = 'admin'
        flash("Switched persona to Vikram Sundar (Startup / Admin). Full governance access granted.", "info")
    
    referrer = request.referrer
    return redirect(referrer or url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_identifier = request.form.get('user_id', '').strip()
        password = request.form.get('password', '').strip()

        if not user_identifier or not password:
            flash("Please enter both User ID/Email and password.", "warning")
            return render_template('login.html')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users
            WHERE verified_user_id = ? OR LOWER(email) = LOWER(?)
        """, (user_identifier, user_identifier))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['verified_user_id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            session['_csrf_token'] = secrets.token_hex(32)
            log_audit(user['verified_user_id'], None, "USER_LOGIN", f"User {user['name']} authenticated.")
            flash(f"Welcome back, {user['name']}!", "success")
            next_url = request.args.get('next')
            if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please verify your User ID / Email and password.", "danger")
            return render_template('login.html', entered_id=user_identifier), 401

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for('login'))

# --- MAIN DASHBOARD ---

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Dynamic metrics from SQLite
    cursor.execute("SELECT COUNT(*) as cnt FROM properties")
    total_properties = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM properties WHERE risk_score < 30")
    low_risk_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM properties WHERE risk_score >= 30 AND risk_score < 60")
    medium_risk_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM properties WHERE risk_score >= 60 AND risk_score < 80")
    high_risk_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM properties WHERE risk_score >= 80")
    critical_risk_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM properties WHERE verification_status = 'Verified' AND risk_score < 30")
    verified_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM properties WHERE risk_score >= 30 OR verification_status != 'Verified'")
    suspicious_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM risk_alerts WHERE alert_type = 'Potential Duplicate Property'")
    duplicate_alerts_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM risk_alerts WHERE alert_type = 'Hash Mismatch'")
    hash_alerts_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM transfers WHERE status != 'Approved'")
    active_transfers_count = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM documents")
    total_documents = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) as cnt FROM documents WHERE verification_status = 'Hash Mismatch'")
    tampered_docs_count = cursor.fetchone()['cnt']

    # Recent Alerts
    cursor.execute("""
        SELECT * FROM risk_alerts
        ORDER BY id DESC LIMIT 6
    """)
    recent_alerts = [dict(r) for r in cursor.fetchall()]

    # Recent Audits
    cursor.execute("""
        SELECT * FROM audit_logs
        ORDER BY id DESC LIMIT 6
    """)
    recent_audits = [dict(r) for r in cursor.fetchall()]

    # Recent Verifications (Section 14 & 17)
    cursor.execute("""
        SELECT * FROM verification_records
        ORDER BY id DESC LIMIT 6
    """)
    recent_verifications = [dict(r) for r in cursor.fetchall()]

    # Load ML Metrics (Section 7 & 8: RF vs LR comparison on test set)
    cursor.execute("SELECT * FROM model_metrics ORDER BY is_primary DESC, id ASC")
    db_metrics_rows = [dict(r) for r in cursor.fetchall()]

    conn.close()

    ml_data = None
    meta_path = os.path.join(BASE_DIR, 'models', 'model_metadata.json')
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                ml_data = json.load(f)
        except Exception:
            pass

    stats = {
        'total_properties': total_properties,
        'verified_count': verified_count,
        'suspicious_count': suspicious_count,
        'low_risk_count': low_risk_count,
        'medium_risk_count': medium_risk_count,
        'high_risk_count': high_risk_count,
        'critical_risk_count': critical_risk_count,
        'review_required_count': medium_risk_count,
        'duplicate_alerts_count': duplicate_alerts_count,
        'hash_alerts_count': hash_alerts_count,
        'tampered_docs_count': tampered_docs_count,
        'active_transfers_count': active_transfers_count,
        'total_documents': total_documents
    }

    return render_template(
        'dashboard.html',
        stats=stats,
        ml_data=ml_data,
        db_metrics=db_metrics_rows,
        recent_alerts=recent_alerts,
        recent_audits=recent_audits,
        recent_verifications=recent_verifications
    )

# --- PROPERTY DIRECTORY & SEARCH ---

@app.route('/properties')
@login_required
def properties():
    query = request.args.get('q', '').strip()
    active_filter = request.args.get('filter', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    sql = "SELECT * FROM properties WHERE 1=1"
    params = []

    if query:
        sql += """ AND (
            property_id LIKE ? OR
            owner_name LIKE ? OR
            survey_number LIKE ? OR
            district LIKE ? OR
            taluk LIKE ? OR
            village LIKE ? OR
            location LIKE ?
        )"""
        q_wild = f"%{query}%"
        params.extend([q_wild] * 7)

    if active_filter == 'low':
        sql += " AND risk_score < 30"
    elif active_filter == 'review':
        sql += " AND risk_score >= 30 AND risk_score < 60"
    elif active_filter == 'high':
        sql += " AND risk_score >= 60"
    elif active_filter == 'duplicate':
        sql += " AND property_id IN (SELECT property_id FROM risk_alerts WHERE alert_type = 'Potential Duplicate Property')"
    elif active_filter == 'hash_mismatch':
        sql += " AND property_id IN (SELECT property_id FROM risk_alerts WHERE alert_type = 'Hash Mismatch')"
    elif active_filter == 'verified':
        sql += " AND verification_status = 'Verified'"

    sql += " ORDER BY id ASC"
    cursor.execute(sql, params)
    props = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) as cnt FROM properties")
    total_count = cursor.fetchone()['cnt']
    conn.close()

    return render_template(
        'properties.html',
        properties=props,
        query=query,
        active_filter=active_filter,
        total_count=total_count
    )

# --- PROPERTY DIGITAL PASSPORT ---

@app.route('/property/<property_id>')
@login_required
def property_passport(property_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Master Property Record
    cursor.execute("SELECT * FROM properties WHERE property_id = ?", (property_id,))
    prop = cursor.fetchone()
    if not prop:
        conn.close()
        flash(f"Property {property_id} not found.", "danger")
        return redirect(url_for('properties'))
    prop = dict(prop)

    # Documents & Data
    cursor.execute("""
        SELECT d.*, dd.owner_name, dd.survey_number, dd.land_area, dd.location, dd.registration_date as doc_reg_date
        FROM documents d
        LEFT JOIN document_data dd ON d.document_id = dd.document_id
        WHERE d.property_id = ?
    """, (property_id,))
    docs = [dict(r) for r in cursor.fetchall()]

    # Ownership History
    cursor.execute("SELECT * FROM ownership_history WHERE property_id = ? ORDER BY start_date ASC", (property_id,))
    history = [dict(r) for r in cursor.fetchall()]

    # Active Alerts
    cursor.execute("SELECT * FROM risk_alerts WHERE property_id = ? ORDER BY id DESC", (property_id,))
    alerts = [dict(r) for r in cursor.fetchall()]

    # Latest Verification Record (Section 13 & 14)
    cursor.execute("SELECT * FROM verification_records WHERE property_id = ? ORDER BY id DESC LIMIT 1", (property_id,))
    verif_row = cursor.fetchone()
    last_verif = dict(verif_row) if verif_row else None

    conn.close()

    # Determine indicators for explainability and pre-transaction check
    indicators = {
        'owner_mismatch': any('Owner' in a['alert_type'] for a in alerts),
        'survey_mismatch': any('Survey' in a['alert_type'] for a in alerts),
        'area_mismatch': any('Area' in a['alert_type'] for a in alerts),
        'duplicate_property': any('Duplicate' in a['alert_type'] for a in alerts),
        'hash_mismatch': any('Hash Mismatch' in a['alert_type'] for a in alerts),
        'ownership_conflict': any('Timeline' in a['alert_type'] or 'Conflict' in a['alert_type'] for a in alerts),
        'suspicious_transfer': any('Rapid' in a['alert_type'] for a in alerts),
        'missing_document': any('Missing' in a['alert_type'] for a in alerts),
        'location_mismatch': any('Location Mismatch' in a['alert_type'] for a in alerts) or prop.get('location_status') == 'Location Mismatch Detected',
        'land_purpose_mismatch': any('Land-Purpose Mismatch' in a['alert_type'] for a in alerts) or prop.get('purpose_status') == 'Land-Purpose Mismatch'
    }

    # Recalculate explainable reasons breakdown
    risk_res = calculate_property_risk(indicators)
    xai = explain_property_risk(indicators)

    # Generate QR Code pointing to this Digital Passport
    passport_url = request.host_url.rstrip('/') + url_for('property_passport', property_id=property_id)
    qr_data_uri = generate_qr_data_uri(passport_url)

    return render_template(
        'property_passport.html',
        prop=prop,
        documents=docs,
        history=history,
        alerts=alerts,
        indicators=indicators,
        risk_reasons=risk_res['reasons'],
        risk_recommendation=risk_res['recommendation'],
        xai=xai,
        last_verif=last_verif,
        qr_code_data_uri=qr_data_uri,
        passport_url=passport_url
    )

@app.route('/property/new', methods=['GET', 'POST'])
@login_required
@role_required('seller', 'admin')
def new_property():
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()

        # Generate next sequential ID
        cursor.execute("SELECT COUNT(*) as cnt FROM properties")
        next_num = cursor.fetchone()['cnt'] + 1
        property_id = f"RS-PROP-{next_num:04d}"

        owner_name = request.form.get('owner_name', '').strip()
        owner_id = request.form.get('owner_id', f"USR-{1000 + next_num}").strip()
        survey_number = request.form.get('survey_number', '').strip()
        land_area = float(request.form.get('land_area', 2400))
        area_unit = 'sq.ft'
        property_type = request.form.get('property_type', 'Residential Plot')
        district = request.form.get('district', 'Chennai')
        taluk = request.form.get('taluk', 'Tambaram')
        village = request.form.get('village', 'Madipakkam')
        location_str = f"{village}, {taluk}, {district}"
        registration_date = request.form.get('registration_date', datetime.now().strftime('%Y-%m-%d'))
        previous_owner = request.form.get('previous_owner', '').strip() or None

        # Geo & Land Purpose inputs
        latitude = float(request.form.get('latitude', 13.0827))
        longitude = float(request.form.get('longitude', 80.2707))
        address = request.form.get('address', '').strip() or location_str
        land_purpose = request.form.get('land_purpose', 'Residential').strip()
        declared_purpose = request.form.get('declared_purpose', 'Residential').strip()
        
        # 4-point polygon around coordinates
        poly = [
            [round(latitude - 0.00045, 6), round(longitude - 0.00055, 6)],
            [round(latitude + 0.00045, 6), round(longitude - 0.00055, 6)],
            [round(latitude + 0.00045, 6), round(longitude + 0.00055, 6)],
            [round(latitude - 0.00045, 6), round(longitude + 0.00055, 6)]
        ]
        poly_json = json.dumps(poly)
        p_status = 'Land-Purpose Mismatch' if land_purpose.lower() != declared_purpose.lower() else 'Consistent'

        cursor.execute("""
            INSERT INTO properties (
                property_id, owner_id, owner_name, survey_number, land_area, area_unit,
                property_type, district, taluk, village, location, registration_date,
                ownership_status, verification_status, risk_score, risk_level, previous_owner,
                latitude, longitude, address, land_purpose, declared_purpose, location_status, purpose_status, boundary_coordinates
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', 'Pending', 0, 'Low Risk', ?, ?, ?, ?, ?, ?, 'Consistent', ?, ?)
        """, (
            property_id, owner_id, owner_name, survey_number, land_area, area_unit,
            property_type, district, taluk, village, location_str, registration_date, previous_owner,
            latitude, longitude, address, land_purpose, declared_purpose, p_status, poly_json
        ))

        # Insert into ownership history
        if previous_owner:
            cursor.execute("""
                INSERT INTO ownership_history (property_id, owner_name, start_date, end_date, transfer_reference, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                property_id, previous_owner,
                f"{int(registration_date[:4]) - 5}-01-01", registration_date,
                f"DOC-REG-{random.randint(1000, 9999)}", "Prior Registered Conveyance"
            ))

        cursor.execute("""
            INSERT INTO ownership_history (property_id, owner_name, start_date, end_date, transfer_reference, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            property_id, owner_name, registration_date, None,
            f"DEED-{random.randint(10000, 99999)}", "Current Active Title Holder"
        ))

        conn.commit()
        conn.close()

        log_audit(session.get('user_id', 'SYSTEM'), property_id, "PROPERTY_REGISTERED", f"Created Property Digital Passport {property_id}.")
        
        # Run initial verification scan
        run_full_property_verification(property_id, trigger_user=session.get('user_id', 'SYSTEM'))

        flash(f"Property {property_id} registered successfully with Digital Passport created!", "success")
        return redirect(url_for('property_passport', property_id=property_id))

    return render_template('new_property.html')

# --- VERIFICATION & TAMPER SIMULATION ACTIONS ---

@app.route('/property/<property_id>/verify', methods=['POST'])
@login_required
def run_verification(property_id):
    current_user = session.get('user_id', 'SYSTEM')
    res = run_full_property_verification(property_id, trigger_user=current_user)
    if res:
        flash(f"Multi-vector verification complete! Score: {res['risk_score']} ({res['risk_level']}). Status: {res['verification_status']}.", "info")
    else:
        flash("Property verification failed or property not found.", "danger")
    return redirect(url_for('property_passport', property_id=property_id))

@app.route('/property/<property_id>/tamper', methods=['POST'])
@login_required
@role_required('admin')
def simulate_tamper_route(property_id):
    """Simulates unauthorized byte modification to demonstrate live SHA-256 detection."""
    if not DEMO_MODE:
        abort(404)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE property_id = ? ORDER BY id ASC LIMIT 1", (property_id,))
    doc = cursor.fetchone()
    conn.close()

    if not doc:
        flash("No document found to tamper.", "warning")
        return redirect(url_for('property_passport', property_id=property_id))

    filepath = safe_upload_path(app.config['UPLOAD_FOLDER'], doc['filename'])
    success = simulate_tampering(filepath) if filepath else False
    if success:
        log_audit(session.get('user_id', 'TEST_LAB'), property_id, "FILE_TAMPER_SIMULATION", f"Modified byte contents of {doc['filename']}.")
        # Immediately re-run verification to reflect tamper in score and alerts
        run_full_property_verification(property_id, trigger_user=session.get('user_id', 'TEST_LAB'))
        flash(f"⚠️ TAMPER LAB: Modified file bytes for {doc['filename']}. SHA-256 mismatch detected and risk score increased (+30)!", "error")
    else:
        flash("Could not locate document file on disk to tamper.", "danger")

    return redirect(url_for('property_passport', property_id=property_id))

@app.route('/property/<property_id>/restore', methods=['POST'])
@login_required
@role_required('admin')
def restore_file_route(property_id):
    """Restores clean file content and re-syncs hash."""
    if not DEMO_MODE:
        abort(404)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM properties WHERE property_id = ?", (property_id,))
    prop = cursor.fetchone()

    cursor.execute("SELECT * FROM documents WHERE property_id = ?", (property_id,))
    docs = cursor.fetchall()
    conn.close()

    if prop and docs:
        for doc in docs:
            filepath = safe_upload_path(app.config['UPLOAD_FOLDER'], doc['filename'])
            if not filepath:
                continue
            clean_lines = [
                "===========================================================",
                "       PROPAGENT ZERO DIGITAL VERIFICATION ARCHIVE",
                f"           DEMO DOCUMENT: {doc['document_type'].upper()}",
                "===========================================================",
                f"Document ID      : {doc['document_id']}",
                f"Property ID      : {property_id}",
                f"Registered Owner : {prop['owner_name']}",
                f"Survey Number    : {prop['survey_number']}",
                f"Plot Land Area   : {prop['land_area']} sq.ft",
                f"Revenue Location : {prop['location']}",
                f"Execution Date   : {prop['registration_date']}",
                f"Issuing Office   : Sub-Registrar Office, Revenue Administration",
                f"Disclaimer       : Fictional synthetic document for fraud detection demo.",
                "==========================================================="
            ]
            restore_clean_file(filepath, "\n".join(clean_lines))

        log_audit(session.get('user_id', 'TEST_LAB'), property_id, "FILE_RESTORED_CLEAN", "Restored authentic document bytes.")
        run_full_property_verification(property_id, trigger_user=session.get('user_id', 'TEST_LAB'))
        flash(f"✓ Restored clean document files and validated SHA-256 cryptographic hashes for {property_id}.", "success")

    return redirect(url_for('property_passport', property_id=property_id))

# --- DOCUMENT UPLOADS ---

@app.route('/property/<property_id>/upload', methods=['POST'])
@login_required
@role_required('seller', 'admin')
def upload_document_route(property_id):
    if 'file' not in request.files:
        flash("No file part provided.", "danger")
        return redirect(url_for('property_passport', property_id=property_id))

    file = request.files['file']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(url_for('property_passport', property_id=property_id))

    if file and allowed_file(file.filename):
        doc_type = request.form.get('document_type', 'Supplemental Document')
        raw_name = secure_filename(file.filename)
        filename = f"{property_id}_{doc_type.replace(' ', '_').lower()}_{int(datetime.now().timestamp())}_{raw_name}"
        save_path = safe_upload_path(app.config['UPLOAD_FOLDER'], filename)
        if not save_path:
            flash("Unsafe filename rejected.", "danger")
            return redirect(url_for('property_passport', property_id=property_id))
        file.save(save_path)

        # Generate SHA-256 hash immediately
        sha_hash = compute_sha256_for_file(save_path)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as cnt FROM documents WHERE property_id = ?", (property_id,))
        doc_idx = cursor.fetchone()['cnt'] + 1
        doc_id = f"RS-DOC-{property_id.split('-')[-1]}-{doc_idx}"

        cursor.execute("""
            INSERT INTO documents (document_id, property_id, document_type, filename, sha256_hash, upload_date, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, 'Verified')
        """, (doc_id, property_id, doc_type, filename, sha_hash, datetime.now().strftime('%Y-%m-%d')))

        # Document Data record
        cursor.execute("SELECT owner_name, survey_number, land_area, location, registration_date FROM properties WHERE property_id = ?", (property_id,))
        p = cursor.fetchone()
        cursor.execute("""
            INSERT INTO document_data (document_id, owner_name, survey_number, land_area, location, registration_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (doc_id, p['owner_name'], p['survey_number'], p['land_area'], p['location'], p['registration_date']))

        conn.commit()
        conn.close()

        log_audit(
            session.get('user_id', 'USER'),
            property_id,
            "DOCUMENT_UPLOADED",
            f"Uploaded {doc_type} ({doc_id}). SHA-256: {sha_hash[:16]}..."
        )

        # Re-run full verification
        run_full_property_verification(property_id, trigger_user=session.get('user_id', 'USER'))

        flash(f"Document {doc_id} uploaded successfully! SHA-256 cryptographic hash calculated: {sha_hash[:20]}...", "success")
    else:
        flash("Unsupported file extension. Allowed: txt, pdf, png, jpg, doc, docx", "danger")

    return redirect(url_for('property_passport', property_id=property_id))

@app.route('/documents')
@login_required
def documents():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.*, p.owner_name
        FROM documents d
        JOIN properties p ON d.property_id = p.property_id
        ORDER BY d.id DESC LIMIT 100
    """)
    docs = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT property_id, owner_name, village FROM properties ORDER BY property_id ASC")
    props = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) as cnt FROM documents")
    total_docs = cursor.fetchone()['cnt']
    conn.close()

    return render_template('documents.html', documents=docs, properties=props, total_docs=total_docs)

@app.route('/documents/upload', methods=['POST'])
@login_required
@role_required('seller', 'admin')
def upload_document_global():
    property_id = request.form.get('property_id')
    doc_type = request.form.get('document_type', 'Sale Deed')
    file = request.files.get('file')

    if not property_id or not file or file.filename == '':
        flash("Please select a property and file to upload.", "danger")
        return redirect(url_for('documents'))

    if not allowed_file(file.filename):
        flash("Invalid file format. Allowed: txt, pdf, doc, docx, png, jpg", "danger")
        return redirect(url_for('documents'))

    raw_name = secure_filename(file.filename)
    filename = f"{property_id}_{doc_type.replace(' ', '_').lower()}_{int(datetime.now().timestamp())}_{raw_name}"
    save_path = safe_upload_path(app.config['UPLOAD_FOLDER'], filename)
    if not save_path:
        flash("Unsafe filename rejected.", "danger")
        return redirect(url_for('documents'))
    file.save(save_path)

    sha_hash = compute_sha256_for_file(save_path)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM documents WHERE property_id = ?", (property_id,))
    doc_idx = cursor.fetchone()['cnt'] + 1
    doc_id = f"RS-DOC-{property_id.split('-')[-1]}-{doc_idx}"

    cursor.execute("""
        INSERT INTO documents (document_id, property_id, document_type, filename, sha256_hash, upload_date, verification_status)
        VALUES (?, ?, ?, ?, ?, ?, 'Verified')
    """, (doc_id, property_id, doc_type, filename, sha_hash, datetime.now().strftime('%Y-%m-%d')))

    # Optional metadata overrides entered in form
    doc_owner = request.form.get('doc_owner', '').strip()
    doc_survey = request.form.get('doc_survey', '').strip()
    doc_area = request.form.get('doc_area')
    doc_location = request.form.get('doc_location', '').strip()

    cursor.execute("SELECT owner_name, survey_number, land_area, location, registration_date FROM properties WHERE property_id = ?", (property_id,))
    p = cursor.fetchone()

    cursor.execute("""
        INSERT INTO document_data (document_id, owner_name, survey_number, land_area, location, registration_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        doc_id,
        doc_owner or p['owner_name'],
        doc_survey or p['survey_number'],
        float(doc_area) if doc_area else p['land_area'],
        doc_location or p['location'],
        p['registration_date']
    ))

    conn.commit()
    conn.close()

    log_audit(session.get('user_id', 'USER'), property_id, "DOCUMENT_UPLOADED", f"Uploaded {doc_type} ({doc_id}) via Document Vault.")
    run_full_property_verification(property_id, trigger_user=session.get('user_id', 'USER'))

    flash(f"Document {doc_id} uploaded to {property_id}! SHA-256: {sha_hash[:20]}...", "success")
    return redirect(url_for('documents'))

# --- TRANSFERS PIPELINE ---

@app.route('/transfers')
@login_required
def transfers():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT t.*, p.risk_score, p.risk_level, p.verification_status as prop_verif,
               u1.name as seller_name, u2.name as buyer_name
        FROM transfers t
        LEFT JOIN properties p ON t.property_id = p.property_id
        LEFT JOIN users u1 ON t.seller_id = u1.verified_user_id
        LEFT JOIN users u2 ON t.buyer_id = u2.verified_user_id
        ORDER BY t.id DESC
    """)
    transfer_list = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT property_id, owner_name, risk_score FROM properties ORDER BY property_id ASC")
    props = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM users WHERE role = 'buyer'")
    buyers = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return render_template(
        'transfers.html',
        transfers=transfer_list,
        properties=props,
        buyers=buyers,
        selected_property_id=request.args.get('property_id')
    )

@app.route('/transfers/initiate_page/<property_id>')
@login_required
def initiate_transfer_page(property_id):
    return redirect(url_for('transfers', property_id=property_id))

@app.route('/transfers/initiate', methods=['POST'])
@login_required
@role_required('seller', 'admin')
def initiate_transfer():
    property_id = request.form.get('property_id')
    buyer_id = request.form.get('buyer_id')
    notes = request.form.get('notes', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM properties WHERE property_id = ?", (property_id,))
    prop = cursor.fetchone()
    if not prop:
        conn.close()
        flash("Invalid property selected.", "danger")
        return redirect(url_for('transfers'))

    # Generate Transfer ID (e.g. TR-2026-0042)
    cursor.execute("SELECT COUNT(*) as cnt FROM transfers")
    next_tr = cursor.fetchone()['cnt'] + 1
    transfer_id = f"TR-2026-{next_tr:04d}"

    seller_id = prop['owner_id']

    # Initial transfer status gated by risk score
    init_status = 'Admin Review' if prop['risk_score'] < 30 else 'Review Required'

    cursor.execute("""
        INSERT INTO transfers (transfer_id, property_id, seller_id, buyer_id, status, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (transfer_id, property_id, seller_id, buyer_id, init_status, notes or 'Pre-agreement safety diligence check initiated.'))

    conn.commit()
    conn.close()

    log_audit(
        session.get('user_id', 'SELLER'),
        property_id,
        "TRANSFER_SUBMITTED",
        f"Created transfer request {transfer_id} from {seller_id} to {buyer_id}. Status: {init_status}."
    )

    flash(f"Transfer {transfer_id} created successfully! Pre-transaction checks initiated. Status: {init_status}.", "success")
    return redirect(url_for('transfers'))

@app.route('/transfers/<transfer_id>/status', methods=['POST'])
@login_required
@role_required('admin')
def update_transfer_status(transfer_id):
    new_status = request.args.get('new_status')
    if new_status not in ['Approved', 'Review Required', 'Rejected']:
        flash("Invalid transfer status action.", "danger")
        return redirect(url_for('transfers'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM transfers WHERE transfer_id = ?", (transfer_id,))
    tr = cursor.fetchone()

    if tr:
        cursor.execute("""
            UPDATE transfers
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE transfer_id = ?
        """, (new_status, transfer_id))

        # If approved, update ownership history
        if new_status == 'Approved':
            cursor.execute("SELECT * FROM users WHERE verified_user_id = ?", (tr['buyer_id'],))
            buyer = cursor.fetchone()
            buyer_name = buyer['name'] if buyer else "New Buyer"
            cursor.execute("""
                INSERT INTO ownership_history (property_id, owner_name, start_date, transfer_reference, notes)
                VALUES (?, ?, ?, ?, ?)
            """, (
                tr['property_id'],
                buyer_name,
                datetime.now().strftime('%Y-%m-%d'),
                transfer_id,
                f"Safe Transfer completed via PROPAGENT ZERO approval ({session.get('user_name', 'Admin')})"
            ))

        conn.commit()
        conn.close()

        log_audit(
            session.get('user_id', 'ADMIN'),
            tr['property_id'],
            f"TRANSFER_STATUS_{new_status.upper()}",
            f"Transfer {transfer_id} updated from '{tr['status']}' to '{new_status}'."
        )
        flash(f"Transfer {transfer_id} marked as '{new_status}' successfully!", "success")
    else:
        conn.close()
        flash("Transfer not found.", "danger")

    return redirect(url_for('transfers'))

# --- RISK ALERTS CENTER ---

@app.route('/alerts')
@login_required
def alerts():
    type_filter = request.args.get('type', '').strip()
    conn = get_db_connection()
    cursor = conn.cursor()

    sql = """
        SELECT a.*, p.owner_name, p.risk_score
        FROM risk_alerts a
        JOIN properties p ON a.property_id = p.property_id
        WHERE 1=1
    """
    params = []
    if type_filter:
        sql += " AND a.alert_type = ?"
        params.append(type_filter)

    sql += " ORDER BY a.id DESC"
    cursor.execute(sql, params)
    alert_list = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return render_template('alerts.html', alerts=alert_list, type_filter=type_filter)

# --- VERIFICATION CENTER ---

@app.route('/verification')
@login_required
def verification_center():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM verification_records ORDER BY id DESC LIMIT 100")
    records = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_template('verification.html', records=records)

@app.route('/verification/scan_all', methods=['POST'])
@login_required
@role_required('admin')
def run_system_wide_scan():
    """Executes multi-vector checks across all properties in SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT property_id FROM properties")
    all_props = [r['property_id'] for r in cursor.fetchall()]
    conn.close()

    current_user = session.get('user_id', 'SYSTEM')
    scan_count = 0
    for pid in all_props:
        run_full_property_verification(pid, trigger_user=current_user)
        scan_count += 1

    log_audit(current_user, None, "FLEET_VERIFICATION_RUN", f"Executed verification scan across {scan_count} properties.")
    flash(f"Successfully completed system-wide verification scan across {scan_count} property records!", "success")
    return redirect(url_for('verification_center'))

@app.route('/verification/scan_duplicates', methods=['POST'])
@login_required
@role_required('admin')
def run_duplicate_scan():
    """Scans and updates duplicate alerts across all properties."""
    dups = scan_all_duplicates()
    flash(f"Duplicate scan complete! Identified {len(dups)} properties with overlapping survey boundaries.", "info")
    return redirect(url_for('alerts', type='Potential Duplicate Property'))

# --- AUDIT TRAIL ---

@app.route('/audit')
@login_required
@role_required('admin')
def audit():
    query = request.args.get('q', '').strip()
    conn = get_db_connection()
    cursor = conn.cursor()

    sql = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    if query:
        sql += " AND (user_id LIKE ? OR action LIKE ? OR property_id LIKE ? OR details LIKE ?)"
        q_wild = f"%{query}%"
        params.extend([q_wild] * 4)

    sql += " ORDER BY id DESC LIMIT 200"
    cursor.execute(sql, params)
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return render_template('audit.html', logs=logs, query=query)

# --- JSON REST APIs ---

@app.route('/api/property/<property_id>')
def api_property(property_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM properties WHERE property_id = ?", (property_id,))
    p = cursor.fetchone()
    if not p:
        conn.close()
        return jsonify({'error': 'Property not found'}), 404

    cursor.execute("SELECT * FROM documents WHERE property_id = ?", (property_id,))
    docs = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM risk_alerts WHERE property_id = ?", (property_id,))
    alerts = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM ownership_history WHERE property_id = ? ORDER BY start_date ASC", (property_id,))
    history = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM verification_records WHERE property_id = ? ORDER BY id DESC LIMIT 1", (property_id,))
    latest_verif = cursor.fetchone()
    conn.close()

    return jsonify({
        'property': dict(p),
        'documents': docs,
        'alerts': alerts,
        'ownership_history': history,
        'latest_verification': dict(latest_verif) if latest_verif else None
    })

@app.route('/api/verify/<property_id>')
def api_verify(property_id):
    res = run_full_property_verification(property_id, trigger_user="API")
    if not res:
        return jsonify({'error': 'Property not found'}), 404
    return jsonify(res)

@app.route('/api/verify-property', methods=['POST'])
def api_verify_property():
    """
    POST /api/verify-property (Section 16 requirement)
    Accepts JSON or Form with:
      - 'property_id': e.g. "RS-PROP-0001"
      OR
      - Feature indicators: owner_mismatch, survey_mismatch, area_mismatch, duplicate_property,
        hash_mismatch, ownership_conflict, suspicious_transfer, missing_document
    Returns standardized risk assessment, ML prediction, SHAP explanation, and hash status.
    """
    req_data = request.get_json(silent=True) or request.form.to_dict()
    if not req_data:
        return jsonify({'error': 'Missing JSON payload or form parameters'}), 400

    prop_id = req_data.get('property_id')
    if prop_id:
        res = run_full_property_verification(prop_id, trigger_user="API_POST")
        if not res:
            return jsonify({'error': f"Property '{prop_id}' not found"}), 404

        hash_status_text = 'DOCUMENT INTEGRITY VERIFIED' if not res['indicators'].get('hash_mismatch') else 'DOCUMENT TAMPERING DETECTED'
        return jsonify({
            'property_id': prop_id,
            'ml_prediction': res['xai']['ml_prediction'],
            'ml_probability': round(res['xai']['suspicious_probability'] / 100.0, 4),
            'risk_score': res['risk_score'],
            'risk_status': res['risk_level'],
            'hash_status': hash_status_text,
            'explanation': res['xai']['plain_explanation']
        })

    # If verifying arbitrary property feature flags directly
    indicators = {
        'owner_mismatch': bool(int(req_data.get('owner_mismatch', 0))),
        'survey_mismatch': bool(int(req_data.get('survey_mismatch', 0))),
        'area_mismatch': bool(int(req_data.get('area_mismatch', 0))),
        'duplicate_property': bool(int(req_data.get('duplicate_property', 0))),
        'hash_mismatch': bool(int(req_data.get('hash_mismatch', 0))),
        'ownership_conflict': bool(int(req_data.get('ownership_conflict', 0))),
        'suspicious_transfer': bool(int(req_data.get('suspicious_transfer', 0))),
        'missing_document': bool(int(req_data.get('missing_document', 0)))
    }

    risk_res = calculate_property_risk(indicators)
    xai_res = explain_property_risk(indicators)
    hash_status_text = 'DOCUMENT INTEGRITY VERIFIED' if not indicators['hash_mismatch'] else 'DOCUMENT TAMPERING DETECTED'

    return jsonify({
        'property_id': req_data.get('custom_id', 'INSPECTION_SIMULATION'),
        'ml_prediction': xai_res['ml_prediction'],
        'ml_probability': round(xai_res['suspicious_probability'] / 100.0, 4),
        'risk_score': risk_res['score'],
        'risk_status': risk_res['risk_level'],
        'hash_status': hash_status_text,
        'explanation': xai_res['plain_explanation']
    })

@app.route('/api/model-metrics')
def api_model_metrics():
    """
    GET /api/model-metrics (Section 16 requirement)
    Returns evaluated model performance metrics and comparison table.
    """
    meta_path = os.path.join(BASE_DIR, 'models', 'model_metadata.json')
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            return jsonify(meta)
        except Exception:
            pass

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM model_metrics ORDER BY is_primary DESC, id ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    return jsonify({'model_metrics': rows})


# --- PROPERTY INTELLIGENCE DASHBOARD ---

@app.route('/intelligence')
@app.route('/intelligence/<property_id>')
@login_required
def property_intelligence(property_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT property_id, owner_name, village, district, risk_score, risk_level FROM properties ORDER BY property_id ASC")
    all_props = [dict(r) for r in cursor.fetchall()]

    if not property_id:
        property_id = request.args.get('property_id') or (all_props[0]['property_id'] if all_props else 'RS-PROP-0001')

    cursor.execute("SELECT * FROM properties WHERE property_id = ?", (property_id,))
    prop_row = cursor.fetchone()
    if not prop_row and all_props:
        property_id = all_props[0]['property_id']
        cursor.execute("SELECT * FROM properties WHERE property_id = ?", (property_id,))
        prop_row = cursor.fetchone()

    prop = dict(prop_row) if prop_row else {}

    cursor.execute("SELECT * FROM documents WHERE property_id = ?", (property_id,))
    docs = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM ownership_history WHERE property_id = ? ORDER BY start_date ASC", (property_id,))
    history = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM risk_alerts WHERE property_id = ? ORDER BY id DESC", (property_id,))
    alerts = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM verification_records WHERE property_id = ? ORDER BY id DESC LIMIT 1", (property_id,))
    verif_row = cursor.fetchone()
    conn.close()

    indicators = {
        'owner_mismatch': any('Owner' in a['alert_type'] for a in alerts),
        'survey_mismatch': any('Survey' in a['alert_type'] for a in alerts),
        'area_mismatch': any('Area' in a['alert_type'] for a in alerts),
        'duplicate_property': any('Duplicate' in a['alert_type'] for a in alerts),
        'hash_mismatch': any('Hash Mismatch' in a['alert_type'] for a in alerts),
        'ownership_conflict': any('Timeline' in a['alert_type'] or 'Conflict' in a['alert_type'] for a in alerts),
        'suspicious_transfer': any('Rapid' in a['alert_type'] for a in alerts),
        'missing_document': any('Missing' in a['alert_type'] for a in alerts),
        'location_mismatch': any('Location Mismatch' in a['alert_type'] for a in alerts) or prop.get('location_status') == 'Location Mismatch Detected',
        'land_purpose_mismatch': any('Land-Purpose Mismatch' in a['alert_type'] for a in alerts) or prop.get('purpose_status') == 'Land-Purpose Mismatch'
    }

    risk_res = calculate_property_risk(indicators)
    xai = explain_property_risk(indicators)

    passport_url = request.host_url.rstrip('/') + url_for('property_passport', property_id=property_id)
    qr_data_uri = generate_qr_data_uri(passport_url)

    return render_template(
        'intelligence.html',
        prop=prop,
        all_props=all_props,
        documents=docs,
        history=history,
        alerts=alerts,
        indicators=indicators,
        risk_reasons=risk_res['reasons'],
        risk_recommendation=risk_res['recommendation'],
        xai=xai,
        last_verif=dict(verif_row) if verif_row else None,
        qr_code_data_uri=qr_data_uri,
        passport_url=passport_url
    )

# --- PROPERTY COMPARISON ---

@app.route('/compare')
@login_required
def property_compare():
    p1_id = request.args.get('p1', 'RS-PROP-0001')
    p2_id = request.args.get('p2', 'RS-PROP-0015')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT property_id, owner_name, village, district FROM properties ORDER BY property_id ASC")
    all_props = [dict(r) for r in cursor.fetchall()]

    def get_prop_details(pid):
        cursor.execute("SELECT * FROM properties WHERE property_id = ?", (pid,))
        p_row = cursor.fetchone()
        if not p_row:
            return None
        p = dict(p_row)
        cursor.execute("SELECT * FROM documents WHERE property_id = ?", (pid,))
        p['documents'] = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM risk_alerts WHERE property_id = ?", (pid,))
        p['alerts'] = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM ownership_history WHERE property_id = ? ORDER BY start_date ASC", (pid,))
        p['history'] = [dict(r) for r in cursor.fetchall()]
        return p

    prop1 = get_prop_details(p1_id)
    prop2 = get_prop_details(p2_id)
    conn.close()

    return render_template('compare.html', prop1=prop1, prop2=prop2, p1_id=p1_id, p2_id=p2_id, all_props=all_props)

# --- DIRECT QR CODE ENDPOINT ---

@app.route('/property/<property_id>/qr')
def property_qr_code(property_id):
    from flask import Response
    passport_url = request.host_url.rstrip('/') + url_for('property_passport', property_id=property_id)
    svg_content = generate_qr_svg(passport_url)
    return Response(svg_content, mimetype='image/svg+xml')

if __name__ == '__main__':
    init_db()
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')

    print("=================================================================")
    print("  PROPAGENT ZERO — AI-Powered Property Verification & Fraud Detection")
    print("  Verify. Detect. Protect.")
    print(f"  Server running on http://{host}:{port} (Debug: {debug_mode})")
    print("  Prototype disclaimer: Synthetic/demo data only.")
    print("=================================================================")
    app.run(host=host, port=port, debug=debug_mode)
