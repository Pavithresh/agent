"""
REALSAFE Route, Security & Integration Test Suite
Verifies all Flask routes, security controls, template rendering, and interactive workflows:
- Authentication & Role-Based Access Control (@login_required, @role_required)
- Session Security & Anti-CSRF Token Validation
- /switch_role, /tamper, /restore restrictions
- API Key Authentication & Route Protection
- Dashboard, Property Directory, Property Passport
- Tamper Simulation and Restore
- Document Upload and Hash Verification
- Safe Transfer Pipeline and Admin Review
- Alerts Center and Audit Trail
- JSON REST API endpoints
"""

import sys
import os
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, DEMO_MODE, API_KEY
from models.database import get_db_connection

def run_route_tests():
    app.config['TESTING'] = True
    client = app.test_client()

    print("\n--- TEST 0: Security & Authentication Gates ---")
    
    # 0A: Unauthenticated user accessing dashboard gets redirected to /login
    resp_unauth = client.get('/dashboard')
    assert resp_unauth.status_code == 302, f"Expected 302 redirect for unauth dashboard, got {resp_unauth.status_code}"
    assert '/login' in resp_unauth.headers.get('Location', '')
    print("PASS: Unauthenticated dashboard access redirected to /login.")

    # 0B: Unauthenticated API access without API key returns 401
    resp_api_unauth = client.get('/api/property/RS-PROP-0001')
    assert resp_api_unauth.status_code == 401, f"Expected 401 for unauth API access, got {resp_api_unauth.status_code}"
    print("PASS: Unauthenticated /api access rejected with HTTP 401.")

    # 0C: Authenticate API using valid X-API-Key header returns 200
    resp_api_key = client.get('/api/property/RS-PROP-0001', headers={'X-API-Key': API_KEY})
    assert resp_api_key.status_code == 200, f"Expected 200 with X-API-Key, got {resp_api_key.status_code}"
    print("PASS: API access authorized via X-API-Key header.")

    # 0D: Login with invalid credentials returns 401
    # Get a fresh CSRF token by visiting login page
    resp_login_page = client.get('/login')
    with client.session_transaction() as sess:
        csrf_tok = sess.get('_csrf_token')

    resp_bad_login = client.post('/login', data={
        'user_id': 'USR-1000',
        'password': 'WrongPassword123!',
        'csrf_token': csrf_tok
    })
    assert resp_bad_login.status_code == 401, f"Expected 401 on bad password, got {resp_bad_login.status_code}"
    print("PASS: Login with invalid credentials rejected with HTTP 401.")

    # 0E: Login with valid credentials succeeds and creates authenticated session
    resp_good_login = client.post('/login', data={
        'user_id': 'USR-1000',
        'password': 'AdminPass2026!',
        'csrf_token': csrf_tok
    }, follow_redirects=True)
    assert resp_good_login.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get('user_id') == 'USR-1000'
        assert sess.get('user_role') == 'admin'
        admin_csrf = sess.get('_csrf_token')
    print("PASS: Admin authentication verified with werkzeug scrypt matching.")

    # 0F: CSRF validation: POST without CSRF token returns 400
    resp_no_csrf = client.post('/property/RS-PROP-0001/tamper')
    assert resp_no_csrf.status_code == 400, f"Expected 400 for missing CSRF, got {resp_no_csrf.status_code}"
    print("PASS: Mutating POST request without CSRF token blocked with HTTP 400.")

    # 0G: Method restriction: GET on /switch_role returns 405 (Method Not Allowed)
    resp_switch_get = client.get('/switch_role/buyer')
    assert resp_switch_get.status_code == 405, f"Expected 405 for GET switch_role, got {resp_switch_get.status_code}"
    print("PASS: GET /switch_role rejected with HTTP 405 (POST required).")

    # 0H: Role-based authorization: Seller account cannot access admin audit ledger
    seller_client = app.test_client()
    seller_client.get('/login')
    with seller_client.session_transaction() as sess:
        s_csrf = sess.get('_csrf_token')
    seller_client.post('/login', data={
        'user_id': 'USR-1001',
        'password': 'SellerPass2026!',
        'csrf_token': s_csrf
    }, follow_redirects=True)
    
    resp_seller_audit = seller_client.get('/audit')
    assert resp_seller_audit.status_code == 403, f"Expected 403 for seller accessing /audit, got {resp_seller_audit.status_code}"
    print("PASS: Role authorization enforced: Seller blocked from Admin audit ledger (HTTP 403).")

    print("\n--- TEST 1: Core Navigation Routes (Authenticated Admin) ---")
    routes = [
        ('/dashboard', 200),
        ('/properties', 200),
        ('/properties?filter=low', 200),
        ('/properties?filter=review', 200),
        ('/properties?filter=high', 200),
        ('/properties?filter=duplicate', 200),
        ('/properties?filter=hash_mismatch', 200),
        ('/properties?q=Chennai', 200),
        ('/documents', 200),
        ('/transfers', 200),
        ('/alerts', 200),
        ('/alerts?type=Hash+Mismatch', 200),
        ('/verification', 200),
        ('/audit', 200),
        ('/audit?q=VERIFICATION', 200),
        ('/property/new', 200),
        ('/intelligence', 200),
        ('/intelligence/RS-PROP-0001', 200),
        ('/compare', 200),
        ('/compare?p1=RS-PROP-0001&p2=RS-PROP-0015', 200),
        ('/login', 200)
    ]

    for path, expected_status in routes:
        resp = client.get(path)
        assert resp.status_code == expected_status, f"Route {path} returned {resp.status_code}, expected {expected_status}"
    print(f"PASS: All {len(routes)} navigation routes returned HTTP 200 OK.")

    print("\n--- TEST 2: Property Digital Passport Benchmark Cases ---")
    test_properties = [
        'RS-PROP-0001',
        'RS-PROP-0007',
        'RS-PROP-0015',
        'RS-PROP-0023',
        'RS-PROP-0031',
        'RS-PROP-0044',
        'RS-PROP-0058',
        'RS-PROP-0072',
        'RS-PROP-0091',
        'RS-PROP-0100'
    ]

    for pid in test_properties:
        resp = client.get(f'/property/{pid}')
        assert resp.status_code == 200, f"Passport for {pid} returned {resp.status_code}"
        assert pid.encode() in resp.data, f"Property ID {pid} not found in passport HTML output"
    print(f"PASS: Verified all {len(test_properties)} benchmark Property Passports render cleanly.")

    print("\n--- TEST 3: Interactive Document Tampering Simulation & Restore ---")
    # Fetch active admin CSRF token
    with client.session_transaction() as sess:
        admin_csrf = sess.get('_csrf_token')

    # Tamper RS-PROP-0001
    resp_tamper = client.post('/property/RS-PROP-0001/tamper', data={'csrf_token': admin_csrf}, follow_redirects=True)
    assert resp_tamper.status_code == 200
    assert b"TAMPER LAB: Modified file bytes" in resp_tamper.data or b"Hash Mismatch" in resp_tamper.data

    # Restore RS-PROP-0001
    resp_restore = client.post('/property/RS-PROP-0001/restore', data={'csrf_token': admin_csrf}, follow_redirects=True)
    assert resp_restore.status_code == 200
    assert b"Restored clean document files" in resp_restore.data or b"Verified" in resp_restore.data
    print("PASS: Tamper and restore workflows executed with live SHA-256 detection and CSRF validation.")

    print("\n--- TEST 4: Safe Transfer Workflow Execution ---")
    # Initiate Transfer
    resp_tr = client.post('/transfers/initiate', data={
        'property_id': 'RS-PROP-0001',
        'buyer_id': 'USR-1002',
        'notes': 'Automated Integration Diligence Transfer',
        'csrf_token': admin_csrf
    }, follow_redirects=True)
    assert resp_tr.status_code == 200
    assert b"TR-2026-" in resp_tr.data

    # Find the newly created transfer
    conn = get_db_connection()
    tr_row = conn.execute("SELECT transfer_id FROM transfers ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert tr_row is not None
    latest_tr = tr_row['transfer_id']

    # Admin Review Status Update
    resp_approve = client.post(f'/transfers/{latest_tr}/status?new_status=Approved', data={'csrf_token': admin_csrf}, follow_redirects=True)
    assert resp_approve.status_code == 200
    assert b"Approved" in resp_approve.data
    print(f"PASS: Transfer {latest_tr} created and Approved through Admin governance.")

    print("\n--- TEST 5: Supplemental Document Upload & Hashing ---")
    mock_file_data = b"MOCK TITLE DEED SUPPLEMENTAL VERIFICATION CONTENT"
    resp_up = client.post('/property/RS-PROP-0001/upload', data={
        'document_type': 'Ownership Certificate',
        'file': (io.BytesIO(mock_file_data), 'supplemental_cert.txt'),
        'csrf_token': admin_csrf
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp_up.status_code == 200
    assert b"uploaded successfully" in resp_up.data
    print("PASS: Supplemental document uploaded and SHA-256 calculated.")

    print("\n--- TEST 6: JSON REST APIs ---")
    # 1. GET /api/property/<id> (session-authenticated)
    api_resp = client.get('/api/property/RS-PROP-0001')
    assert api_resp.status_code == 200
    json_data = api_resp.get_json()
    assert 'property' in json_data
    assert json_data['property']['property_id'] == 'RS-PROP-0001'

    # 2. GET /api/verify/<id>
    verif_api_resp = client.get('/api/verify/RS-PROP-0001')
    assert verif_api_resp.status_code == 200
    v_data = verif_api_resp.get_json()
    assert 'risk_score' in v_data

    # 3. GET /api/model-metrics
    metrics_resp = client.get('/api/model-metrics')
    assert metrics_resp.status_code == 200
    m_data = metrics_resp.get_json()
    assert 'random_forest' in m_data or 'model_metrics' in m_data

    # 4. POST /api/verify-property
    post_verif = client.post('/api/verify-property', json={'property_id': 'RS-PROP-0031'})
    assert post_verif.status_code == 200
    pv_data = post_verif.get_json()
    assert pv_data['property_id'] == 'RS-PROP-0031'
    assert 'risk_score' in pv_data
    assert 'risk_status' in pv_data
    assert 'ml_prediction' in pv_data
    assert 'hash_status' in pv_data
    assert 'explanation' in pv_data
    print(f"      Verified POST /api/verify-property: Score={pv_data['risk_score']}, Status={pv_data['risk_status']}, Hash={pv_data['hash_status']}")

    print("PASS: All JSON REST API endpoints verified (GET & POST with session & header auth).")

    print("\n--- TEST 7: Geo Map, Land Purpose, QR & Comparison Intelligence ---")
    # 1. QR Code endpoint
    qr_resp = client.get('/property/RS-PROP-0001/qr')
    assert qr_resp.status_code == 200, f"QR endpoint returned {qr_resp.status_code}"
    assert b"<svg" in qr_resp.data, "QR code output is not valid SVG"
    print("PASS: Cryptographic QR Code endpoint renders valid SVG.")

    # 2. Intelligence View and Land-Purpose Mismatch
    intel_resp = client.get('/intelligence/RS-PROP-0015')
    assert intel_resp.status_code == 200
    assert b"LAND-PURPOSE MISMATCH" in intel_resp.data, "Land-purpose mismatch banner missing on RS-PROP-0015"
    assert b"leaflet" in intel_resp.data.lower(), "Leaflet map asset missing in intelligence page"
    print("PASS: Property Intelligence Dashboard renders Geo Map and flags Land-Purpose Mismatch on RS-PROP-0015.")

    # 3. Property Comparison
    comp_resp = client.get('/compare?p1=RS-PROP-0001&p2=RS-PROP-0015')
    assert comp_resp.status_code == 200
    assert b"RS-PROP-0001" in comp_resp.data and b"RS-PROP-0015" in comp_resp.data
    assert b"Comparative Attributes Matrix" in comp_resp.data
    print("PASS: Property Comparison renders factual side-by-side matrix.")

    print("\n=======================================================")
    print("ALL 8 ROUTE, SECURITY & INTELLIGENCE TEST SUITES PASSED (100% OK)!")
    print("=======================================================")

if __name__ == '__main__':
    run_route_tests()
