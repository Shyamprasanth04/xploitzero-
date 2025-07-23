from flask import Flask, render_template, request, send_file, jsonify, redirect, url_for, make_response, render_template_string, abort
import io
import csv
import json
from scanner import scan_all
from weasyprint import HTML
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import os

app = Flask(__name__)

latest_scan = {}

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_this_secret_key')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your_email@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your_password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'your_email@example.com')
app.config['API_KEY'] = os.environ.get('API_KEY', 'changeme_api_key_12345')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(512))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create default admin user if not present
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    url = request.form.get('url')
    email = request.form.get('email')
    selected_checks = {
        'headers': 'scan_headers' in request.form,
        'xss': 'scan_xss' in request.form,
        'sqli': 'scan_sqli' in request.form,
        'open_redirect': 'scan_open_redirect' in request.form,
        'directory_listing': 'scan_directory_listing' in request.form,
        'admin_panels': 'scan_admin_panels' in request.form,
    }
    results = scan_all(url, selected_checks)
    global latest_scan
    latest_scan = results
    # Save to DB
    scan_entry = ScanResult(url=url, results_json=json.dumps(results))
    db.session.add(scan_entry)
    db.session.commit()
    # Send email if provided
    if email:
        try:
            msg = Message('Your Vulnerability Scan Results', recipients=[email])
            msg.body = f"Scan results for {url}:\n\n" + json.dumps(results, indent=2)
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send email: {e}")
    return render_template('results.html', results=results)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    api_key = request.headers.get('X-API-KEY')
    if api_key != app.config['API_KEY']:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url in request'}), 400
    url = data['url']
    email = data.get('email')
    selected_checks = data.get('selected_checks', {
        'headers': True,
        'xss': True,
        'sqli': True,
        'open_redirect': True,
        'directory_listing': True,
        'admin_panels': True,
    })
    results = scan_all(url, selected_checks)
    # Save to DB
    scan_entry = ScanResult(url=url, results_json=json.dumps(results))
    db.session.add(scan_entry)
    db.session.commit()
    # Send email if provided
    if email:
        try:
            msg = Message('Your Vulnerability Scan Results', recipients=[email])
            msg.body = f"Scan results for {url}:\n\n" + json.dumps(results, indent=2)
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send email: {e}")
    return jsonify(results)

@app.route('/history')
@login_required
def history():
    scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    for scan in scans:
        scan.parsed_results = json.loads(scan.results_json)
    return render_template('history.html', scans=scans)

@app.route('/view/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    results = json.loads(scan.results_json)
    return render_template('results.html', results=results)

@app.route('/download/<int:scan_id>')
@login_required
def download_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    results = json.loads(scan.results_json)
    format = request.args.get('format', 'json')
    if format == 'json':
        response = make_response(json.dumps(results, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan_id}.json'
        return response
    elif format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Check', 'Summary'])
        for key in results:
            if isinstance(results[key], dict) and 'summary' in results[key]:
                writer.writerow([key, results[key]['summary']])
            else:
                writer.writerow([key, str(results[key])])
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan_id}.csv'
        return response
    elif format == 'pdf':
        html = render_template_string('''
        <h1>Web Application Vulnerability Scan Report</h1>
        <h2>Summary</h2>
        <ul>
        {% for key, value in scan.items() %}
            <li><strong>{{ key|capitalize }}:</strong> 
                {% if value.summary is defined %}{{ value.summary }}{% else %}{{ value }}{% endif %}
            </li>
        {% endfor %}
        </ul>
        <h2>Details</h2>
        <pre>{{ scan|tojson(indent=2) }}</pre>
        ''', scan=results)
        pdf = HTML(string=html).write_pdf()
        return send_file(io.BytesIO(pdf), download_name=f'scan_{scan_id}.pdf', as_attachment=True)
    else:
        return redirect(url_for('history'))

@app.route('/export/<format>')
@login_required
def export_results(format):
    if not latest_scan:
        return redirect(url_for('home'))
    if format == 'json':
        response = make_response(json.dumps(latest_scan, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = 'attachment; filename=scan_results.json'
        return response
    elif format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Check', 'Summary'])
        for key in latest_scan:
            if isinstance(latest_scan[key], dict) and 'summary' in latest_scan[key]:
                writer.writerow([key, latest_scan[key]['summary']])
            else:
                writer.writerow([key, str(latest_scan[key])])
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=scan_results.csv'
        return response
    elif format == 'pdf':
        html = render_template_string('''
        <h1>Web Application Vulnerability Scan Report</h1>
        <h2>Summary</h2>
        <ul>
        {% for key, value in scan.items() %}
            <li><strong>{{ key|capitalize }}:</strong> 
                {% if value.summary is defined %}{{ value.summary }}{% else %}{{ value }}{% endif %}
            </li>
        {% endfor %}
        </ul>
        <h2>Details</h2>
        <pre>{{ scan|tojson(indent=2) }}</pre>
        ''', scan=latest_scan)
        pdf = HTML(string=html).write_pdf()
        return send_file(io.BytesIO(pdf), download_name='scan_results.pdf', as_attachment=True)
    else:
        return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    total_scans = len(scans)
    findings = {
        'headers': 0,
        'xss': 0,
        'sqli': 0,
        'open_redirect': 0,
        'directory_listing': 0,
        'admin_panels': 0,
    }
    scan_dates = []
    for scan in scans:
        results = json.loads(scan.results_json)
        scan_dates.append(scan.timestamp.strftime('%Y-%m-%d'))
        if 'headers' in results and isinstance(results['headers'], dict):
            # Count as finding if any header is missing
            if any(v is None for k, v in results['headers'].items() if k != 'status_code' and k != 'error'):
                findings['headers'] += 1
        if 'xss' in results and isinstance(results['xss'], dict):
            if results['xss'].get('vulnerable') or (results['xss'].get('vulnerable') is False and results['xss'].get('payload')):
                findings['xss'] += int(results['xss'].get('vulnerable', False))
        if 'sqli' in results and isinstance(results['sqli'], dict):
            if results['sqli'].get('summary'):
                findings['sqli'] += 1
        if 'open_redirect' in results and isinstance(results['open_redirect'], dict):
            if results['open_redirect'].get('vulnerable'):
                findings['open_redirect'] += 1
        if 'directory_listing' in results and isinstance(results['directory_listing'], dict):
            if results['directory_listing'].get('summary'):
                findings['directory_listing'] += 1
        if 'admin_panels' in results and isinstance(results['admin_panels'], dict):
            if results['admin_panels'].get('summary'):
                findings['admin_panels'] += 1
    return render_template('dashboard.html', total_scans=total_scans, findings=findings, scan_dates=scan_dates)

if __name__ == '__main__':
    app.run(debug=True) 