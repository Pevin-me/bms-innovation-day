from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response
from flask_socketio import SocketIO, emit
from sensor_reader import BMSSensorReader
import threading
import time
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging
from datetime import datetime, timedelta
from functools import wraps
import traceback
from config import get_config
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load configuration
config = get_config()

# Helper function to get IST timestamp
def get_ist_timestamp():
    """Get current timestamp in IST timezone."""
    utc_now = datetime.utcnow()
    ist_offset = timedelta(hours=5, minutes=30)
    ist_now = utc_now + ist_offset
    return ist_now.strftime("%Y-%m-%d %H:%M:%S")

app = Flask(__name__)
app.config.from_object(config)
socketio = SocketIO(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bms.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize sensor reader with configuration
sensor_reader = BMSSensorReader(
    serial_port=config.SERIAL_PORT,
    baud_rate=config.SERIAL_BAUD_RATE
)
last_status = "normal"

# Cache for last received data
last_esp32_data = {
    'voltage': 0.0,
    'current': 0.0,
    'power': 0.0,
    'temperature': None,
    'soc': None,
    'status': 'normal',
    'timestamp': '',
    'source': 'esp32'
}
last_esp32_update = 0

# Error handling decorator
def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            if request.is_json:
                return jsonify({'error': 'Internal server error'}), 500
            else:
                flash('An error occurred. Please try again.', 'error')
                return redirect(url_for('dashboard'))
    return decorated_function

# Input validation functions
def validate_voltage(voltage):
    """Validate voltage reading."""
    try:
        voltage = float(voltage)
        return 0.0 <= voltage <= 100.0  # Support up to 100V for multi-cell packs
    except (ValueError, TypeError):
        return False

def validate_current(current):
    """Validate current reading."""
    try:
        current = float(current)
        return -50.0 <= current <= 50.0
    except (ValueError, TypeError):
        return False

def validate_temperature(temp):
    """Validate temperature reading."""
    try:
        temp = float(temp)
        return -50.0 <= temp <= 100.0
    except (ValueError, TypeError):
        return False

def validate_soc(soc):
    """Validate state of charge."""
    try:
        soc = float(soc)
        return 0.0 <= soc <= 100.0
    except (ValueError, TypeError):
        return False

def sanitize_input(data):
    """Sanitize user input."""
    if isinstance(data, str):
        return data.strip()[:1000]  # Limit length and strip whitespace
    return data

def validate_login_input(username, password):
    """Validate login input."""
    if not username or not password:
        return False, "Username and password are required"
    
    if len(username) > 50 or len(password) > 100:
        return False, "Input too long"
    
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Invalid username format"
    
    return True, "Valid"

def validate_contact_input(data):
    """Validate contact form input."""
    errors = []
    
    # Required fields
    required_fields = ['FirstName', 'LastName', 'Email', 'Message']
    for field in required_fields:
        if not data.get(field) or not data.get(field).strip():
            errors.append(f"{field} is required")
    
    # Email validation
    email = data.get('Email', '').strip()
    if email and '@' not in email:
        errors.append("Invalid email format")
    
    # Length validation
    if len(data.get('Message', '')) > 1000:
        errors.append("Message too long")
    
    return len(errors) == 0, errors

# ------------------- Sensor Thread -------------------
def sensor_reading_thread():
    global last_status, last_esp32_data, last_esp32_update
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    while True:
        try:
            # Check if we have recent ESP32 data
            current_time = time.time()
            has_recent_esp32_data = (last_esp32_update > 0 and 
                                   (current_time - last_esp32_update) < 3.0)
            
            if has_recent_esp32_data:
                # Use cached ESP32 data for display
                data = last_esp32_data.copy()
                logger.debug("Using cached ESP32 data for display")
            else:
                # No ESP32 data, return zero values
                data = {
                    'voltage': 0.0,
                    'current': 0.0,
                    'power': 0.0,
                    'temperature': 0.0,
                    'soc': 0.0,
                    'status': 'normal',
                    'timestamp': get_ist_timestamp(),
                    'source': 'none'
                }
                logger.debug("No ESP32 data, using zero values")

            # Save to database with error handling (only for new data)
            if not has_recent_esp32_data:
                try:
                    conn = sqlite3.connect('bms.db')
                    c = conn.cursor()
                    c.execute('''INSERT INTO battery_data 
                                 (voltage, current, power, temperature, soc, status)
                                 VALUES (?, ?, ?, ?, ?, ?)''',
                              (data['voltage'],
                               data['current'],
                               data['power'],
                               data['temperature'],
                               data['soc'],
                               data['status']))
                    conn.commit()
                    conn.close()
                    
                    # Reset error counter on successful database write
                    consecutive_errors = 0
                    
                except Exception as db_error:
                    logger.error(f"Database write failed: {db_error}")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        logger.critical("Too many consecutive database errors. Stopping sensor thread.")
                        break

            # Emit to clients
            try:
                socketio.emit('battery_update', data)
            except Exception as socket_error:
                logger.error(f"Socket emit failed: {socket_error}")

            # Handle status changes and notifications (only for new data)
            if not has_recent_esp32_data:
                if last_status == "normal" and data['status'] != "normal":
                    try:
                        socketio.emit('notification', {
                            'message': f"Anomaly detected: {data['status'].replace('_', ' ')}",
                            'level': 'warning',
                            'timestamp': time.strftime("%H:%M:%S")
                        })
                        # Log alert to database
                        log_alert(data['status'], f"Anomaly detected: {data['status']}")
                    except Exception as notif_error:
                        logger.error(f"Notification failed: {notif_error}")
                        
                elif last_status != "normal" and data['status'] == "normal":
                    try:
                        socketio.emit('notification', {
                            'message': "Battery status back to normal",
                            'level': 'info',
                            'timestamp': time.strftime("%H:%M:%S")
                        })
                        # Resolve any open alerts
                        resolve_alerts()
                    except Exception as notif_error:
                        logger.error(f"Notification failed: {notif_error}")

                last_status = data['status']

        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Sensor reading failed: {e}")
            logger.error(traceback.format_exc())
            
            if consecutive_errors >= max_consecutive_errors:
                logger.critical("Too many consecutive sensor errors. Stopping sensor thread.")
                break

        time.sleep(config.SENSOR_READ_INTERVAL)

def log_alert(alert_type, message, severity='warning'):
    """Log alert to database."""
    try:
        conn = sqlite3.connect('bms.db')
        c = conn.cursor()
        c.execute('''INSERT INTO alerts (alert_type, message, severity) 
                     VALUES (?, ?, ?)''',
                  (alert_type, message, severity))
        conn.commit()
        conn.close()
        logger.info(f"Alert logged: {alert_type} - {message}")
    except Exception as e:
        logger.error(f"Failed to log alert: {e}")

def resolve_alerts():
    """Resolve all open alerts."""
    try:
        conn = sqlite3.connect('bms.db')
        c = conn.cursor()
        c.execute('''UPDATE alerts 
                     SET is_resolved = 1, resolved_at = CURRENT_TIMESTAMP 
                     WHERE is_resolved = 0''')
        conn.commit()
        conn.close()
        logger.info("All alerts resolved")
    except Exception as e:
        logger.error(f"Failed to resolve alerts: {e}")

def get_current_data():
    """Get current data from ESP32 cache or return zero values."""
    global last_esp32_data, last_esp32_update
    
    current_time = time.time()
    
    # If we have recent ESP32 data (within 3 seconds), use it
    if last_esp32_update > 0 and (current_time - last_esp32_update) < 3.0:
        logger.debug("Using cached ESP32 data")
        return last_esp32_data
    else:
        # Return zero values if no recent ESP32 data
        logger.debug("No recent ESP32 data, returning zero values")
        return {
            'voltage': 0.0,
            'current': 0.0,
            'power': 0.0,
            'temperature': 0.0,
            'soc': 0.0,
            'status': 'normal',
            'timestamp': get_ist_timestamp(),
            'source': 'none'
        }

# Start sensor thread
threading.Thread(target=sensor_reading_thread, daemon=True).start()

# ------------------- Database Setup -------------------
def init_db():
    """Initialize database with proper schema and migrations."""
    conn = sqlite3.connect('bms.db')
    c = conn.cursor()
    
    try:
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password TEXT NOT NULL,
                      email TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      last_login DATETIME,
                      is_active BOOLEAN DEFAULT 1)''')
        
        # Battery data table with proper schema
        c.execute('''CREATE TABLE IF NOT EXISTS battery_data
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      voltage REAL NOT NULL,
                      current REAL NOT NULL,
                      power REAL NOT NULL,
                      temperature REAL,
                      soc REAL,
                      status TEXT DEFAULT 'normal',
                      cell_voltages TEXT,
                      cell_temperatures TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        # System settings table
        c.execute('''CREATE TABLE IF NOT EXISTS system_settings
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      setting_key TEXT UNIQUE NOT NULL,
                      setting_value TEXT NOT NULL,
                      description TEXT,
                      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        # Alerts table
        c.execute('''CREATE TABLE IF NOT EXISTS alerts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      alert_type TEXT NOT NULL,
                      message TEXT NOT NULL,
                      severity TEXT DEFAULT 'warning',
                      is_resolved BOOLEAN DEFAULT 0,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      resolved_at DATETIME)''')
        
        conn.commit()
        
        # Run migrations
        run_migrations(c, conn)
        
        # Create default users
        create_default_users(c, conn)
        
        # Create default settings
        create_default_settings(c, conn)
        
        conn.commit()
        logger.info("[INFO] Database initialized successfully")
        
    except Exception as e:
        logger.error(f"[ERROR] Database initialization failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

def run_migrations(cursor, conn):
    """Run database migrations to update schema."""
    try:
        # Check if SOC column exists in battery_data
        cursor.execute("PRAGMA table_info(battery_data)")
        columns = [info[1] for info in cursor.fetchall()]
        
        # Add missing columns
        if 'soc' not in columns:
            cursor.execute("ALTER TABLE battery_data ADD COLUMN soc REAL")
            logger.info("[INFO] Added SOC column to battery_data")
        
        if 'cell_voltages' not in columns:
            cursor.execute("ALTER TABLE battery_data ADD COLUMN cell_voltages TEXT")
            logger.info("[INFO] Added cell_voltages column to battery_data")
            
        if 'cell_temperatures' not in columns:
            cursor.execute("ALTER TABLE battery_data ADD COLUMN cell_temperatures TEXT")
            logger.info("[INFO] Added cell_temperatures column to battery_data")
            
        if 'created_at' not in columns:
            cursor.execute("ALTER TABLE battery_data ADD COLUMN created_at DATETIME")
            logger.info("[INFO] Added created_at column to battery_data")
        
        # Check users table columns
        cursor.execute("PRAGMA table_info(users)")
        user_columns = [info[1] for info in cursor.fetchall()]
        
        if 'created_at' not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN created_at DATETIME")
            logger.info("[INFO] Added created_at column to users")
            
        if 'last_login' not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login DATETIME")
            logger.info("[INFO] Added last_login column to users")
            
        if 'is_active' not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1")
            logger.info("[INFO] Added is_active column to users")
        
        conn.commit()
        
    except Exception as e:
        logger.error(f"[ERROR] Migration failed: {e}")
        raise

def create_default_users(cursor, conn):
    """Create default users if they don't exist."""
    try:
        # Check if admin user exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                          ('admin', generate_password_hash('admin123'), 'admin@bms.local'))
            logger.info("[INFO] Created default admin user")
        
        # Check if user1 exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'user1'")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                          ('user1', generate_password_hash('password1'), 'user1@bms.local'))
            logger.info("[INFO] Created default user1")
            
    except sqlite3.IntegrityError:
        pass  # Users already exist
    except Exception as e:
        logger.error(f"[ERROR] Failed to create default users: {e}")

def create_default_settings(cursor, conn):
    """Create default system settings."""
    default_settings = [
        ('voltage_min', '3.6', 'Minimum safe battery voltage'),
        ('voltage_max', '4.1', 'Maximum safe battery voltage'),
        ('temp_max', '40', 'Maximum safe temperature in Celsius'),
        ('soc_min', '20', 'Minimum safe state of charge percentage'),
        ('data_retention_days', '30', 'Number of days to retain data'),
        ('alert_email', 'admin@bms.local', 'Email for alerts'),
        ('system_name', 'BMS System', 'System name'),
        ('version', '2.0', 'System version')
    ]
    
    try:
        for key, value, description in default_settings:
            cursor.execute("INSERT OR IGNORE INTO system_settings (setting_key, setting_value, description) VALUES (?, ?, ?)",
                          (key, value, description))
        logger.info("[INFO] Created default system settings")
    except Exception as e:
        logger.error(f"[ERROR] Failed to create default settings: {e}")

def add_soc_column_if_missing():
    """Legacy function - now handled by migrations."""
    pass

init_db()

# ------------------- Routes -------------------
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@handle_errors
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        # Validate input
        is_valid, error_msg = validate_login_input(username, password)
        if not is_valid:
            logger.warning(f"Invalid login attempt: {error_msg}")
            return render_template('login.html', error=error_msg)
        
        try:
            conn = sqlite3.connect('bms.db')
            c = conn.cursor()
            c.execute('SELECT id, password, is_active FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            
            if user and user[2] and check_password_hash(user[1], password):  # Check if user is active
                # Update last login
                c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
                conn.commit()
                conn.close()
                
                session['username'] = username
                session['user_id'] = user[0]
                logger.info(f"User {username} logged in successfully")
                return redirect(url_for('dashboard'))
            else:
                conn.close()
                logger.warning(f"Failed login attempt for username: {username}")
                return render_template('login.html', error="Invalid username or password")
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return render_template('login.html', error="Login failed. Please try again.")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get current data (ESP32 cache or zero values)
    data = get_current_data()

    return render_template('dashboard.html', username=session['username'], data=data)

@app.route('/api/battery_data')
def get_battery_data():
    conn = sqlite3.connect('bms.db')
    c = conn.cursor()
    c.execute('SELECT * FROM battery_data ORDER BY timestamp DESC LIMIT 20')
    rows = c.fetchall()
    conn.close()

    data = []
    for row in rows:
        try:
            soc_value = float(row[7]) if row[7] is not None else 0.0
        except (ValueError, TypeError):
            soc_value = 0.0

        status_value = str(row[6]) if row[6] is not None else "unknown"

        data.append({
            'id': row[0],
            'timestamp': row[1],
            'voltage': row[2],
            'current': row[3],
            'power': row[4],
            'temperature': row[5],
            'soc': soc_value,
            'status': status_value
        })

    return jsonify(data)

@app.route('/api/esp32_data', methods=['POST'])
@handle_errors
def receive_esp32_data():
    """Receive data from ESP32 via HTTP POST."""
    try:
        data = request.get_json()
        
        if not data:
            logger.warning("Received empty data from ESP32")
            return jsonify({'status': 'error', 'message': 'No data received'}), 400
        
        # Log received data
        logger.info(f"Received ESP32 data: {data}")
        
        # Validate and sanitize data
        voltage = data.get('voltage', 0)
        current = data.get('current', 0)
        temperature = data.get('temperature', None)
        soc = data.get('soc', None)
        
        # Validate data ranges
        if not validate_voltage(voltage):
            logger.warning(f"Invalid voltage from ESP32: {voltage}")
            voltage = 0.0
            
        if not validate_current(current):
            logger.warning(f"Invalid current from ESP32: {current}")
            current = 0.0
            
        if temperature is not None and not validate_temperature(temperature):
            logger.warning(f"Invalid temperature from ESP32: {temperature}")
            temperature = None
            
        if soc is not None and not validate_soc(soc):
            logger.warning(f"Invalid SOC from ESP32: {soc}")
            soc = None
        
        # Calculate power
        power = voltage * current
        
        # Determine status based on thresholds
        status = 'normal'
        if temperature is not None and temperature > config.TEMP_MAX:
            status = 'temperature_anomaly'
        elif voltage < config.VOLTAGE_MIN or voltage > config.VOLTAGE_MAX:
            status = 'voltage_anomaly'
        elif soc is not None and soc < config.SOC_MIN:
            status = 'low_soc_anomaly'
        
        # Store in database
        conn = sqlite3.connect('bms.db')
        c = conn.cursor()
        c.execute('''INSERT INTO battery_data 
                     (voltage, current, power, temperature, soc, status)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (voltage, current, power, temperature, soc, status))
        conn.commit()
        conn.close()
        
        # Prepare data for real-time update
        update_data = {
            'voltage': voltage,
            'current': current,
            'power': power,
            'temperature': temperature,
            'soc': soc,
            'status': status,
            'timestamp': get_ist_timestamp(),
            'source': 'esp32'
        }
        
        # Cache the data for display between updates
        global last_esp32_data, last_esp32_update
        last_esp32_data = update_data.copy()
        last_esp32_update = time.time()
        
        # Emit to connected clients
        socketio.emit('battery_update', update_data)
        
        # Log alert if anomaly detected
        if status != 'normal':
            log_alert(status, f"ESP32 detected anomaly: {status}")
        
        logger.info(f"ESP32 data processed successfully: {status}")
        return jsonify({'status': 'success', 'message': 'Data received and processed'}), 200
        
    except Exception as e:
        logger.error(f"Error processing ESP32 data: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/download_csv')
def download_csv():
    conn = sqlite3.connect('bms.db')
    c = conn.cursor()
    c.execute('SELECT * FROM battery_data ORDER BY timestamp DESC')
    rows = c.fetchall()
    conn.close()

    header = ['id', 'timestamp', 'voltage', 'current', 'power', 'temperature', 'soc', 'status']

    def generate():
        yield ','.join(header) + '\n'
        for row in rows:
            yield ','.join([str(x) if x is not None else '' for x in row]) + '\n'

    return Response(generate(), mimetype='text/csv',
                    headers={"Content-Disposition": "attachment;filename=battery_data.csv"})

@app.route('/history')
def history():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('bms.db')
    c = conn.cursor()
    c.execute('SELECT * FROM battery_data ORDER BY timestamp DESC LIMIT 20')
    rows = c.fetchall()
    conn.close()

    data = []
    for row in rows:
        try:
            soc_value = float(row[7]) if row[7] is not None else 0.0
        except (ValueError, TypeError):
            soc_value = 0.0

        status_value = str(row[6]) if row[6] is not None else "unknown"  # <-- ensure string

        # Convert UTC timestamp to IST
        timestamp_str = row[1]
        try:
            # Parse the UTC timestamp
            utc_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            # Add IST offset (+5:30)
            ist_time = utc_time + timedelta(hours=5, minutes=30)
            timestamp_str = ist_time.strftime("%Y-%m-%d %H:%M:%S")
        except:
            # If parsing fails, use original timestamp
            pass

        data.append({
            'id': row[0],
            'timestamp': timestamp_str,
            'voltage': row[2],
            'current': row[3],
            'power': row[4],
            'temperature': row[5],
            'soc': soc_value,
            'status': status_value
        })

    return render_template('history.html', data=data)

@app.route('/contact-admin', methods=['GET', 'POST'])
@handle_errors
def contact_admin():
    if request.method == 'POST':
        # Sanitize all inputs
        form_data = {
            'FirstName': sanitize_input(request.form.get('FirstName', '')),
            'LastName': sanitize_input(request.form.get('LastName', '')),
            'Email': sanitize_input(request.form.get('Email', '')),
            'PhoneNumber': sanitize_input(request.form.get('PhoneNumber', '')),
            'Message': sanitize_input(request.form.get('Message', ''))
        }
        
        # Validate input
        is_valid, errors = validate_contact_input(form_data)
        if not is_valid:
            error_msg = '; '.join(errors)
            logger.warning(f"Invalid contact form submission: {error_msg}")
            return render_template('contact_admin.html', error=error_msg)
        
        try:
            # Log the contact request (in a real system, you'd send an email)
            logger.info(f"Contact form submitted by {form_data['FirstName']} {form_data['LastName']} ({form_data['Email']})")
            logger.info(f"Message: {form_data['Message']}")
            
            # In a real implementation, you would:
            # 1. Send email to admin
            # 2. Store in database
            # 3. Send confirmation to user
            
            flash('Your message has been sent to the administrator. We will get back to you soon!')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Contact form error: {e}")
            return render_template('contact_admin.html', error="Failed to send message. Please try again.")
    
    return render_template('contact_admin.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
