from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # Import Flask-Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
from web3 import Web3
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding 

# Initialize Flask application
app = Flask(__name__)
app.config.from_object('config') # Load configuration from config.py
# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db) 

# Web3 connection setup
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

SYSTEM_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
agU5TBJ2FK0vPAQFFGdm/Y6J8H4WGgP8dHVMNDHhpzPO76zaU4mZSKPmvvTYvIFE
DgkhvmB4QCbqURTqjYJH+dAVgPMvjWPYsLjg1Q6nxDwfij+5Bu9sGViHa7Hjn1Dy
0SikvAkZrYJvAzPUwkV+Q+X4XH2Wj3XB/vqK7LDXrTmTPGpYHxUmXYlJ8XQhDWWt
HR6tJn3/AgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2eFyoy/5Yk+QUGgc7XW6
dS4g4EsmWiEkc1B/gUZ5CZQDYULgm4v8/4ExM0jNEisfy3PkutUyo/SPqw4xQQI/
kSDgk/QzfW4FSVTyGmvZnYMtbXgXnQvSRs+9SW7BfHHnZWgk4K/o2sOZEKV7sdvG
hmUck7F/tBsOJq+l4MN9+4xevTsn+hfH9HnLUN7NGXNHdMZQPJTf5lfG41HyYrRL
+LBgi2gGivY9RQCrVWxAyZKzpCHRYGrMdL2tEQYlOeECgYEA3ZcS3GJKl+P3CWbh
+JkIB6FxwK4gpkXznKYUDXHfLg9aGXRa1ZlgFVVJx9SfC87aLZu52iFGYcv2Ig7Y
zqaZVOuEQlTYlzPQT1rxCEx0ZlQijSw3RjfAkGHnWmz8Q99g7vgQnXwZZWDYPQXZ
5PHmkMrjq6PxeAchFSAJ8P9V7SUCgYEA2FiFXFXRLtLGI6yv8mkS5LzvZkUfnrPx
KtjotVsZ5+hvRUyLrIpQBRJGxtMnq3KT5jkY4MvycmNYIyKnpeVS0SQ79yj+ZsFj
AymJKHP3ULh2yr1wCH1OyFz6eY4k8D3+4ht+pPYx6vpa2+/tMoNmKYYGGmVYajXz
ulPRdC7TAkMCgYAqOBLQp9VC5dzN9QBfYu7TSjCnCiSB0xDo9Jm8qlAnolNoWOqf
LHQQr/MH10rDCdxbzAqyhMPuJH0hLb9AA0Kc0GEIRFwLXHdN2qN9JO9eUZbX+I/s
m4gf3o3hg/WrgJTpZ/keKBnU2v4NCKyWwan0IuDVVXBwnKPoZNsm5OMDXQKBgQCB
5CoMvESz33PFY+JmQMlC1tjJqbXLUcQDnSMZnCrFP/Rw1bhwqGhT0uMCMpOJzXKq
K0Smcm585QCf7+9uwxkZ43l8+F4bT1YQf4BxPXXjGmXIbPNgAdCIreV/p4j9Pm6+
I1kXyJVVgNFBM+NjzkKf0y6fGdghjA8tN/D6ziu0twKBgDBhvWqKUHNp3QQKcY1P
UpOlY3BHhS/V8R7+roRfcmJ0AA+2xcNGvTH+s6novS0rPDaZ1YypOzWFcrSIQGcL
w02qFa0bJxrOgG/QcOZKXLJ9PCjcRqy6PTXlYvFglzJtI4+DWWHVmtOhugLKrfMN
hW2Jsq1XKjcFfHzaJGl9QTl6
-----END PRIVATE KEY-----"""

SYSTEM_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWWoFOUwS
dhStLzwEBRRnZv2OifB+FhoD/HR1TDQx4aczzu+s2lOJmUij5r702LyBRA4JIb5g
eEAm6lEU6o2CR/nQFYDzL41j2LC44NUOp8Q8H4o/uQbvbBlYh2ux459Q8tEopLwJ
Ga2CbwMz1MJFfkPl+Fx9lo91wf76iuyw1605kzxqWB8VJl2JSfF0IQ1lrR0erSZ9
/wIDAQAB
-----END PUBLIC KEY-----"""

# Smart contract configuration
sender_address = "0x4fA56e6950d6B974601804dEB870D445181743b0"
sender_private_key = "0x0cce9b153592751fbb7716098f3ea95bca91faa3c293e1c07547686fdb88a1eb"

# Load smart contract ABI and address
with open("KeyManagementContract_abi.json", 'r') as file:
    key_contract_abi = json.load(file)

key_contract_address = "0xb28C8F360B18723d6083a74f370D1619bDfE676e"  # Your deployed contract address
key_contract = web3.eth.contract(address=key_contract_address, abi=key_contract_abi)

# Load exam management contract
with open("ExamManagementContract_abi.json", 'r') as file:
    exam_contract_abi = json.load(file)

exam_contract_address = "0x36558B9f2C8D0481b013F429e04f9fbc878Bb703"  # Your deployed exam contract address
exam_contract = web3.eth.contract(address=exam_contract_address, abi=exam_contract_abi)

# Encryption/Decryption utility functions
def generate_key_pair():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # Import Flask-Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
from web3 import Web3
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding  # Add this import

# ... rest of your imports and setup ...

def encrypt_data(public_key_pem, data):
    """Encrypt data using public key with hybrid encryption"""
    # Convert string public key to key object
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    # Ensure data is bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # For large data, use hybrid encryption (AES + RSA)
    if len(data) > 190:  # Safe limit for 2048-bit RSA
        # Generate random AES key
        aes_key = os.urandom(32)  # 256-bit key
        
        # Encrypt the data with AES
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad data to be multiple of block size
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()  # Use sym_padding here
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt the AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Format: [encrypted_key_length (4 bytes)][encrypted_key][iv][encrypted_data]
        encrypted = (len(encrypted_key).to_bytes(4, byteorder='big') + 
                    encrypted_key + iv + encrypted_data)
    else:
        # For small data, use RSA directly
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    # Return base64 encoded encrypted data for storage
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_data(private_key_pem, encrypted_data_b64):
    """Decrypt data using private key with hybrid decryption"""
    # Convert string private key to key object
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    # Decrypt data
    encrypted = base64.b64decode(encrypted_data_b64)
    
    # Check if it's hybrid encryption (first 4 bytes indicate encrypted key length)
    if len(encrypted) > 256:  # Likely hybrid encryption
        try:
            # Extract the encrypted key length
            key_length = int.from_bytes(encrypted[:4], byteorder='big')
            
            # Extract the encrypted key, IV and encrypted data
            encrypted_key = encrypted[4:4+key_length]
            iv = encrypted[4+key_length:4+key_length+16]
            encrypted_data = encrypted[4+key_length+16:]
            
            # Decrypt the AES key
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the data with AES
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad the data
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()  # Use sym_padding here
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data.decode('utf-8')
        except Exception as e:
            # If hybrid decryption fails, fall back to direct RSA
            pass
    
    # Direct RSA decryption
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted.decode('utf-8')

def store_private_key_on_blockchain(user_id, private_key):
    """Store encrypted private key on blockchain"""
    # We encrypt the private key with a password before storing it
    # In a real system, this would be more secure
    # Here we're using a simple encryption for demonstration
    encrypted_key = encrypt_data(
        # Use the constant defined at the top of the file instead of config
        SYSTEM_PUBLIC_KEY, 
        private_key
    )
    
    # Send transaction to store encrypted key
    try:
        nonce = web3.eth.get_transaction_count(sender_address)
        tx = key_contract.functions.storePrivateKey(
            user_id, 
            encrypted_key
        ).build_transaction({
            'nonce': nonce,
            'gas': 3000000,
            'gasPrice': web3.to_wei('20', 'gwei'),
            'from': sender_address
        })
        
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
        
        # For newer Web3.py versions, use .raw_transaction instead of .rawTransaction
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        
        return True, f"Key stored with transaction hash: {tx_hash.hex()}"
    except Exception as e:
        return False, f"Failed to store key: {str(e)}"

def get_private_key_from_blockchain(user_id):
    """Retrieve private key from blockchain"""
    try:
        encrypted_key = key_contract.functions.getPrivateKey(user_id).call()
        if not encrypted_key:
            return None, "No key found for this user"
        
        # Decrypt with system private key
        decrypted_key = decrypt_data(
            SYSTEM_PRIVATE_KEY,
            encrypted_key
        )
        
        return decrypted_key, "Key retrieved successfully"
    except Exception as e:
        return None, f"Error retrieving key: {str(e)}"
    
# Models# Updated User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'student'
    public_key = db.Column(db.Text, nullable=True)  # Store public key in database
    blockchain_address = db.Column(db.String(42), nullable=True)  # Ethereum address for user

class Exam(db.Model):
    __tablename__ = 'exams'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    age_min = db.Column(db.Integer, nullable=False)
    age_max = db.Column(db.Integer, nullable=False)
    education_level = db.Column(db.String(50), nullable=False)
    eligible_colleges = db.Column(db.Text, nullable=True)
    mcqs = db.relationship('MCQ', backref='exam', lazy=True)
    start_time = db.Column(db.Time, nullable=True)  # Start time
    results_published = db.Column(db.Boolean, default=False)  # Track result publication
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_exam_creator_id'), nullable=True)  # Named foreign key

    # New fields
    date = db.Column(db.Date, nullable=True)  # Exam date
    time_limit = db.Column(db.Integer, nullable=True)  # Time limit in minutes


class ExamRegistration(db.Model):
    __tablename__ = 'exam_registrations'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    college_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.Text, nullable=False)
    aadhaar_number = db.Column(db.String(12), nullable=False)
    age = db.Column(db.Integer, nullable=False)

class MCQ(db.Model):
    __tablename__ = 'mcqs'
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(
        db.Integer,
        db.ForeignKey('exams.id', name='fk_mcqs_exam_id'),  # Explicitly named foreign key
        nullable=False
    )
    question = db.Column(db.String(255), nullable=False)
    option1 = db.Column(db.String(100), nullable=False)
    option2 = db.Column(db.String(100), nullable=False)
    option3 = db.Column(db.String(100), nullable=False)
    option4 = db.Column(db.String(100), nullable=False)
    correct_answer = db.Column(db.String(100), nullable=False)


class Query(db.Model):
    __tablename__ = 'queries'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)  # Admin's response
    timestamp = db.Column(db.DateTime, default=db.func.now())

class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    rank = db.Column(db.Integer, nullable=True)

    # Add relationships
    student = db.relationship('User', backref='results', lazy=True)
    exam = db.relationship('Exam', backref='results', lazy=True)


# Routes
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Choose a different one.', 'warning')
            return redirect(url_for('register'))
        
        # Generate key pair for the user
        private_key, public_key = generate_key_pair()
        
        # Create the user with public key
        user = User(
            username=username, 
            password=password, 
            role=role, 
            public_key=public_key
        )
        
        # Add user to database to get ID
        db.session.add(user)
        db.session.flush()  # Get ID without committing
        
        # Store private key on blockchain
        success, message = store_private_key_on_blockchain(user.id, private_key)
        if not success:
            db.session.rollback()
            flash(f'Registration failed: {message}', 'danger')
            return redirect(url_for('register'))
        
        # Log the key creation on blockchain
        # In the register route:
        try:
            nonce = web3.eth.get_transaction_count(sender_address)
            tx = key_contract.functions.logKeyGeneration(
                user.id, role, username
            ).build_transaction({
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'from': sender_address
            })
            
            signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            web3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception as e:
            # Continue even if logging fails
            print(f"Failed to log key generation: {str(e)}")
        
        # Commit the user to database
        db.session.commit()
        
        flash(f'{role.capitalize()} registered successfully! Your keys have been generated securely.', 'success')
        return redirect(url_for('home'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['role'] = user.role
            session['user_id'] = user.id  # Add user_id to session
            flash('Login successful!', 'success')
            
            # Check role and redirect accordingly
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'student':
                return redirect(url_for('student_dashboard'))
            else:
                # Handle any other roles that might be added in the future
                flash('Unknown user role. Please contact administrator.', 'warning')
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    exams = Exam.query.all()
    
    # Decrypt exam descriptions for display
    decrypted_exams = []
    for exam in exams:
        decrypted_exam = get_decrypted_exam_data(exam)
        decrypted_exams.append(decrypted_exam)
    
    return render_template(
        'admin_dashboard.html', 
        exams=exams,
        decrypted_exams=decrypted_exams,
        zipped_exams=zip(exams, decrypted_exams)
    )
@app.route('/admin/add_exam', methods=['GET', 'POST'])
def add_exam():
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        age_min = int(request.form['age_min'])
        age_max = int(request.form['age_max'])
        education_level = request.form['education_level']
        eligible_colleges = request.form['eligible_colleges']
        
        # Convert date string to Python date object
        date_str = request.form['date']
        exam_date = datetime.strptime(date_str, '%Y-%m-%d').date()  # Parse to date
        
        # Process start time if provided
        start_time = None
        start_time_str = ""
        if 'start_time' in request.form and request.form['start_time']:
            start_time_str = request.form['start_time']
            start_time = datetime.strptime(start_time_str, '%H:%M').time()
        
        time_limit = int(request.form['time_limit'])

        # Get admin's public key
        admin_id = session['user_id']
        admin = User.query.get(admin_id)
        
        # Encrypt sensitive exam data
        encrypted_description = encrypt_data(admin.public_key, description)
        encrypted_eligible_colleges = encrypt_data(admin.public_key, eligible_colleges)

        exam = Exam(
            name=name,
            description=encrypted_description,  # Encrypted
            age_min=age_min,
            age_max=age_max,
            education_level=education_level,
            eligible_colleges=encrypted_eligible_colleges,  # Encrypted
            date=exam_date,
            start_time=start_time,  # Add start time if provided
            time_limit=time_limit,
            creator_id=admin_id  # Store the creator ID directly in the database
        )

        # Add exam to database to get ID
        db.session.add(exam)
        db.session.flush()  # Get ID without committing

        # Log exam creation on blockchain
        try:
            # Prepare exam data for blockchain with more comprehensive information
            exam_data = {
                'name': name,
                'admin_id': admin_id,
                'creator_username': admin.username,
                'date': date_str,
                'start_time': start_time_str,
                'time_limit': time_limit,
                'age_range': f"{age_min}-{age_max}",
                'education_level': education_level,
                'created_at': datetime.now().isoformat(),
                'description_hash': web3.keccak(text=description).hex(),  # Store hash for verification
                'eligible_colleges_hash': web3.keccak(text=eligible_colleges).hex()
            }
            
            # Convert to JSON
            exam_json = json.dumps(exam_data)
            
            # Log on blockchain
            nonce = web3.eth.get_transaction_count(sender_address)
            tx = exam_contract.functions.createExam(
                exam.id,
                admin_id,
                exam_json
            ).build_transaction({
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'from': sender_address
            })
            
            signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            web3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Add a log entry specifically for admin association
            nonce = web3.eth.get_transaction_count(sender_address)
            admin_log = {
                'exam_id': exam.id,
                'admin_id': admin_id,
                'admin_username': admin.username,
                'action': 'created_exam',
                'timestamp': datetime.now().isoformat()
            }
            admin_log_json = json.dumps(admin_log)
            
            tx = exam_contract.functions.logExamAction(
                admin_id,
                exam.id,
                'admin_created_exam',
                admin_log_json
            ).build_transaction({
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'from': sender_address
            })
            
            signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            web3.eth.wait_for_transaction_receipt(tx_hash)
            
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to create exam: {str(e)}', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Complete the transaction
        db.session.commit()
        flash('Exam added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_exam.html')

# Fix 1: Update the set_mcqs function to use raw_transaction instead of rawTransaction
@app.route('/admin/set_mcqs/<int:exam_id>', methods=['GET', 'POST'])
def set_mcqs(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    exam = Exam.query.get_or_404(exam_id)
    admin_id = session['user_id']
    admin = User.query.get(admin_id)

    if request.method == 'POST':
        question = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_answer = request.form['correct_answer']

        # Encrypt question and options with admin's public key
        encrypted_question = encrypt_data(admin.public_key, question)
        encrypted_option1 = encrypt_data(admin.public_key, option1)
        encrypted_option2 = encrypt_data(admin.public_key, option2)
        encrypted_option3 = encrypt_data(admin.public_key, option3)
        encrypted_option4 = encrypt_data(admin.public_key, option4)
        encrypted_correct_answer = encrypt_data(admin.public_key, correct_answer)

        mcq = MCQ(
            exam_id=exam_id,
            question=encrypted_question,
            option1=encrypted_option1,
            option2=encrypted_option2,
            option3=encrypted_option3,
            option4=encrypted_option4,
            correct_answer=encrypted_correct_answer
        )
        
        # Add to database
        db.session.add(mcq)
        db.session.flush()
        
        # Store on blockchain
        try:
            # Create JSON data
            mcq_data = {
                'exam_id': exam_id,
                'question_id': mcq.id,
                'creator_id': admin_id,
                'created_at': datetime.now().isoformat()
            }
            
            mcq_json = json.dumps(mcq_data)
            
            # Hash of actual question for verification
            question_hash = web3.keccak(text=question).hex()
            
            # Add to blockchain
            nonce = web3.eth.get_transaction_count(sender_address)
            tx = exam_contract.functions.addQuestion(
                exam_id,
                mcq.id,
                question_hash,
                mcq_json
            ).build_transaction({
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'from': sender_address
            })
            
            signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)  # FIXED: changed from rawTransaction to raw_transaction
            web3.eth.wait_for_transaction_receipt(tx_hash)
            
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to add question: {str(e)}', 'danger')
            return redirect(url_for('set_mcqs', exam_id=exam_id))
        
        # Complete transaction
        db.session.commit()
        flash('MCQ added successfully!', 'success')
        return redirect(url_for('set_mcqs', exam_id=exam_id))

    # Retrieve and decrypt existing MCQs
    mcqs = MCQ.query.filter_by(exam_id=exam_id).all()
    
    # Get admin's private key to decrypt
    private_key, msg = get_private_key_from_blockchain(admin_id)
    if private_key:
        # Decrypt MCQs for display
        decrypted_mcqs = []
        for mcq in mcqs:
            try:
                decrypted_mcq = {
                    'id': mcq.id,
                    'question': decrypt_data(private_key, mcq.question),
                    'option1': decrypt_data(private_key, mcq.option1),
                    'option2': decrypt_data(private_key, mcq.option2),
                    'option3': decrypt_data(private_key, mcq.option3),
                    'option4': decrypt_data(private_key, mcq.option4),
                    'correct_answer': decrypt_data(private_key, mcq.correct_answer)
                }
                decrypted_mcqs.append(decrypted_mcq)
            except Exception as e:
                print(f"Error decrypting MCQ {mcq.id}: {str(e)}")
    else:
        flash('Could not decrypt questions: ' + msg, 'warning')
        decrypted_mcqs = []
        
    return render_template('set_mcqs.html', exam=exam, mcqs=decrypted_mcqs)

# Fix 2: Update the take_exam function to use raw_transaction instead of rawTransaction
# and to handle the key retrieval error
@app.route('/take_exam/<int:exam_id>', methods=['GET', 'POST'])
def take_exam(exam_id):
    # Ensure user is logged in and is a student
    if 'role' not in session or session['role'] != 'student':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    # Fetch the exam and validate its existence
    exam = Exam.query.get_or_404(exam_id)
    
    # Get decrypted exam data
    decrypted_exam = get_decrypted_exam_data(exam)

    # Fetch current time for schedule validation
    current_time = datetime.now()
    
    # Check if exam has required date/time fields
    if not exam.date or not exam.start_time:
        flash('Exam schedule is not set properly.', 'danger')
        return redirect(url_for('student_dashboard'))
        
    exam_start_time = datetime.combine(exam.date, exam.start_time)
    exam_end_time = exam_start_time + timedelta(minutes=exam.time_limit or 180)  # Default to 3 hours if not set

    # Check if the exam is scheduled
    if current_time < exam_start_time:
        flash('The exam has not started yet.', 'danger')
        return redirect(url_for('student_dashboard'))

    # Check if the exam is within the allowed time range
    if current_time > exam_end_time:
        flash('The exam has ended.', 'danger')
        return redirect(url_for('student_dashboard'))

    # Check if the student is registered for the exam
    student_id = session['user_id']
    student = User.query.get(student_id)
    registration = ExamRegistration.query.filter_by(student_id=student_id, exam_id=exam_id).first()
    if not registration:
        flash('You are not registered for this exam.', 'danger')
        return redirect(url_for('student_dashboard'))

    # Check if the student has already attempted the exam
    existing_result = Result.query.filter_by(student_id=student_id, exam_id=exam_id).first()
    if existing_result:
        flash('You have already attempted this exam.', 'danger')
        return redirect(url_for('student_dashboard'))

    # Get admin's private key to decrypt questions - Fixed to handle errors better
    admin_id = exam.creator_id
    if not admin_id:
        # Try to get from blockchain if not stored in database
        try:
            exam_data_json = exam_contract.functions.getExamData(exam.id).call()
            exam_data = json.loads(exam_data_json)
            admin_id = exam_data.get('admin_id')
        except Exception as e:
            # If blockchain doesn't have it, try to use the first admin
            admin = User.query.filter_by(role='admin').first()
            if admin:
                admin_id = admin.id
            else:
                flash('Could not determine exam creator.', 'danger')
                return redirect(url_for('student_dashboard'))
    
    admin_private_key = None
    try:
        admin_private_key, msg = get_private_key_from_blockchain(admin_id)
        if not admin_private_key:
            # If we can't get the admin's key, try to use any available admin
            other_admins = User.query.filter(User.role == 'admin', User.id != admin_id).all()
            for admin in other_admins:
                admin_private_key, _ = get_private_key_from_blockchain(admin.id)
                if admin_private_key:
                    break
            
            if not admin_private_key:
                flash('Could not load exam questions: ' + msg, 'danger')
                return redirect(url_for('student_dashboard'))
    except Exception as e:
        flash(f'Error retrieving keys: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))
    
    # Fetch and decrypt the exam questions
    encrypted_mcqs = MCQ.query.filter_by(exam_id=exam_id).all()
    
    # Decrypt questions
    decrypted_mcqs = []
    for mcq in encrypted_mcqs:
        try:
            decrypted_mcq = {
                'id': mcq.id,
                'question': decrypt_data(admin_private_key, mcq.question),
                'option1': decrypt_data(admin_private_key, mcq.option1),
                'option2': decrypt_data(admin_private_key, mcq.option2),
                'option3': decrypt_data(admin_private_key, mcq.option3),
                'option4': decrypt_data(admin_private_key, mcq.option4),
                # Don't decrypt correct answer for students!
            }
            decrypted_mcqs.append(decrypted_mcq)
        except Exception as e:
            print(f"Error decrypting MCQ {mcq.id}: {str(e)}")

    # Handle POST request for submitting the exam
    if request.method == 'POST':
        # Extract student answers 
        answers = request.form
        student_answers = {}
        for key, value in answers.items():
            if key.startswith('mcq_'):
                mcq_id = int(key.split('_')[1])
                student_answers[mcq_id] = value
                
        # Calculate score
        score = 0
        for mcq in encrypted_mcqs:
            if mcq.id in student_answers:
                correct = decrypt_data(admin_private_key, mcq.correct_answer)
                if student_answers[mcq.id] == correct:
                    score += 1
                    
        # Encrypt student responses with student's public key
        encrypted_answers = {}
        for mcq_id, answer in student_answers.items():
            encrypted_answers[mcq_id] = encrypt_data(student.public_key, answer)
        
        # Record the result in the database
        result = Result(student_id=student_id, exam_id=exam_id, score=score)
        db.session.add(result)
        db.session.flush()  # Get the result ID
        
        # Log the exam attempt and result on blockchain
        try:
            # Create JSON data
            exam_attempt_data = {
                'exam_id': exam_id,
                'student_id': student_id,
                'start_time': session.get('exam_start_time', ''),
                'end_time': current_time.isoformat(),
                'score': score,
                'question_count': len(encrypted_mcqs),
                'result_id': result.id
            }
            
            attempt_json = json.dumps(exam_attempt_data)
            
            # Store on blockchain
            nonce = web3.eth.get_transaction_count(sender_address)
            tx = exam_contract.functions.recordExamAttempt(
                student_id,
                exam_id,
                result.id,
                score,
                len(encrypted_mcqs),
                attempt_json
            ).build_transaction({
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'from': sender_address
            })
            
            signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)  # FIXED: changed from rawTransaction to raw_transaction
            web3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Also store each answer
            for mcq_id, answer in student_answers.items():
                answer_hash = web3.keccak(text=answer).hex()
                
                nonce = web3.eth.get_transaction_count(sender_address)
                tx = exam_contract.functions.recordStudentAnswer(
                    result.id,
                    mcq_id,
                    answer_hash
                ).build_transaction({
                    'nonce': nonce,
                    'gas': 3000000,
                    'gasPrice': web3.to_wei('20', 'gwei'),
                    'from': sender_address
                })
                
                signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
                tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)  # FIXED: changed from rawTransaction to raw_transaction
                web3.eth.wait_for_transaction_receipt(tx_hash)
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error recording exam results: {str(e)}', 'danger')
            return redirect(url_for('student_dashboard'))

        # Complete the transaction
        db.session.commit()
        flash(f'You completed the exam! Your score is {score}.', 'success')
        return redirect(url_for('student_dashboard'))

    # Store the exam start time in the session
    session['exam_start_time'] = current_time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Log exam start on blockchain
    try:
        log_data = {
            'exam_id': exam_id,
            'student_id': student_id,
            'start_time': session['exam_start_time'],
            'action': 'exam_started'
        }
        
        log_json = json.dumps(log_data)
        
        nonce = web3.eth.get_transaction_count(sender_address)
        tx = exam_contract.functions.logExamAction(
            student_id,
            exam_id,
            'exam_started',
            log_json
        ).build_transaction({
            'nonce': nonce,
            'gas': 3000000,
            'gasPrice': web3.to_wei('20', 'gwei'),
            'from': sender_address
        })
        
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)  # FIXED: changed from rawTransaction to raw_transaction
        web3.eth.wait_for_transaction_receipt(tx_hash)
    except Exception as e:
        # Continue even if logging fails
        print(f"Failed to log exam start: {str(e)}")

    return render_template('take_exam.html', 
                           exam=exam, 
                           decrypted_exam=decrypted_exam,
                           mcqs=decrypted_mcqs)


@app.route('/admin/review_results/<int:exam_id>', methods=['GET', 'POST'])
def review_results(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    results = Result.query.filter_by(exam_id=exam_id).all()
    if request.method == 'POST':
        action = request.form['action']
        student_id = int(request.form['student_id'])
        result = Result.query.filter_by(student_id=student_id, exam_id=exam_id).first()

        if action == 'accept':
            result.status = 'accepted'
        elif action == 'reject':
            result.status = 'rejected'
        elif action == 'second_chance':
            result.status = 'second_chance'
            # Allow the student to retake the exam
            db.session.delete(result)

        db.session.commit()
        flash('Result updated successfully!', 'success')

    return render_template('review_results.html', results=results)

@app.route('/admin/delete_exam/<int:exam_id>')
def delete_exam(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    
    exam = Exam.query.get_or_404(exam_id)
    
    try:
        # First, record the deletion in the blockchain
        admin_id = session['user_id']
        
        deletion_data = {
            'exam_id': exam_id,
            'admin_id': admin_id,
            'exam_name': exam.name,
            'deletion_time': datetime.now().isoformat(),
            'action': 'delete_exam'
        }
        
        deletion_json = json.dumps(deletion_data)
        
        # Log to blockchain
        nonce = web3.eth.get_transaction_count(sender_address)
        tx = exam_contract.functions.logExamAction(
            admin_id,
            exam_id,
            'exam_deleted',
            deletion_json
        ).build_transaction({
            'nonce': nonce,
            'gas': 3000000,
            'gasPrice': web3.to_wei('20', 'gwei'),
            'from': sender_address
        })
        
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Delete related data first (due to foreign key constraints)
        # 1. Delete MCQs
        mcqs = MCQ.query.filter_by(exam_id=exam_id).all()
        for mcq in mcqs:
            db.session.delete(mcq)
        
        # 2. Delete exam results
        results = Result.query.filter_by(exam_id=exam_id).all()
        for result in results:
            db.session.delete(result)
        
        # 3. Delete registrations
        registrations = ExamRegistration.query.filter_by(exam_id=exam_id).all()
        for registration in registrations:
            db.session.delete(registration)
        
        # 4. Finally delete the exam
        db.session.delete(exam)
        db.session.commit()
        
        flash('Exam has been successfully deleted.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the exam: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/contact_admin', methods=['GET', 'POST'])
def contact_admin():
    if 'role' not in session or session['role'] != 'student':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        message = request.form['message']
        query = Query(student_id=session['user_id'], message=message)
        db.session.add(query)
        db.session.commit()
        flash('Your query has been sent to the admin.', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template('contact_admin.html')

@app.route('/view_results/<int:exam_id>')
def view_results(exam_id):
    if 'role' not in session or session['role'] != 'student':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    exam = Exam.query.get_or_404(exam_id)
    if not exam.results_published:
        flash('Results for this exam are not yet published.', 'info')
        return redirect(url_for('student_dashboard'))

    student_id = session['user_id']
    student_result = Result.query.filter_by(student_id=student_id, exam_id=exam_id).first()

    # Get decrypted exam description
    decrypted_exam = get_decrypted_exam_data(exam)

    # Get student's private key to decrypt their own information
    student_private_key = None
    if session['role'] == 'student':
        student_private_key, _ = get_private_key_from_blockchain(student_id)

    # Join with User and ExamRegistration tables and decrypt student info
    exam_registrations = {}
    students = User.query.filter_by(role='student').all()
    
    for student in students:
        registration = ExamRegistration.query.filter_by(student_id=student.id, exam_id=exam_id).first()
        if registration:
            # First try to decrypt with the student's own key
            student_key, _ = get_private_key_from_blockchain(student.id)
            if student_key:
                try:
                    decrypted_data = {
                        'aadhaar_number': decrypt_data(student_key, registration.aadhaar_number),
                        'college_name': decrypt_data(student_key, registration.college_name)
                    }
                    exam_registrations[student.id] = decrypted_data
                except Exception:
                    # If student key decrypt fails, data remains encrypted
                    exam_registrations[student.id] = {
                        'aadhaar_number': 'Encrypted',
                        'college_name': 'Encrypted'
                    }
            else:
                exam_registrations[student.id] = {
                    'aadhaar_number': 'Encrypted',
                    'college_name': 'Encrypted'
                }

    rankings = (
        db.session.query(
            Result,
            User.username
        )
        .join(User, User.id == Result.student_id)
        .filter(Result.exam_id == exam_id)
        .order_by(Result.score.desc())
        .all()
    )

    # Calculate the student's rank
    rank = next((idx + 1 for idx, (result, _) in enumerate(rankings) if result.student_id == student_id), None)

    return render_template(
        'view_results.html', 
        exam=exam,
        decrypted_exam=decrypted_exam,
        student_result=student_result, 
        rankings=rankings,
        exam_registrations=exam_registrations,
        rank=rank,
        enumerate=enumerate  # Pass enumerate to the template
    )

@app.route('/admin/edit_exam/<int:exam_id>', methods=['GET', 'POST'])
def edit_exam(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    exam = Exam.query.get_or_404(exam_id)
    admin_id = session['user_id']
    
    # Get decrypted exam data for displaying in the form
    decrypted_exam = get_decrypted_exam_data(exam)

    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        description = request.form['description']
        age_min = int(request.form['age_min'])
        age_max = int(request.form['age_max'])
        education_level = request.form['education_level']
        eligible_colleges = request.form['eligible_colleges']
        
        # Convert date string to Python date object
        date_str = request.form['date']
        exam_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        time_limit = int(request.form['time_limit'])
        
        # Get admin's public key
        admin = User.query.get(admin_id)
        
        # Encrypt sensitive data
        encrypted_description = encrypt_data(admin.public_key, description)
        encrypted_eligible_colleges = encrypt_data(admin.public_key, eligible_colleges)

        # Update exam
        exam.name = name
        exam.description = encrypted_description
        exam.age_min = age_min
        exam.age_max = age_max
        exam.education_level = education_level
        exam.eligible_colleges = encrypted_eligible_colleges
        exam.date = exam_date
        exam.time_limit = time_limit

        try:
            # Update in blockchain
            exam_data = {
                'name': name,
                'admin_id': admin_id,
                'date': date_str,
                'time_limit': time_limit,
                'age_range': f"{age_min}-{age_max}",
                'education_level': education_level,
                'updated_at': datetime.now().isoformat(),
                'description_hash': web3.keccak(text=description).hex(),
                'eligible_colleges_hash': web3.keccak(text=eligible_colleges).hex()
            }
            
            # Convert to JSON
            exam_json = json.dumps(exam_data)
            
            # Log on blockchain
            nonce = web3.eth.get_transaction_count(sender_address)
            tx = exam_contract.functions.updateExam(
                exam.id,
                admin_id,
                exam_json
            ).build_transaction({
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'from': sender_address
            })
            
            signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            web3.eth.wait_for_transaction_receipt(tx_hash)
            
            # Update database
            db.session.commit()
            flash('Exam updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to update exam: {str(e)}', 'danger')
            return redirect(url_for('edit_exam', exam_id=exam_id))

    return render_template('edit_exam.html', exam=exam, decrypted_exam=decrypted_exam)

# Route to delete an exam
# @app.route('/admin/delete_exam/<int:exam_id>')
# def delete_exam(exam_id):
#     if 'role' not in session or session['role'] != 'admin':
#         flash('Unauthorized access!', 'danger')
#         return redirect(url_for('login'))

#     exam = Exam.query.get_or_404(exam_id)
#     db.session.delete(exam)
#     db.session.commit()
#     flash('Exam deleted successfully!', 'success')
#     return redirect(url_for('admin_dashboard'))

# Route to manage questions for an exam
@app.route('/admin/manage_questions/<int:exam_id>', methods=['GET', 'POST'])
def manage_questions(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    exam = Exam.query.get_or_404(exam_id)

    if request.method == 'POST':
        question = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_answer = request.form['correct_answer']

        mcq = MCQ(
            exam_id=exam_id,
            question=question,
            option1=option1,
            option2=option2,
            option3=option3,
            option4=option4,
            correct_answer=correct_answer
        )
        db.session.add(mcq)
        db.session.commit()
        flash('Question added successfully!', 'success')

    mcqs = MCQ.query.filter_by(exam_id=exam_id).all()
    return render_template('manage_questions.html', exam=exam, mcqs=mcqs)
@app.route('/schedule_exam/<int:exam_id>', methods=['GET', 'POST'])
def schedule_exam(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    exam = Exam.query.get_or_404(exam_id)

    if request.method == 'POST':
        # Convert date and time strings to appropriate Python objects
        date_str = request.form['exam_date']  # Format: YYYY-MM-DD
        start_time_str = request.form['start_time']  # Format: HH:MM
        end_time_str = request.form['end_time']  # Format: HH:MM

        try:
            exam_date = datetime.strptime(date_str, '%Y-%m-%d').date()  # Convert to date object
            start_time = datetime.strptime(start_time_str, '%H:%M').time()  # Convert to time object
            end_time = datetime.strptime(end_time_str, '%H:%M').time()  # Convert to time object

            # Update the exam with the schedule
            exam.date = exam_date
            exam.start_time = start_time
            exam.end_time = end_time
            db.session.commit()
            flash('Exam schedule updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except ValueError as e:
            flash(f'Invalid date or time format: {e}', 'danger')

    return render_template('schedule_exam.html', exam=exam)


@app.route('/publish_results/<int:exam_id>')
def publish_results(exam_id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    # Fetch the exam
    exam = Exam.query.get_or_404(exam_id)

    # Update the results_published flag
    exam.results_published = True
    db.session.commit()

    flash('Results published successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/view_queries', methods=['GET', 'POST'])
def view_queries():
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    queries = Query.query.filter(Query.response == None).all()  # Unanswered queries

    if request.method == 'POST':
        query_id = request.form['query_id']
        response = request.form['response']
        query = Query.query.get(query_id)
        if query:
            query.response = response
            db.session.commit()
            flash('Query responded successfully!', 'success')
        return redirect(url_for('view_queries'))

    return render_template('view_queries.html', queries=queries)


from datetime import datetime

@app.route('/student_dashboard')
def student_dashboard():
    if 'role' in session and session['role'] == 'student':
        student_id = session['user_id']
        exams = Exam.query.all()
        registrations = ExamRegistration.query.filter_by(student_id=student_id).all()

        # Fetch registered and attempted exams
        registered_exam_ids = {reg.exam_id for reg in registrations}
        attempted_exam_ids = {
            result.exam_id for result in Result.query.filter_by(student_id=student_id).all()
        }

        # Precompute exam statuses and decrypt descriptions
        current_time = datetime.now()
        exam_statuses = {}
        decrypted_exams = []
        
        for exam in exams:
            # Handle exam status
            if exam.date is None or exam.start_time is None:
                exam_statuses[exam.id] = 'invalid_time'
            else:
                exam_start = datetime.combine(exam.date, exam.start_time)
                if exam.id in attempted_exam_ids:
                    exam_statuses[exam.id] = 'submitted'
                elif current_time < exam_start:
                    exam_statuses[exam.id] = 'not_started'
                else:
                    exam_statuses[exam.id] = 'available'
            
            # Get decrypted exam data
            decrypted_data = get_decrypted_exam_data(exam)
            decrypted_exams.append(decrypted_data)

        return render_template(
            'student_dashboard.html',
            exams=exams,
            decrypted_exams=decrypted_exams,
            registered_exam_ids=registered_exam_ids,
            exam_statuses=exam_statuses
        )
    flash('Access unauthorized. Please log in as a student.', 'danger')
    return redirect(url_for('login'))

@app.route('/register_exam/<int:exam_id>', methods=['GET', 'POST'])
def register_exam(exam_id):
    if 'role' not in session or session['role'] != 'student':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    exam = Exam.query.get_or_404(exam_id)
    student_id = session['user_id']
    student = User.query.get(student_id)
    
    # Get decrypted exam data
    decrypted_exam = get_decrypted_exam_data(exam)
    
    if request.method == 'POST':
        name = request.form['name']
        college_name = request.form['college_name']
        address = request.form['address']
        aadhaar_number = request.form['aadhaar_number']
        age = int(request.form['age'])
        education_level = request.form['education_level']

        # Check eligibility
        if age < exam.age_min or age > exam.age_max:
            flash('You are not eligible for this exam due to age criteria.', 'danger')
            return redirect(url_for('register_exam', exam_id=exam_id))
            
        if exam.education_level != education_level:
            flash('You are not eligible for this exam due to education criteria.', 'danger')
            return redirect(url_for('register_exam', exam_id=exam_id))
        
        # Check eligible colleges if available
        eligible_colleges_list = []
        if 'eligible_colleges' in decrypted_exam and decrypted_exam['eligible_colleges'] != 'Information unavailable':
            eligible_colleges_list = [c.strip() for c in decrypted_exam['eligible_colleges'].split(',')]
            
        if eligible_colleges_list and college_name not in eligible_colleges_list:
            flash('Your college is not eligible for this exam.', 'danger')
            return redirect(url_for('register_exam', exam_id=exam_id))

        # Encrypt registration data with student's public key
        encrypted_name = encrypt_data(student.public_key, name)
        encrypted_college = encrypt_data(student.public_key, college_name)
        encrypted_address = encrypt_data(student.public_key, address)
        encrypted_aadhaar = encrypt_data(student.public_key, aadhaar_number)

        # Create registration in database
        registration = ExamRegistration(
            student_id=student_id,
            exam_id=exam_id,
            name=encrypted_name,
            college_name=encrypted_college,
            address=encrypted_address,
            aadhaar_number=encrypted_aadhaar,
            age=age
        )
        
        # Add to database
        db.session.add(registration)
        db.session.flush()  # Get ID without committing
        
        # Store registration data on blockchain
        try:
            # Create JSON data for blockchain
            registration_data = {
                'student_id': student_id,
                'exam_id': exam_id,
                'name_hash': web3.keccak(text=name).hex(),  # Store hash of sensitive data
                'college_hash': web3.keccak(text=college_name).hex(),
                'aadhaar_hash': web3.keccak(text=aadhaar_number).hex(),
                'age': age,
                'timestamp': datetime.now().isoformat(),
                'registration_id': registration.id
            }
            
            # Convert to JSON
            registration_json = json.dumps(registration_data)
            
            # Send transaction to blockchain
            nonce = web3.eth.get_transaction_count(sender_address)
            tx = exam_contract.functions.registerStudentForExam(
                student_id,
                exam_id,
                registration_json
            ).build_transaction({
                'nonce': nonce,
                'gas': 3000000,
                'gasPrice': web3.to_wei('20', 'gwei'),
                'from': sender_address
            })
            
            signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            web3.eth.wait_for_transaction_receipt(tx_hash)
            
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
            return redirect(url_for('student_dashboard'))
        
        # Complete the transaction
        db.session.commit()
        flash('You have successfully registered for the exam!', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template('register_exam.html', 
                          exam=exam, 
                          decrypted_exam=decrypted_exam)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/exam_schedules')
def exam_schedules():
    if 'role' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
        
    exams = Exam.query.all()
    return render_template('exam_schedules.html', exams=exams)

# Helper function to decrypt exam data for displaying in frontend
def get_decrypted_exam_data(exam):
    """Helper function to get decrypted exam data for display"""
    decrypted_data = {
        'id': exam.id,
        'name': exam.name,
        'age_min': exam.age_min,
        'age_max': exam.age_max,
        'education_level': exam.education_level,
        'date': exam.date,
        'start_time': exam.start_time,
        'time_limit': exam.time_limit,
        'results_published': exam.results_published,
        'description': 'Description unavailable',
        'eligible_colleges': 'Information unavailable'
    }
    
    # Get the admin/creator who created this exam
    admin_id = exam.creator_id
    if not admin_id:
        # Try to get from blockchain if not stored in database
        try:
            exam_data_json = exam_contract.functions.getExamData(exam.id).call()
            exam_data = json.loads(exam_data_json)
            admin_id = exam_data.get('admin_id')
        except Exception as e:
            print(f"Error retrieving exam data from blockchain: {str(e)}")
    
    # If we have admin ID, get private key and decrypt
    if admin_id:
        admin_private_key, _ = get_private_key_from_blockchain(admin_id)
        if admin_private_key:
            try:
                if exam.description:
                    decrypted_data['description'] = decrypt_data(admin_private_key, exam.description)
                if exam.eligible_colleges:
                    decrypted_data['eligible_colleges'] = decrypt_data(admin_private_key, exam.eligible_colleges)
            except Exception as e:
                print(f"Error decrypting exam data: {str(e)}")
    
    return decrypted_data

# Also update the student_dashboard route to use the decryption helper
# @app.route('/student_dashboard')
# def student_dashboard():
#     if 'role' in session and session['role'] == 'student':
#         student_id = session['user_id']
#         exams = Exam.query.all()
#         registrations = ExamRegistration.query.filter_by(student_id=student_id).all()

#         # Fetch registered and attempted exams
#         registered_exam_ids = {reg.exam_id for reg in registrations}
#         attempted_exam_ids = {
#             result.exam_id for result in Result.query.filter_by(student_id=student_id).all()
#         }

#         # Precompute exam statuses and decrypt descriptions
#         current_time = datetime.now()
#         exam_statuses = {}
#         decrypted_exams = []
        
#         for exam in exams:
#             # Handle exam status
#             if exam.date is None or exam.start_time is None:
#                 exam_statuses[exam.id] = 'invalid_time'
#             else:
#                 exam_start = datetime.combine(exam.date, exam.start_time)
#                 if exam.id in attempted_exam_ids:
#                     exam_statuses[exam.id] = 'submitted'
#                 elif current_time < exam_start:
#                     exam_statuses[exam.id] = 'not_started'
#                 else:
#                     exam_statuses[exam.id] = 'available'
            
#             # Get decrypted exam data
#             decrypted_data = get_decrypted_exam_data(exam)
#             decrypted_exams.append(decrypted_data)

#         return render_template(
#             'student_dashboard.html',
#             exams=exams,
#             decrypted_exams=decrypted_exams,
#             registered_exam_ids=registered_exam_ids,
#             exam_statuses=exam_statuses
#         )
#     flash('Access unauthorized. Please log in as a student.', 'danger')
#     return redirect(url_for('login'))

# @app.route('/register_exam/<int:exam_id>', methods=['GET', 'POST'])
# def register_exam(exam_id):
#     if 'role' not in session or session['role'] != 'student':
#         flash('Unauthorized access!', 'danger')
#         return redirect(url_for('login'))

#     exam = Exam.query.get_or_404(exam_id)
#     student_id = session['user_id']
#     student = User.query.get(student_id)
    
#     # Get decrypted exam data
#     decrypted_exam = get_decrypted_exam_data(exam)
    
#     if request.method == 'POST':
#         name = request.form['name']
#         college_name = request.form['college_name']
#         address = request.form['address']
#         aadhaar_number = request.form['aadhaar_number']
#         age = int(request.form['age'])
#         education_level = request.form['education_level']

#         # Check eligibility
#         if age < exam.age_min or age > exam.age_max:
#             flash('You are not eligible for this exam due to age criteria.', 'danger')
#             return redirect(url_for('register_exam', exam_id=exam_id))
            
#         if exam.education_level != education_level:
#             flash('You are not eligible for this exam due to education criteria.', 'danger')
#             return redirect(url_for('register_exam', exam_id=exam_id))
        
#         # Check eligible colleges if available
#         eligible_colleges_list = []
#         if 'eligible_colleges' in decrypted_exam and decrypted_exam['eligible_colleges'] != 'Information unavailable':
#             eligible_colleges_list = [c.strip() for c in decrypted_exam['eligible_colleges'].split(',')]
            
#         if eligible_colleges_list and college_name not in eligible_colleges_list:
#             flash('Your college is not eligible for this exam.', 'danger')
#             return redirect(url_for('register_exam', exam_id=exam_id))

#         # Encrypt registration data with student's public key
#         encrypted_name = encrypt_data(student.public_key, name)
#         encrypted_college = encrypt_data(student.public_key, college_name)
#         encrypted_address = encrypt_data(student.public_key, address)
#         encrypted_aadhaar = encrypt_data(student.public_key, aadhaar_number)

#         # Create registration in database
#         registration = ExamRegistration(
#             student_id=student_id,
#             exam_id=exam_id,
#             name=encrypted_name,
#             college_name=encrypted_college,
#             address=encrypted_address,
#             aadhaar_number=encrypted_aadhaar,
#             age=age
#         )
        
#         # Add to database
#         db.session.add(registration)
#         db.session.flush()  # Get ID without committing
        
#         # Store registration data on blockchain
#         try:
#             # Create JSON data for blockchain
#             registration_data = {
#                 'student_id': student_id,
#                 'exam_id': exam_id,
#                 'name_hash': web3.keccak(text=name).hex(),  # Store hash of sensitive data
#                 'college_hash': web3.keccak(text=college_name).hex(),
#                 'aadhaar_hash': web3.keccak(text=aadhaar_number).hex(),
#                 'age': age,
#                 'timestamp': datetime.now().isoformat(),
#                 'registration_id': registration.id
#             }
            
#             # Convert to JSON
#             registration_json = json.dumps(registration_data)
            
#             # Send transaction to blockchain
#             nonce = web3.eth.get_transaction_count(sender_address)
#             tx = exam_contract.functions.registerStudentForExam(
#                 student_id,
#                 exam_id,
#                 registration_json
#             ).build_transaction({
#                 'nonce': nonce,
#                 'gas': 3000000,
#                 'gasPrice': web3.to_wei('20', 'gwei'),
#                 'from': sender_address
#             })
            
#             signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
#             tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
#             web3.eth.wait_for_transaction_receipt(tx_hash)
            
#         except Exception as e:
#             db.session.rollback()
#             flash(f'Registration failed: {str(e)}', 'danger')
#             return redirect(url_for('student_dashboard'))
        
#         # Complete the transaction
#         db.session.commit()
#         flash('You have successfully registered for the exam!', 'success')
#         return redirect(url_for('student_dashboard'))

#     return render_template('register_exam.html', 
#                           exam=exam, 
#                           decrypted_exam=decrypted_exam)

# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     session.pop('role', None)
#     flash('You have been logged out.', 'info')
#     return redirect(url_for('home'))

# @app.route('/exam_schedules')
# def exam_schedules():
#     if 'role' not in session or session['role'] != 'admin':
#         flash('Unauthorized access!', 'danger')
#         return redirect(url_for('login'))
        
    exams = Exam.query.all()
    return render_template('exam_schedules.html', exams=exams)
# Run the application
if __name__ == '__main__':
    app.run(debug=True)

