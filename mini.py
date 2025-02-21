from flask import Flask, request, jsonify, render_template
import os
import re
import base64
import secrets

app = Flask(__name__)

@app.route('/')
def index():
    try:
        return render_template('Malware-1.html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/About.html')
def about():
    try:
        return render_template('About.html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500    
@app.route('/Login.html')
def login():
    try:
        return render_template('Login.html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500   
         
@app.route('/signup.html')
def signup():
    try:
        return render_template('signup.html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500    
    
@app.route('/forgot.html')
def forgot():
    try:
        return render_template('forgot.html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500 
    
@app.route('/Whatsnew.html')
def Whatsnew():
    try:
        return render_template('Whatsnew.html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500               


def check_phishing(url):
    return "phishing" not in url

def scan_folder(folder_path):
    safe_files = []
    virus_files = []

    # Ensure folder_path is safe
    if not os.path.isdir(folder_path):
        return None, None

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)

            # Limit file types scanned for security
            if file.endswith(('.exe', '.scr', '.bat', '.cmd', '.js')):
                virus_files.append({'name': file_path})
            else:
                safe_files.append({'name': file_path})

    return safe_files, virus_files

def is_malicious(url):
    malicious_urls = [
        "malicious.com",
        "phishing.com",
        "example.com/bad"
    ]
    for bad_url in malicious_urls:
        if bad_url in url:
            return True
    return False

def scan_url(url):
    suspicious_patterns = [
        r'http[s]?://.*\.(exe|zip|tar|gz|js)',
        r'http[s]?://.*\.php',
        r'http[s]?://.*(login|admin|root|shell)',
        r'extension:\s*.*\.html',
        r'https://toolsxsocial\.in/.*/.*',
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return [], [{'name': url, 'reason': 'Suspicious URL detected'}]

    if is_malicious(url) or not check_phishing(url):
        return [], [{'name': url, 'reason': 'Potential phishing site detected'}]

    return [{'name': url}], []  # Safe URL

def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = base64.b64encode(data)
    
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)

    # Generate a random key for decryption
    key = secrets.token_hex(16)  # Generate a 32-character hex key
    key_file_path = file_path + '.key'
    
    with open(key_file_path, 'w') as key_file:
        key_file.write(key)
    
    os.remove(file_path)  # Remove the original file after encryption
    return encrypted_file_path, key_file_path

def decrypt_file(file_path):
    if not file_path.endswith('.enc'):
        raise ValueError("File must have a .enc extension for decryption.")

    key_file_path = file_path[:-4] + '.key'  # Corresponding key file path

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = base64.b64decode(encrypted_data)
    decrypted_file_path = file_path[:-4]  # Remove '.enc'
    
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    os.remove(file_path)  # Remove the encrypted file after decryption
    os.remove(key_file_path)  # Remove the key file after decryption
    return decrypted_file_path

@app.route('/perform_action', methods=['POST'])
def perform_action():
    data = request.json
    action = data.get('action')
    input_data = data.get('input')

    # Input validation for action and input_data
    if not action or not input_data:
        return jsonify({'error': 'Action and input data are required'}), 400

    if action == 'scan_folder':
        safe_files, virus_files = scan_folder(input_data)
    elif action == 'scan_url':
        safe_files, virus_files = scan_url(input_data)
    else:
        return jsonify({'error': 'Invalid action'}), 400

    return jsonify({
        'safe_files': safe_files,
        'virus_files': virus_files
    })

@app.route('/perform_encrypt_decrypt', methods=['POST'])
def perform_encrypt_decrypt():
    data = request.json
    action = data.get('action')
    input_text = data.get('input')

    # Input validation for action and input_text
    if not action or not input_text:
        return jsonify({'error': 'Action and input text are required'}), 400

    if os.path.isfile(input_text):
        if action == 'encrypt':
            encrypted_path, key_path = encrypt_file(input_text)
            return jsonify({'message': f'File encrypted: {encrypted_path}', 'key': key_path})
        elif action == 'decrypt':
            try:
                decrypted_path = decrypt_file(input_text)
                return jsonify({'message': f'File decrypted: {decrypted_path}'})
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
    else:
        return jsonify({'error': 'Input is not a valid file'}), 400

    return jsonify({'error': 'Invalid action'}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
