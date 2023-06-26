import hashlib
import os
from flask import Flask, render_template, current_app, request, redirect, url_for, g
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
from sqlite3 import Error
import time
import datetime
from time import ctime, sleep
import threading

app = Flask(__name__)


def create_connection():
    conn = None
    try:
        if not os.path.exists("logs.db"):
            conn = sqlite3.connect('logs.db')
        else:
            conn = sqlite3.connect('logs.db')
        return conn
    except Error as e:
        print(e)
    return conn


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", "wb") as f:
        f.write(pem)


def save_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(pem)


def load_private_key():
    if os.path.isfile("private_key.pem"):
        with open("private_key.pem", "rb") as f:
            pem = f.read()
            return serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    else:
        return None


def load_public_key():
    if os.path.isfile("public_key.pem"):
        with open("public_key.pem", "rb") as f:
            pem = f.read()
            return serialization.load_pem_public_key(pem, backend=default_backend())
    else:
        return None


private_key = load_private_key()
public_key = load_public_key()
if private_key is None or public_key is None:
    private_key, public_key = generate_key_pair()
    save_private_key(private_key)
    save_public_key(public_key)


@app.before_request
def before_request():
    g.private_key = private_key
    g.public_key = public_key


class Block:
    def __init__(self, timestamp, data, previous_hash):
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.current_hash = self.hash_block()
        self.encrypted_data = None
        self.decrypted_data = None

    def encrypt_data(self, public_key):
        data_bytes = self.data.encode()
        encrypted_data = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.encrypted_data = encrypted_data.hex()

    def decrypt_data(self, private_key):
        try:
            encrypted_data = bytes.fromhex(self.encrypted_data)
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.decrypted_data = decrypted_data.decode()
        except Exception as e:
            print(e)

    def hash_block(self):
        input_string = f"{self.timestamp}{self.data}{self.previous_hash}"
        input_bytes = input_string.encode()
        hash_bytes = hashlib.sha256(input_bytes)
        hash_hex = hash_bytes.hexdigest()
        return hash_hex


class Blockchain:
    def __init__(self):
        self.chain = self.load_blocks_from_db()

    def load_blocks_from_db(self):
        conn = create_connection()
        with conn:
            c = conn.cursor()
            try:
                c.execute("SELECT * FROM blocks")
                rows = c.fetchall()

                blocks = []
                for row in rows:
                    timestamp, encrypted_data, previous_hash, current_hash = row
                    new_block = Block(timestamp, "", previous_hash)
                    new_block.encrypted_data = encrypted_data
                    new_block.current_hash = current_hash
                    blocks.append(new_block)

                return blocks
            except sqlite3.OperationalError:
                return []

    def add_block(self, data, public_key):
        timestamp = "Fri Jun 16 01:35:54 2023"
        previous_hash = self.chain[-1].current_hash if self.chain else ""
        new_block = Block(timestamp, data, previous_hash)
        new_block.encrypt_data(public_key)
        self.chain.append(new_block)
        self.save_to_db(new_block)

    def save_to_db(self, block):
        conn = create_connection()
        with conn:
            create_table(conn)
            c = conn.cursor()
            c.execute("INSERT INTO blocks (timestamp, encrypted_data, previous_hash, current_hash) VALUES (?, ?, ?, ?)",
                      (block.timestamp, block.encrypted_data, block.previous_hash, block.current_hash))
            conn.commit()


def create_table(conn):
    try:
        c = conn.cursor()
        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS blocks
            ("timestamp" TEXT PRIMARY KEY, encrypted_data TEXT, previous_hash TEXT, current_hash TEXT)
        '''
        c.execute(create_table_sql)
    except Error as e:
        print(e)


blockchain = Blockchain()

# def generate_block_every_second():
#     scheduled_time_pre = "01:20 AM"
#     scheduled_time_close = "01:35 AM"
#     while True:
#         public_key = load_public_key()
#         if public_key is not None:
#             current_time = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30))).strftime("%a %b %d %H:%M:%S %Y")
#             if current_time == scheduled_time_close:
#                 data = f"Open: {get_today_open(GOOGL)}, High: {get_today_high(GOOGL)}, Close: {get_today_close(symbol)}"
#                 blockchain.add_block(data, public_key)
#         sleep(1)

@app.route("/")
def index():
    private_key = g.private_key

    blocks = []
    for block in blockchain.chain:
        if block.timestamp == 0:
            continue
        if block.decrypted_data is None:
            block.decrypt_data(private_key)

        block_dict = {
            "timestamp": block.timestamp,
            "data": block.decrypted_data,
            "previous_hash": block.previous_hash,
            "current_hash": block.current_hash
        }
        blocks.append(block_dict)

    return render_template("index.html", blocks=blocks)


@app.route("/add_block", methods=["POST"])
def add_block():
    data = request.form.get("data")
    public_key = g.public_key

    blockchain.add_block(data, public_key)

    return redirect(url_for("index"))


if __name__ == "__main__":
    # block_thread = threading.Thread(target=generate_block_every_second)
    # block_thread.daemon = True
    # block_thread.start()
    app.run(debug=True)
