# Flask Blockchain

A simple blockchain implementation using Flask, SQLite, and cryptography.

## Features

- Secure encryption and decryption of block data using RSA keys.
- SQLite database for storing the blockchain.
- Web interface for viewing existing blocks and adding new blocks.
- Automatic generation of blocks with encrypted data at scheduled times (commented out in the code).

## Getting Started

1. Clone the repository.
2. Install the required dependencies: `pip install -r requirements.txt`
3. Run the Flask application: `python app.py`
4. Access the web interface at `http://localhost:5000` in your browser.

## Usage

- Visit the homepage to see the existing blocks in the blockchain.
- Use the form to add a new block with encrypted data to the blockchain.
- The blocks are automatically saved to the SQLite database.
- The private and public key files are automatically generated and stored in the project directory.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

