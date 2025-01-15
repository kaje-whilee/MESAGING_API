# MESAGING_API
python 
Fitstly it have a createuser.py file that creates a user
Or a signup endpoint
Logic:
Generates a unique user ID.
Hashes passwords using bcrypt for secure storage.
Creates asymmetric key pairs for users (public/private keys).
Stores user details (email, hashed password, keys) in the MongoDB database.
And secondly we have a logi.py route which logs in the user
Logic:
Verifies email and hashed password during login.
Issues a JWT-based access token for authenticated sessions.
Stores tokens as HTTP-only cookies for added security.
Purpose: Authenticates users and initiates secure sessions.
Third one is send message route which sends message from one user to other
Logic:
Derives a shared secret between the sender and recipient using ECDH.
Encrypts the message using the shared secret.
Generates and attaches a MAC for integrity verification.
Stores encrypted messages in the database.
It stores encrypted message in db (BASE64 encrypted)
4th route is receive message route .. which receives messages sent by users
Logic:
Fetches encrypted messages from the database.
Derives the shared secret using the recipient's private key and sender's public key.
Decrypts the message and verifies its integrity using the MAC.
