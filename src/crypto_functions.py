import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

def encrypt_message(message, receiver_public_key_file):
    """Encrypts a message using AES and encrypts the AES key with RSA."""
    # Generate an AES key
    aes_key = os.urandom(32)

    # Encrypt the message using AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad and encrypt the message
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Load receiver's RSA public key
    with open(receiver_public_key_file, "rb") as key_file:
        receiver_public_key = serialization.load_pem_public_key(key_file.read())

    # Encrypt the AES key with RSA
    encrypted_aes_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return iv, encrypted_message, encrypted_aes_key

def generate_mac(data, mac_key):
    """Generates a MAC for the given data using the provided key."""
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_mac(data, mac_key, received_mac):
    """Verifies the given MAC matches the one generated from the data."""
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(data)

    try:
        h.verify(received_mac)
        return True
    except:
        return False

def decrypt_message(encrypted_message, iv, encrypted_aes_key, receiver_private_key_file):
    """Decrypts a message by first decrypting the AES key using RSA."""
    # Load receiver's RSA private key
    with open(receiver_private_key_file, "rb") as key_file:
        receiver_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Decrypt the AES key
    aes_key = receiver_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the message using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_message_padded = decryptor.update(encrypted_message) + decryptor.finalize()

    # Unpad the message
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_message_padded) + unpadder.finalize()

    return decrypted_message.decode()

