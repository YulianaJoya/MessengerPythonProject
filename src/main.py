import argparse
import os
from cryptography.hazmat.primitives import serialization
from crypto_functions import encrypt_message, decrypt_message, generate_mac, verify_mac

def main():
    parser = argparse.ArgumentParser(description="Secure Communication System")

    subparsers = parser.add_subparsers(dest="role")

    # Sender sub-command
    sender_parser = subparsers.add_parser("sender", help="Acts as the sender")
    sender_parser.add_argument("message_file", help="Path to the .txt file containing the message to send")
    sender_parser.add_argument("receiver_public_key", help="Path to the receiver's RSA public key")

    # Receiver sub-command
    receiver_parser = subparsers.add_parser("receiver", help="Acts as the receiver")
    receiver_parser.add_argument("receiver_private_key", help="Path to the receiver's RSA private key")

    args = parser.parse_args()

    if args.role == "sender":
        send_message(args.message_file, args.receiver_public_key)
    elif args.role == "receiver":
        receive_message(args.receiver_private_key)

def send_message(message_file, receiver_public_key):
    """Functionality for sending a message."""

    # Load the message from the specified file
    with open(message_file, "r") as f:
        message = f.read()

    # Encrypt the message, generate MAC, etc.
    iv, encrypted_message, encrypted_aes_key = encrypt_message(message, receiver_public_key)
    mac_key = os.urandom(32)
    message_mac = generate_mac(encrypted_message, mac_key)

    # Save everything to a file
    with open("Transmitted_Data", "wb") as f:
        f.write(iv + encrypted_message + encrypted_aes_key + message_mac)

    print("Message sent.")

def receive_message(receiver_private_key):
    """Functionality for receiving and processing a message."""

    # Load receiver's RSA private key
    with open(receiver_private_key, "rb") as key_file:
        receiver_private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Read the transmitted data
    with open("Transmitted_Data", "rb") as f:
        data = f.read()

    # Split the data into parts
    iv = data[:16]
    encrypted_message = data[16:-96]
    encrypted_aes_key = data[-96:-64]
    received_mac = data[-64:]

    # Verify the MAC
    mac_key = os.urandom(32) # Temporary placeholder, ensure matching verification elsewhere
    if verify_mac(encrypted_message, mac_key, received_mac):
        print("MAC verified. Proceeding to decrypt the message...")
    else:
        print("MAC verification failed.")
        return

    decrypted_message = decrypt_message(encrypted_message, iv, encrypted_aes_key, receiver_private_key)

    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()

