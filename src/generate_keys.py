from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    # Generate the RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Save the private key
    with open("keys/receiver_private_key.pem", "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key
    public_key = private_key.public_key()
    with open("keys/receiver_public_key.pem", "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Run the function to generate the keys
generate_rsa_keys()
