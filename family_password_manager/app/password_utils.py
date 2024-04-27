from cryptography.fernet import Fernet


# Function to generate a key
def generate_key():
    return Fernet.generate_key()

# Function to encrypt the password
def encrypt_password(password):
    key = generate_key()
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password.decode(), key.decode()

# Function to decrypt the password
def decrypt_password(encrypted_password, encryption_key):
    try:
        f = Fernet(encryption_key.encode())
        decrypted_password = f.decrypt(encrypted_password.encode())
        return decrypted_password.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

if __name__ == "__main__":
    password = "my_super_secret_password"
    encrypted_password, key = encrypt_password(password)
    print("Encrypted:", encrypted_password)
    print("Key:", key)

    decrypted_password = decrypt_password(encrypted_password, key)
    print("Decrypted:", decrypted_password)
