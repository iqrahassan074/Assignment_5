import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key(password: str) -> bytes:

    hash_digest = hashlib.sha256(password.encode()).digest()
    key = base64.urlsafe_b64encode(hash_digest)
    return key


st.title("🔐 Secure Data Encryption System")

option = st.radio("Select Operation", ("Encrypt", "Decrypt"))

text = st.text_area("Enter your text here")
password = st.text_input("Enter password", type="password")

if st.button(option):
    if not text or not password:
        st.warning("Please enter both text and password.")
    else:
        try:
            key = generate_key(password)
            f = Fernet(key)

            if option == "Encrypt":
                encrypted_text = f.encrypt(text.encode()).decode()
                st.success("Encrypted Text:")
                st.code(encrypted_text)
            else:
                decrypted_text = f.decrypt(text.encode()).decode()
                st.success("Decrypted Text:")
                st.code(decrypted_text)

        except Exception as e:
            st.error(f"Error: {e}")







