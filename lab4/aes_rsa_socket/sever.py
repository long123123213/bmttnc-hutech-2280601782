from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import hashlib

# Initialize server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

# Generate RSA key pair
server_key = RSA.generate(2048)

# list of connected clients
clients = []

# Function to encrypt message
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Function to decrypt message
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# Function to handle client connection
def handle_client(client_socket, client_address):
    print(f"Connected with {client_address}")

    # Send server's public key to client
    client_socket.send(server_key.publickey().export_key(format="PEM"))

    # Receive client's public key
    client_key = RSA.import_key(client_socket.recv(2048)) # Sửa lỗi: Đã nhận client_key

    # Generate AES key for message encryption
    aes_key = get_random_bytes(16)

    # Encrypt the AES key using the client's public key
    cipher_rsa = PKCS1_OAEP.new(client_key) # Sửa lỗi: Thay client_received_key bằng client_key
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)

    # Add client to the list
    clients.append((client_socket, aes_key))

    while True:
        try:
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message: # Xử lý trường hợp client ngắt kết nối
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"Received from {client_address}: {decrypted_message}")

            if decrypted_message == "exit": # Đặt điều kiện thoát trong vòng lặp
                break

            # Send received message to all other clients
            for client, key_ in clients:
                if client != client_socket:
                    try:
                        encrypted = encrypt_message(key_, decrypted_message)
                        client.send(encrypted)
                    except Exception as e:
                        print(f"Error sending to a client: {e}")
                        # Xử lý client bị lỗi (có thể loại bỏ khỏi danh sách clients)

        except Exception as e:
            print(f"Error in handle_client for {client_address}: {e}")
            break # Thoát khỏi vòng lặp nếu có lỗi

    clients.remove((client_socket, aes_key))
    client_socket.close()
    print(f"Connection with {client_address} closed")

# Accept and handle client connections
while True:
    try:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()
    except Exception as e:
        print(f"Error accepting new connection: {e}")
        break # Thoát khỏi vòng lặp chính nếu có lỗi nghiêm trọng