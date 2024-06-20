import re
from collections import defaultdict
import subprocess
import psycopg2
import os

# Expresiones regulares para analizar las líneas de los logs
secure_log_pattern = re.compile(
    r'(?P<datetime>[A-Za-z]+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(sshd|saslauthd)\[\d+\]:\s+(Failed password for|authentication failure).*?from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

message_log_pattern = re.compile(
    r'(?P<datetime>[A-Za-z]+\s+\d+ \d+:\d+:\d+)\s+\S+\s+(sshd|saslauthd)\[\d+\]:\s+(Failed password for|authentication failure).*?from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

access_log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^\s]+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+)'
)

maillog_pattern = re.compile(
    r'(?P<datetime>[A-Za-z]+\s+\d+ \d+:\d+:\d+)\s+\S+\s+sendmail\[\d+\]:\s+AUTH=server,\s+relay=\S+\s+\[(?P<ip>\d+\.\d+\.\d+\.\d+)\],\s+authid=(?P<user>\S+),'
)

def parse_log_line(line, pattern):
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return None

def process_log(file_path, pattern):
    connections = defaultdict(int)
    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                log_entry = parse_log_line(line, pattern)
                if log_entry:
                    key = log_entry.get('ip') or log_entry.get('user')
                    connections[key] += 1
        print(f"Processed {file_path} successfully.")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    return connections

def store_user_connections(cursor, connections, source):
    for key, count in connections.items():
        cursor.execute(
            "INSERT INTO user_connections (ip, connection_count, source) VALUES (%s, %s, %s) ON CONFLICT (ip, source) DO UPDATE SET connection_count = user_connections.connection_count + EXCLUDED.connection_count",
            (key, count, source)
        )
        print(f"Inserted/Updated IP/User: {key}, Connection Count: {count}, Source: {source}")

def block_ip(ip):
    print(f"Blocking IP: {ip}")
    os.system(f"iptables -A INPUT -s {ip} -j DROP")

def main():
    # Conectar a la base de datos
    print("Connecting to the database...")
    try:
        conn = psycopg2.connect(
            dbname="intrusion_detection",
            user="intrusion_user",
            password="password",
            host="localhost"
        )
        cur = conn.cursor()
        print("Connected to the database.")
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        return

    # Directorio de logs
    logs_dir = '/var/log'

    # Procesar los logs y almacenar los resultados en la base de datos
    print("Processing secure...")
    secure_connections = process_log(f'{logs_dir}/secure', secure_log_pattern)
    print("Processing messages...")
    message_connections = process_log(f'{logs_dir}/messages', message_log_pattern)
    print("Processing access_log...")
    access_connections = process_log(f'{logs_dir}/httpd/access_log', access_log_pattern)
    print("Processing maillog...")
    mail_connections = process_log(f'{logs_dir}/maillog', maillog_pattern)

    print("Storing results in the database...")
    try:
        store_user_connections(cur, secure_connections, "ssh")
        store_user_connections(cur, message_connections, "smtp")
        store_user_connections(cur, access_connections, "web")
        store_user_connections(cur, mail_connections, "mail")
    except psycopg2.Error as e:
        print(f"Error storing results in the database: {e}")
        return

    # Verificar y tomar acciones
    try:
        for ip in secure_connections:
            if secure_connections[ip] > 50:  # Umbral de ejemplo
                block_ip(ip)

        for ip in message_connections:
            if message_connections[ip] > 50:  # Umbral de ejemplo
                block_ip(ip)

        for ip in access_connections:
            if access_connections[ip] > 100:  # Umbral de ejemplo
                block_ip(ip)

        for user in mail_connections:
            if mail_connections[user] > 50:  # Umbral de ejemplo
                print(f"Take action on user: {user}")
    except Exception as e:
        print(f"Error taking action: {e}")

    # Confirmar y cerrar la conexión
    print("Committing the transaction...")
    try:
        conn.commit()
    except psycopg2.Error as e:
        print(f"Error committing transaction: {e}")
    cur.close()
    conn.close()
    print("Database connection closed.")

if __name__ == "__main__":
    main()





