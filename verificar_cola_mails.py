import re
from collections import defaultdict
import subprocess
import psycopg2
import os

# Expresiones regulares para analizar las líneas de los logs
mail_log_pattern = re.compile(
    r'(?P<datetime>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sendmail\[\d+\]:\s+AUTH=server,\s+relay=\S+\s+\[(?P<ip>\d+\.\d+\.\d+\.\d+)\],\s+authid=\S+,\s+mech=\S+,\s+bits=\d+'
)

def parse_log_line(line, pattern):
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return None

def process_mail_log(file_path, pattern):
    mail_counts = defaultdict(int)
    with open(file_path, 'r') as log_file:
        for line in log_file:
            log_entry = parse_log_line(line, pattern)
            if log_entry:
                ip = log_entry.get('ip')
                mail_counts[ip] += 1
    return mail_counts

def store_mail_counts(cursor, mail_counts):
    for ip, count in mail_counts.items():
        cursor.execute(
            "INSERT INTO mail_counts (ip, mail_count) VALUES (%s, %s) ON CONFLICT (ip) DO UPDATE SET mail_count = mail_counts.mail_count + EXCLUDED.mail_count",
            (ip, count)
        )
        print(f"Inserted/Updated IP: {ip}, Mail Count: {count}")

def block_ip(ip):
    print(f"Blocking IP: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

def main():
    # Conectar a la base de datos
    print("Connecting to the database...")
    conn = psycopg2.connect(
        dbname="intrusion_detection",
        user="intrusion_user",
        password="password",
        host="localhost"
    )
    cur = conn.cursor()
    print("Connected to the database.")

    logs_dir = '/var/log'

    # Procesar el archivo maillog y almacenar los resultados en la base de datos
    print("Processing maillog...")
    mail_counts = process_mail_log(f'{logs_dir}/maillog', mail_log_pattern)

    print("Storing mail counts in the database...")
    store_mail_counts(cur, mail_counts)

    # Verificar y bloquear IPs que generen correos masivos
    for ip, count in mail_counts.items():
        if count > 1:  # Verificar el umbral antes de bloquear
            print(f"IP: {ip}, Mail Count: {count}")
            block_ip(ip)
        else:
            print(f"Ignoring IP: {ip}, Mail Count: {count} (below threshold)")

    # Confirmar y cerrar la conexión
    print("Committing the transaction...")
    conn.commit()
    cur.close()
    conn.close()
    print("Database connection closed.")

if __name__ == "__main__":
    main()






     



 


