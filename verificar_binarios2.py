import subprocess
import psycopg2
import hashlib

def generate_file_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_contents = file.read()
        file_hash = hashlib.sha256(file_contents).hexdigest()
        return file_hash
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return None

def read_file_contents(file_path):
    try:
        with open(file_path, 'r') as file:
            file_contents = file.read()
        return file_contents
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return None

def parse_stat_output(stat_output):
    stat_dict = {}
    lines = stat_output.splitlines()
    for line in lines:
        parts = line.split(": ", 1)
        if len(parts) == 2:
            key, value = parts
            value = value.split()[0]  # Tomar solo la primera parte del valor
            stat_dict[key.strip()] = value.strip()
    return stat_dict

def check_system_files(cursor):
    try:
        # Verificar /etc/passwd
        passwd_stat = subprocess.check_output("stat /etc/passwd", shell=True).decode().strip()
        store_system_file_details(cursor, "/etc/passwd", parse_stat_output(passwd_stat))
        store_file_contents(cursor, "/etc/passwd", read_file_contents("/etc/passwd"))
        compare_and_store_file_hash(cursor, "/etc/passwd", generate_file_hash("/etc/passwd"))

        # Verificar /etc/shadow
        shadow_stat = subprocess.check_output("stat /etc/shadow", shell=True).decode().strip()
        store_system_file_details(cursor, "/etc/shadow", parse_stat_output(shadow_stat))
        store_file_contents(cursor, "/etc/shadow", read_file_contents("/etc/shadow"))
        compare_and_store_file_hash(cursor, "/etc/shadow", generate_file_hash("/etc/shadow"))

    except subprocess.CalledProcessError as e:
        print(f"Error checking files: {e}")

def store_system_file_details(cursor, file_path, stat_output):
    try:
        cursor.execute("""
            INSERT INTO system_files (file_path, file_size, file_owner, last_access, last_modify, last_change)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (file_path) DO NOTHING;
            """,
            (file_path,
             int(stat_output.get('Size', 0)),
             stat_output.get('Uid', ''),
             stat_output.get('Access', ''),
             stat_output.get('Modify', ''),
             stat_output.get('Change', ''))
        )
        print(f"Stored system file details for {file_path}")

    except psycopg2.Error as e:
        print(f"Error storing system file details: {e}")

def store_file_contents(cursor, file_path, file_contents):
    try:
        cursor.execute("SELECT 1 FROM file_contents WHERE file_path = %s", (file_path,))
        if cursor.fetchone():
            cursor.execute("""
                UPDATE file_contents
                SET file_contents = %s
                WHERE file_path = %s
                """, (file_contents, file_path)
            )
        else:
            cursor.execute("""
                INSERT INTO file_contents (file_path, file_contents)
                VALUES (%s, %s)
                """, (file_path, file_contents)
            )
        print(f"Stored file contents for {file_path}")

    except psycopg2.Error as e:
        print(f"Error storing file contents: {e}")

def compare_and_store_file_hash(cursor, file_path, file_hash):
    try:
        cursor.execute("SELECT file_hash FROM file_hashes WHERE file_path = %s", (file_path,))
        result = cursor.fetchone()
        if result:
            stored_hash = result[0]
            if stored_hash != file_hash:
                print(f"Hash mismatch for {file_path}. File may have been modified.")
            else:
                print(f"Hash for {file_path} matches the stored hash.")
            cursor.execute("""
                UPDATE file_hashes
                SET file_hash = %s
                WHERE file_path = %s
                """, (file_hash, file_path)
            )
        else:
            cursor.execute("""
                INSERT INTO file_hashes (file_path, file_hash)
                VALUES (%s, %s)
                """, (file_path, file_hash)
            )
            print(f"Stored file hash for {file_path}")

    except psycopg2.Error as e:
        print(f"Error storing file hash: {e}")

def get_logged_in_users():
    output = subprocess.check_output("who", shell=True).decode().strip().split("\n")
    users = []
    for line in output:
        parts = line.split()
        if len(parts) >= 5:
            user = parts[0]
            ip = parts[-1]
            if ip.startswith("(") and ip.endswith(")"):
                ip = ip[1:-1]
            if ip in ["local", ":0", ":1", ":2", ":3"]:
                ip = "local"
            users.append((user, ip))
    return users

def store_logged_in_users(cursor, users):
    for user, ip in users:
        cursor.execute(
            "INSERT INTO logged_in_users (username, ip_address) VALUES (%s, %s) ON CONFLICT (username, ip_address) DO NOTHING",
            (user, ip)
        )
        print(f"Logged in user: {user}, IP: {ip}")

def main():
    print("Connecting to the database...")
    try:
        conn = psycopg2.connect(
            dbname="intrusion_detection",
            user="intrusion_user",
            password="password",
            host="localhost"
        )
    except psycopg2.Error as e:
        print(f"Unable to connect to the database: {e}")
        return

    try:
        cur = conn.cursor()
        print("Connected to the database.")

        # Verificar y almacenar usuarios conectados
        print("Checking logged in users...")
        logged_in_users = get_logged_in_users()
        store_logged_in_users(cur, logged_in_users)

        # Verificar archivos /etc/passwd y /etc/shadow
        print("Checking system files...")
        check_system_files(cur)

        # Confirmar y cerrar la conexión
        conn.commit()
        print("Committing changes...")

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        conn.rollback()

    finally:
        cur.close()
        conn.close()
        print("Database connection closed.")
        print("Done.")

if __name__ == "__main__":
    main()

