import subprocess
import psycopg2

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

    cur = conn.cursor()
    print("Connected to the database.")

    # Verificar y almacenar usuarios conectados
    print("Checking logged in users...")
    logged_in_users = get_logged_in_users()
    store_logged_in_users(cur, logged_in_users)

    # Confirmar y cerrar la conexión
    conn.commit()
    print("Committing changes...")
    cur.close()
    conn.close()
    print("Database connection closed.")
    print("Done.")

if __name__ == "__main__":
    main()



