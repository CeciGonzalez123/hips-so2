import subprocess
import psycopg2
import os

# Función para verificar la presencia de sniffers y el modo promiscuo
def check_for_sniffers_and_promiscuous(cursor):
    sniffers = ["tcpdump", "ethereal", "wireshark", "dsniff"]
    try:
        output = subprocess.check_output("ps aux", shell=True).decode()
    except subprocess.CalledProcessError as e:
        print(f"Error executing ps aux: {e}")
        store_result(cursor, "Sniffer Check", f"Error executing ps aux: {e}")
        return

    sniffer_found = False

    for sniffer in sniffers:
        if sniffer in output:
            result = f"Warning: {sniffer} is running."
            print(result)
            store_result(cursor, "Sniffer Check", result)
            sniffer_found = True
            # Optional: Kill the process
            try:
                pids = subprocess.check_output(f"pgrep {sniffer}", shell=True).decode().strip().split()
                for pid in pids:
                    subprocess.call(['sudo', 'kill', pid])
                    print(f"Process {sniffer} with PID {pid} has been killed.")
            except subprocess.CalledProcessError as e:
                print(f"Error killing {sniffer} processes: {e}")
                store_result(cursor, "Sniffer Check", f"Error killing {sniffer} processes: {e}")

    if not sniffer_found:
        result = "No sniffers found."
        print(result)
        store_result(cursor, "Sniffer Check", result)

    # Check for promiscuous mode
    try:
        output = subprocess.check_output("ip link", shell=True).decode()
        if "PROMISC" in output:
            result = "Warning: Interface is in promiscuous mode."
        else:
            result = "No interfaces in promiscuous mode detected."
        print(result)
        store_result(cursor, "Promiscuous Mode Check", result)
    except subprocess.CalledProcessError as e:
        print(f"Error executing ip link: {e}")
        store_result(cursor, "Promiscuous Mode Check", f"Error executing ip link: {e}")

def store_result(cursor, check_name, result):
    try:
        cursor.execute(
            "INSERT INTO results (check_name, result) VALUES (%s, %s)",
            (check_name, result)
        )
        print(f"Stored result: {check_name} - {result}")
    except psycopg2.Error as e:
        print(f"Database error: {e}")

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

        # Llamada a la función de verificación de sniffers y modo promiscuo
        check_for_sniffers_and_promiscuous(cur)

        # Confirmar y cerrar la conexión
        print("Committing the transaction...")
        conn.commit()
        cur.close()
        conn.close()
        print("Database connection closed.")
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")

if __name__ == "__main__":
    main()

