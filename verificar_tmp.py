import os
import psycopg2
from datetime import datetime

def check_tmp_directory():
    suspicious_files = []
    quarantine_dir = '/tmp/quarantine'

    # Verificar el directorio /tmp en busca de archivos sospechosos
    for filename in os.listdir('/tmp'):
        if filename.endswith('.sh'):
            suspicious_files.append(filename)
            # Mover el archivo sospechoso a la carpeta de cuarentena
            os.rename(os.path.join('/tmp', filename), os.path.join(quarantine_dir, filename))

    return suspicious_files

def store_results_in_db(files_checked):
    try:
        conn = psycopg2.connect(
            dbname="intrusion_detection",
            user="intrusion_user",
            password="password",
            host="localhost"
        )
        cur = conn.cursor()

        # Insertar resultados en la base de datos
        for file_checked in files_checked:
            cur.execute(
                "INSERT INTO tmp_directory_check (file_name, result, check_time) VALUES (%s, %s, %s)",
                (file_checked, "Moved to quarantine", datetime.now())
            )
            conn.commit()

        print(f"Results stored in the database: {files_checked}")

    except psycopg2.Error as e:
        print(f"Error storing results in the database: {e}")

    finally:
        if conn:
            conn.close()

def main():
    print("Connecting to the database...")
    check_time = datetime.now()
    suspicious_files = check_tmp_directory()
    store_results_in_db(suspicious_files)
    print("Done.")

if __name__ == "__main__":
    main()

