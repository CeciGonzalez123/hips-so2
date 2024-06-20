import subprocess
import psycopg2

# Conexión a la base de datos
try:
    conn = psycopg2.connect(
        dbname="intrusion_detection",
            user="intrusion_user",
            password="password",
            host="localhost"
    )
    print("Connected to the database.")
except psycopg2.Error as e:
    print(f"Error connecting to the database: {e}")
    exit(1)

# Lista de procesos críticos que no deben ser terminados
critical_processes = ['init', 'systemd', 'gnome-shell', 'psql', 'bash', 'python', 'your_script_name.py']

# Función para obtener los procesos con alto uso de memoria
def get_high_memory_processes(threshold=5.0):
    result = subprocess.run(['ps', 'aux', '--sort=-%mem'], capture_output=True, text=True)
    processes = result.stdout.splitlines()
    high_memory_processes = []

    for process in processes[1:]:
        columns = process.split()
        if len(columns) > 10:
            memory_usage = float(columns[3])
            if memory_usage > threshold:
                pid = columns[1]
                user = columns[0]
                command = columns[10]
                if any(crit_proc in command for crit_proc in critical_processes):
                    continue
                runtime = columns[9]
                full_command = ' '.join(columns[10:])
                high_memory_processes.append((pid, user, memory_usage, runtime, full_command))

    return high_memory_processes

# Función para matar un proceso
def kill_process(pid):
    try:
        subprocess.run(['kill', '-9', pid], check=True)
        print(f"Process {pid} killed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to kill process {pid}: {e}")

# Función para registrar procesos terminados en la base de datos
def log_terminated_process(conn, pid, user, memory, runtime, command):
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO terminated_processes (pid, "user", memory, runtime, command)
            VALUES (%s, %s, %s, %s, %s)
        """, (pid, user, memory, runtime, command))
        conn.commit()
        cur.close()
        print(f"Logged terminated process {pid} to the database.")
    except psycopg2.Error as e:
        print(f"Error logging process {pid} to the database: {e}")

# Verificar el uso de memoria
threshold = 5.0  # Umbral de memoria en porcentaje
high_memory_processes = get_high_memory_processes(threshold)

if high_memory_processes:
    for pid, user, memory, runtime, command in high_memory_processes:
        print(f"High memory usage by process {pid} (User: {user}, Memory: {memory}%, Runtime: {runtime}, Command: {command})")
        # Matar el proceso si excede el umbral
        kill_process(pid)
        # Registrar el proceso terminado en la base de datos
        log_terminated_process(conn, pid, user, memory, runtime, command)

# Cerrar la conexión a la base de datos
conn.close()
print("Database connection closed.")
print("Done.")


