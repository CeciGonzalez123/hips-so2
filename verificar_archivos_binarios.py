import hashlib
import psycopg2

# Función para obtener la contraseña encriptada de un archivo shadow
def obtener_contraseña_encriptada(ruta_shadow, nombre_usuario):
    with open(ruta_shadow, 'r') as f:
        for linea in f:
            campos = linea.strip().split(':')
            if campos[0] == nombre_usuario:
                return campos[1]

# Función para almacenar la contraseña encriptada en la base de datos
def almacenar_contraseña_en_base_de_datos(usuario, contraseña_encriptada):
    try:
        # Conexión a la base de datos
        conexion = psycopg2.connect(
            dbname="hips2",# Nombre de tu base de datos PostgreSQL
            user="postgres", # Nombre de usuario de PostgreSQL
            password="1234",  # Contraseña del usuario de PostgreSQL
            host="localhost"  # Host donde está ejecutándose PostgreSQL
        )
        
        # Crear un cursor para ejecutar consultas SQL
        cursor = conexion.cursor()

        # Verificar si la tabla usuarios ya existe
        cursor.execute("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'usuarios')")
        tabla_existe = cursor.fetchone()[0]

        # Si la tabla no existe, crearla
        if not tabla_existe:
            cursor.execute("CREATE TABLE usuarios (id serial PRIMARY KEY, usuario VARCHAR(30), contraseña TEXT)")

        # Insertar usuario o actualizar contraseña si ya existe
        cursor.execute("INSERT INTO usuarios (usuario, contraseña) VALUES (%s, %s) ON CONFLICT (usuario) DO UPDATE SET contraseña = EXCLUDED.contraseña",
                       (usuario, contraseña_encriptada))

        # Confirmar la transacción
        conexion.commit()

        # Cerrar el cursor y la conexión
        cursor.close()
        conexion.close()

    except (Exception, psycopg2.Error) as error:
        print("Error al trabajar con PostgreSQL:", error)

# Ejemplo de uso
def main():
    # Ejemplo de obtención de contraseña encriptada para un usuario específico
    ruta_shadow = '/etc/shadow'
    nombre_usuario = "usuario_ejemplo"

    contraseña_encriptada = obtener_contraseña_encriptada(ruta_shadow, nombre_usuario)

    # Almacenar la contraseña encriptada en la base de datos PostgreSQL
    almacenar_contraseña_en_base_de_datos(nombre_usuario, contraseña_encriptada)

if __name__ == "__main__":
    main()
