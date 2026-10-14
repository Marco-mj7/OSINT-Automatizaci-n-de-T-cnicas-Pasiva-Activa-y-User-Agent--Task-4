import os
import json
from flask import Flask, request
from datetime import datetime

app = Flask(__name__)
ARCHIVO_LOG = "registro_user_agents.json"

def guardar_en_json(nueva_peticion):
    # 1. Leer los datos existentes si el archivo ya existe y no está vacío
    if os.path.exists(ARCHIVO_LOG) and os.path.getsize(ARCHIVO_LOG) > 0:
        try:
            with open(ARCHIVO_LOG, "r", encoding="utf-8") as f:
                historial = json.load(f)
        except json.JSONDecodeError:
            # Si el archivo está corrupto, empezamos una lista nueva
            historial = []
    else:
        # Si el archivo no existe, creamos una lista vacía
        historial = []

    # 2. Añadir la nueva petición a la lista
    historial.append(nueva_peticion)

    # 3. Guardar la lista actualizada en el archivo JSON
    with open(ARCHIVO_LOG, "w", encoding="utf-8") as f:
        json.dump(historial, f, indent=4, ensure_ascii=False)

@app.route('/')
@app.route('/<path:path>')
def capturar_peticion(path=""):
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_agent = request.headers.get('User-Agent', 'No especificado')
    ip_cliente = request.remote_addr
    
    # Mostrar la información en la consola en tiempo real
    print("\n" + "="*60)
    print(f"[{ahora}] NUEVA PETICIÓN RECIBIDA")
    print(f"Ruta solicitada: /{path}")
    print(f"IP del Cliente:  {ip_cliente}")
    print(f"User-Agent:      \033[94m{user_agent}\033[0m")
    print("="*60)
    
    # Crear el diccionario estructurado para el JSON
    datos_peticion = {
        "fecha_hora": ahora,
        "ruta": f"/{path}",
        "ip_cliente": ip_cliente,
        "user_agent": user_agent,
        "metodo": request.method
    }
    
    # Guardar en el archivo JSON sin sobreescribir el historial anterior
    guardar_en_json(datos_peticion)
    
    return "<h1>Petición recibida correctamente</h1><p>Tu User-Agent ha sido registrado en el archivo JSON del servidor.</p>"

if __name__ == '__main__':
    print("Iniciando el servidor HTTP de captura...")
    print("Puedes acceder en tu navegador a: http://127.0.0.1:5000")
    # Ejecuta el servidor en el puerto 5000
    app.run(host='0.0.0.0', port=5000, debug=True)