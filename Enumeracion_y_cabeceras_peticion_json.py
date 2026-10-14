import socket
import requests
import sys
import json  # Importamos el módulo nativo para manejo de JSON

# Configuración del objetivo
TARGET_DOMAIN = "twitter.com" 

def numeracion_pasiva_local(domain):
    print(f"\n[+] Iniciando Enumeración Pasiva Local para: {domain}")
    target_ip = None
    
    # Creamos un diccionario para almacenar los resultados de esta fase
    resultados_pasivos = {
        "dominio": domain,
        "ip_resuelta": None,
        "subdominios_encontrados": []
    }
    
    try:
        target_ip = socket.gethostbyname(domain)
        print(f"    [-] IP Resuelta localmente: {target_ip}")
        resultados_pasivos["ip_resuelta"] = target_ip
    except socket.gaierror:
        print(f"    [!] No se pudo resolver '{domain}' por DNS.")
        
        try:
            socket.inet_aton(domain)
            target_ip = domain
            print(f"    [-] Usando el objetivo como IP directa: {target_ip}")
            resultados_pasivos["ip_resuelta"] = target_ip
        except socket.error:
            print("    [!] El objetivo no es una IP válida ni se puede resolver por DNS.")
            return None, resultados_pasivos

    print("    [-] Buscando subdominios de forma local (Diccionario DNS)...")
    subdominios_comunes = ["www", "mail", "dev", "admin", "test", "api", "staging"]
    
    for sub in subdominios_comunes:
        subdominio_completo = f"{sub}.{domain}"
        try:
            sub_ip = socket.gethostbyname(subdominio_completo)
            # Guardamos como objeto legible en el JSON
            resultados_pasivos["subdominios_encontrados"].append({
                "subdominio": subdominio_completo,
                "ip": sub_ip
            })
        except socket.gaierror:
            pass
            
    if resultados_pasivos["subdominios_encontrados"]:
        print(f"    [-] Subdominios locales detectados:")
        for sub_data in resultados_pasivos["subdominios_encontrados"]:
            print(f"        * {sub_data['subdominio']} -> {sub_data['ip']}")
    else:
        print("    [-] No se encontraron subdominios comunes en el entorno local.")
        
    return target_ip, resultados_pasivos

def numeracion_activa(ip):
    print(f"\n[+] Iniciando Enumeración Activa (Escaneo de Puertos) para: {ip}")
    
    # Estructura para guardar los puertos detectados
    resultados_activos = {
        "ip_escaneada": ip,
        "puertos_abiertos": []
    }
    
    puertos_comunes = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080]
    
    for puerto in puertos_comunes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        resultado = s.connect_ex((ip, puerto))
        
        if resultado == 0:
            print(f"    [-] Puerto {puerto}: ABIERTO")
            resultados_activos["puertos_abiertos"].append(puerto)
            
        s.close()
        
    if not resultados_activos["puertos_abiertos"]:
        print("    [!] No se encontraron puertos abiertos comunes.")
        
    return resultados_activos

# Lista de cabeceras de seguridad clave y su descripción
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS (Fuerza conexiones HTTPS seguras)",
    "Content-Security-Policy": "CSP (Previene ataques XSS e inyecciones de datos)",
    "X-Frame-Options": "Previene ataques de Clickjacking",
    "X-Content-Type-Options": "Previene el sniffing del tipo MIME",
    "Referrer-Policy": "Controla cuánta información de referencia se envía",
    "Permissions-Policy": "Restringe el uso de características del navegador (cámara, micro, etc.)"
}

def analizar_cabeceras(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # Estructura para guardar el análisis HTTP
    resultados_cabeceras = {
        "url_analizada": url,
        "detalles_cabeceras": {},
        "resumen": {}
    }

    try:
        print(f"\n[+] Analizando las cabeceras de seguridad para: {url}\n")
        response = requests.get(url, timeout=10)
        headers = response.headers

        print(f"{'Cabecera de Seguridad':<30} | {'Estado':<10} | {'Valor / Descripción'}")
        print("-" * 90)

        cabeceras_encontradas = 0

        for header, descripcion in SECURITY_HEADERS.items():
            valor = next((headers[h] for h in headers if h.lower() == header.lower()), None)

            if valor:
                print(f"\033[92m{header:<30}\033[0m | \033[92mPresente\033[0m   | {valor}")
                cabeceras_encontradas += 1
                resultados_cabeceras["detalles_cabeceras"][header] = {
                    "estado": "Presente",
                    "valor": valor
                }
            else:
                print(f"\033[91m{header:<30}\033[0m | \033[91mFalta\033[0m      | {descripcion}")
                resultados_cabeceras["detalles_cabeceras"][header] = {
                    "estado": "Falta",
                    "descripcion": descripcion
                }

        print("-" * 90)
        print(f"Resultado: Se encontraron {cabeceras_encontradas} de {len(SECURITY_HEADERS)} cabeceras de seguridad recomendadas.")
        
        resultados_cabeceras["resumen"] = {
            "encontradas": cabeceras_encontradas,
            "total_evaluadas": len(SECURITY_HEADERS)
        }

    except requests.exceptions.RequestException as e:
        print(f"[!] Error al conectar con el sitio web: {e}")
        resultados_cabeceras["error"] = str(e)

    return resultados_cabeceras

# Flujo de ejecución principal unificado
if __name__ == "__main__":
    # Diccionario maestro para consolidar toda la auditoría
    reporte_final = {
        "enumeracion_pasiva": {},
        "enumeracion_activa": {},
        "analisis_cabeceras": {}
    }
    
    # 1. Ejecutar Fase Pasiva
    target_ip, datos_pasivos = numeracion_pasiva_local(TARGET_DOMAIN)
    reporte_final["enumeracion_pasiva"] = datos_pasivos
    
    # 2. Ejecutar Fase Activa (si la IP es válida)
    if target_ip:
        datos_activos = numeracion_activa(target_ip)
        reporte_final["enumeracion_activa"] = datos_activos
    else:
        print("\n[!] Escaneo de puertos omitido: No se obtuvo una IP válida.")
        reporte_final["enumeracion_activa"]["error"] = "No se pudo establecer una IP objetivo válida."

    # 3. Ejecutar Análisis de Cabeceras
    # Toma la URL del argumento o la pide interactivamente
    if len(sys.argv) > 1:
        url_objetivo = sys.argv[1]
    else:
        url_objetivo = input("\nIntroduce la URL o dominio para analizar cabeceras (ej. google.com): ")
    
    datos_cabeceras = analizar_cabeceras(url_objetivo)
    reporte_final["analisis_cabeceras"] = datos_cabeceras

    # 4. Exportar el reporte final consolidado a JSON
    nombre_archivo = "resultados_auditoria.json"
    try:
        with open(nombre_archivo, "w", encoding="utf-8") as archivo_json:
            # indent=4 le da un formato estético al archivo para que sea legible
            json.dump(reporte_final, archivo_json, indent=4, ensure_ascii=False)
        print(f"\n[✓] ¡Éxito! Todos los resultados se exportaron correctamente a: {nombre_archivo}")
    except Exception as e:
        print(f"\n[!] Error inesperado al guardar el archivo JSON: {e}")