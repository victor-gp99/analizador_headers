#!/usr/bin/env python3
import requests
import warnings # Para suprimir el warning de InsecureRequest

def analyze_security_headers(url):
    """
    Analiza las cabeceras HTTP de una URL dada, con un enfoque en las cabeceras de seguridad.
    """
    print(f"\n{'='*50}")
    print(f"Analizando cabeceras de seguridad para: {url}")
    print(f"{'='*50}\n")

    # Suprimir el InsecureRequestWarning al usar verify=False
    warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

    try:
        # Añadir verify=False para ignorar la verificación del certificado SSL
        response = requests.head(url, allow_redirects=True, timeout=15, verify=False)

        print(f"URL efectiva después de redirecciones: {response.url}")
        print(f"Código de estado HTTP: {response.status_code}\n")

        headers = response.headers

        # --- Sección 1: Todas las cabeceras recibidas ---
        print(f"{'-'*10} Todas las Cabeceras Recibidas {'-'*10}")
        if not headers:
            print("[!] No se recibieron cabeceras.")
        else:
            for header_name, header_value in headers.items():
                print(f"  {header_name}: {header_value}")
        print(f"{'-'*50}\n")

        # --- Sección 2: Análisis de Cabeceras de Seguridad ---
        print(f"{'-'*10} Análisis de Cabeceras de Seguridad {'-'*10}")

        # Lista exhaustiva de cabeceras de seguridad comunes a verificar
        security_headers_to_check = {
            "Strict-Transport-Security": {
                "present": False,
                "description": "Fuerza el uso de HTTPS y protege contra ataques de degradación de SSL/TLS."
            },
            "X-Frame-Options": {
                "present": False,
                "description": "Previene ataques de Clickjacking (la página no se puede incrustar en iframes maliciosos)."
            },
            "X-XSS-Protection": {
                "present": False,
                "description": "Ayuda a prevenir ataques de Cross-Site Scripting (XSS) en navegadores antiguos."
            },
            "X-Content-Type-Options": {
                "present": False,
                "description": "Previene el 'MIME-sniffing' por parte del navegador."
            },
            "Content-Security-Policy": {
                "present": False,
                "description": "Controla los recursos que el navegador puede cargar (scripts, estilos, imágenes, etc.)."
            },
            "Referrer-Policy": {
                "present": False,
                "description": "Controla qué información del 'referrer' se envía en las solicitudes."
            },
            "Permissions-Policy": { # Anteriormente Feature-Policy
                "present": False,
                "description": "Controla el acceso a funciones del navegador (micrófono, cámara, etc.)."
            },
            "Cross-Origin-Embedder-Policy": {
                "present": False,
                "description": "Aísla el documento del contenido no COEP, crucial para COOP."
            },
            "Cross-Origin-Opener-Policy": {
                "present": False,
                "description": "Protege ventanas de primer nivel de ser abiertas por documentos entre orígenes."
            },
            "Cross-Origin-Resource-Policy": {
                "present": False,
                "description": "Protege recursos de ser incrustados desde otros orígenes."
            },
            "Cache-Control": { # Importante para la seguridad de la caché
                "present": False,
                "description": "Controla el almacenamiento en caché de la respuesta."
            },
            "Pragma": { # Legado, pero a veces usado con Cache-Control
                "present": False,
                "description": "Cabecera de caché HTTP/1.0, a menudo usada con 'no-cache'."
            },
            "Set-Cookie": { # Aunque no es de "seguridad" per se, su configuración es vital (HttpOnly, Secure, SameSite)
                "present": False,
                "description": "Establece cookies en el navegador del cliente. Verificar HttpOnly, Secure, SameSite."
            },
            # Puedes añadir más aquí si es necesario
            # "Access-Control-Allow-Origin": {
            #     "present": False,
            #     "description": "Controla el CORS (Cross-Origin Resource Sharing). Revisa si es demasiado permisivo."
            # }
        }

        missing_headers_count = 0

        for header_name, details in security_headers_to_check.items():
            if header_name in headers:
                print(f"[+] '{header_name}' está PRESENTE. Valor: {headers[header_name]}")
                security_headers_to_check[header_name]["present"] = True
            else:
                print(f"[-] '{header_name}' está FALTANTE. Descripción: {details['description']}")
                missing_headers_count += 1

        print(f"\n{'*'*50}")
        print(f"Resumen del Análisis:")
        print(f"  Total de cabeceras de seguridad verificadas: {len(security_headers_to_check)}")
        print(f"  Cabeceras de seguridad faltantes: {missing_headers_count}")
        print(f"  Cabeceras de seguridad presentes: {len(security_headers_to_check) - missing_headers_count}")
        print(f"{'*'*50}\n")

    except requests.exceptions.RequestException as e:
        print(f"\n[ERROR] No se pudo acceder a la URL o hubo un problema de red: {e}")
    except Exception as e:
        print(f"\n[ERROR] Ocurrió un error inesperado: {e}")

if __name__ == "__main__":
    target_url = input("Por favor, introduce la URL a analizar (ej. https://ejemplo.com): ")
    if not target_url.startswith(("http://", "https://")):
        print("[!] La URL debe comenzar con 'http://' o 'https://'. Intentando añadir 'https://'...")
        target_url = "https://" + target_url

    analyze_security_headers(target_url)
