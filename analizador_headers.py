#!/usr/bin/env python3
import requests
import warnings
import json
import argparse
from urllib.parse import urlparse

# Suprimir advertencias por certificados SSL no verificados (útil para pruebas, pero ten precaución en producción)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Fuerza el uso de HTTPS y protege contra ataques de degradación de SSL/TLS.",
    "X-Frame-Options": "Previene ataques de Clickjacking.",
    "X-XSS-Protection": "Ayuda a prevenir ataques XSS en navegadores antiguos (considerar 0 o remover si CSP es fuerte).",
    "X-Content-Type-Options": "Previene el 'MIME-sniffing'.",
    "Content-Security-Policy": "Controla los recursos que el navegador puede cargar.",
    "Referrer-Policy": "Controla qué información del 'referrer' se envía.",
    "Permissions-Policy": "Controla el acceso a funciones del navegador.",
    "Cross-Origin-Embedder-Policy": "Aísla el documento del contenido no COEP.",
    "Cross-Origin-Opener-Policy": "Protege ventanas de primer nivel entre orígenes.",
    "Cross-Origin-Resource-Policy": "Protege recursos de ser incrustados desde otros orígenes.",
    "Cache-Control": "Controla el almacenamiento en caché.",
    "Pragma": "Cabecera de caché HTTP/1.0 (generalmente superada por Cache-Control en HTTP/1.1+).",
    "Set-Cookie": "Verificar atributos HttpOnly, Secure, SameSite, Max-Age/Expires, Domain, Path.",
    "Report-To": "Configura un endpoint para que el navegador envíe reportes de políticas (ej. CSP, NEL).",
    "NEL": "Network Error Logging: Permite recopilar errores de red del lado del cliente y enviarlos a Report-To."
}

def analyze_security_headers(url):
    """
    Analiza las cabeceras de seguridad HTTP de un sitio web.

    Realiza una petición HEAD a la URL para obtener las cabeceras de respuesta y
    luego verifica la presencia y el valor de las cabeceras de seguridad predefinidas.

    Args:
        url (str): La URL del sitio web a analizar.

    Returns:
        dict or None: Un diccionario con los resultados del análisis o None si la petición falla.
    """
    print(f"\nAnalizando cabeceras de seguridad para: {url}\n{'='*60}")
    result = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "headers": {},
        "security_analysis": {}
    }

    try:
        response = requests.head(url, allow_redirects=True, timeout=15, verify=False)
        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)

        for header, description in SECURITY_HEADERS.items():
            present = header in response.headers
            result["security_analysis"][header] = {
                "present": present,
                "value": response.headers.get(header, None),
                "description": description
            }
        return result

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] No se pudo acceder a la URL: {e}")
        return None

def save_results(result, output_file):
    """
    Guarda los resultados del análisis en un archivo JSON.

    Args:
        result (dict): El diccionario que contiene los resultados del análisis.
        output_file (str): La ruta y el nombre del archivo JSON de salida.
    """
    if result:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4, ensure_ascii=False)
        print(f"\n[✔] Resultados guardados en: {output_file}")

def main():
    """
    Función principal del script.

    Analiza los argumentos de línea de comandos, valida la URL, realiza el análisis
    de las cabeceras de seguridad, imprime un resumen en la consola y guarda
    los resultados completos en un archivo JSON.
    """
    parser = argparse.ArgumentParser(description="Análisis de cabeceras de seguridad HTTP/HTTPS")
    parser.add_argument("url", help="URL del sitio a analizar (ej. https://ejemplo.com)")
    parser.add_argument("-o", "--output", help="Archivo de salida en formato JSON", default="resultado_headers.json")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    parsed = urlparse(args.url)
    if not parsed.netloc:
        print("[!] URL inválida. Asegúrate de incluir un dominio válido (ej. ejemplo.com).")
        return

    result = analyze_security_headers(args.url)
    if result:
        for header, data in result["security_analysis"].items():
            status = "[+]" if data["present"] else "[-]"
            print(f"{status} {header}: {data['value'] or 'FALTANTE'}")
        save_results(result, args.output)

if __name__ == "__main__":
    main()