# 🔐 Análisis de Cabeceras de Seguridad HTTP/HTTPS

Este script en Python 3 permite analizar de forma automatizada los encabezados de seguridad presentes en servicios web accesibles mediante HTTP o HTTPS.

## 🚀 Características

- Verifica la presencia de cabeceras como `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, entre otras.
- Muestra un resumen claro de cabeceras presentes y faltantes.
- Guarda los resultados en un archivo JSON estructurado.
- Permite ejecución desde línea de comandos con parámetros.

## 🛠️ Requisitos

- Python 3.6 o superior
- Módulo `requests` (instalable con `pip install requests`)

## 📦 Instalación

```bash
git clone https://github.com/tuusuario/analizador-headers.git
cd analizador-headers
pip install -r requirements.txt

