# checkheaders

# 🛡️ Analizador de Cabeceras de Correo Electrónico + Reputación de URLs con VirusTotal

Este script en Python permite **analizar la cabecera y el cuerpo de un correo electrónico** directamente desde la terminal, sin necesidad de subir archivos `.eml`. Su objetivo es ayudarte a evaluar la confiabilidad del mensaje detectando manipulaciones, falta de autenticación, reputación de dominios y presencia de URLs sospechosas.

---

## 🚀 ¿Cómo funciona?

1. **Pega todo el correo** (cabecera y cuerpo) directamente en la terminal.
2. El script **detecta automáticamente** la separación entre cabecera y cuerpo.
3. Se realiza un análisis completo:
   - Extracción del dominio del remitente.
   - Verificación de registros **SPF, DKIM, DMARC**.
   - Análisis de consistencia en campos `Received`.
   - Consulta de reputación del dominio en **VirusTotal**.
   - Extracción y análisis de URLs del cuerpo del correo con **VirusTotal**.
   - Cálculo de puntuación de confiabilidad (escala 0 a 11).

---

## 📌 Características clave

- ✅ Entrada manual (no requiere archivos `.eml`).
- ✅ Verifica autenticidad de dominio: SPF, DKIM, DMARC.
- ✅ Usa la API gratuita de **VirusTotal** para analizar:
  - Reputación de dominios.
  - Reputación de URLs encontradas en el cuerpo.
- ✅ Reporte visual con colores.
- ✅ Clasificación final del correo: confiable, parcialmente confiable o no confiable.

---

## 📸 Ejemplo de salida

![Ejemplo de análisis](./image.png)

---

## 🔧 Requisitos

- Python 3.7 o superior
- API Key gratuita de [VirusTotal](https://www.virustotal.com/)
- Instala las dependencias:

```bash
pip install -r requirements.txt
