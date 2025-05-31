import re
import sys
import base64
import requests
from colorama import init, Fore, Style
import dns.resolver

init(autoreset=True)
VT_API_KEY = "TU_API_KEY_VA_AQUI"

def extraer_dominio_desde_header(header):
    match = re.search(r'@([\w\.-]+)', header)
    return match.group(1) if match else None

def verificar_registro(registro, dominio):
    try:
        dns.resolver.resolve(dominio, registro)
        return True
    except:
        return False

def consistencia_received(header, dominio):
    received_matches = re.findall(r'Received:\s+from\s+(\S+)', header, re.IGNORECASE)
    return any(dominio in r for r in received_matches)

def reputacion_dominio_virustotal(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return False, f"Error HTTP {response.status_code}: {response.text}"
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return True, stats
    except Exception as e:
        return False, f"Error al consultar VT: {e}"

def extraer_urls(texto):
    url_regex = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    return re.findall(url_regex, texto)

def reputacion_urls_virustotal(urls):
    resultados = []
    for url in urls:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(vt_url, headers=headers)
            if response.status_code != 200:
                resultados.append((url, Fore.RED + "❌ Error HTTP" + Style.RESET_ALL, None))
                continue
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            resultados.append((url, Fore.GREEN + "✔️" + Style.RESET_ALL, stats))
        except Exception as e:
            resultados.append((url, Fore.RED + f"❌ Error: {e}" + Style.RESET_ALL, None))
    return resultados

def mostrar_resultado_urls(resultados):
    print(f"{Fore.YELLOW}\n[6] Análisis de URLs encontradas en el correo (cabeceras + cuerpo):{Style.RESET_ALL}")
    if not resultados:
        print(Fore.YELLOW + "No se encontraron URLs.\n" + Style.RESET_ALL)
        return 0
    malas = 0
    for url, estado, stats in resultados:
        print(Fore.CYAN + f"\n🔗 URL: {url}" + Style.RESET_ALL)
        print(f"  Estado: {estado}")
        if stats:
            print(Fore.GREEN + f"    Seguras: {stats.get('harmless', 0)}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"    Sospechosas: {stats.get('suspicious', 0)}" + Style.RESET_ALL)
            print(Fore.RED + f"    Maliciosas: {stats.get('malicious', 0)}" + Style.RESET_ALL)
            malas += stats.get("malicious", 0) + stats.get("suspicious", 0)
    print()
    return malas

def puntuar_confiabilidad(spf_ok, dkim_ok, dmarc_ok, consistencia, vt_ok, urls_malas):
    puntuacion = 0
    if spf_ok: puntuacion += 2
    if dkim_ok: puntuacion += 1
    if dmarc_ok: puntuacion += 2
    if consistencia: puntuacion += 2
    if vt_ok: puntuacion += 2
    if urls_malas == 0:
        puntuacion += 2
    else:
        puntuacion -= 2
    return puntuacion

def clasificar_confiabilidad(puntaje):
    if puntaje >= 9:
        return Fore.GREEN + "✅ Confiable" + Style.RESET_ALL
    elif 6 <= puntaje < 9:
        return Fore.YELLOW + "⚠️ Parcialmente confiable" + Style.RESET_ALL
    else:
        return Fore.RED + "❌ No confiable" + Style.RESET_ALL

def analizar_cabecera_texto(cabecera, cuerpo_texto):
    from_match = re.search(r'From:\s?.*<([^>]+)>', cabecera, re.IGNORECASE)
    from_email = from_match.group(1) if from_match else ""
    dominio = extraer_dominio_desde_header(from_email)

    print(Fore.BLUE + Style.BRIGHT + "\n🔍 Análisis de cabecera de correo\n" + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}[1]{Style.RESET_ALL} Remitente: {Fore.WHITE}{from_email}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[2]{Style.RESET_ALL} Dominio: {Fore.WHITE}{dominio if dominio else 'No extraído'}{Style.RESET_ALL}")

    if not dominio:
        print(Fore.RED + "\n❌ No se pudo extraer el dominio. Finalizando análisis." + Style.RESET_ALL)
        return

    print(f"\n{Fore.MAGENTA}[3]{Style.RESET_ALL} Verificación de registros DNS:")
    spf_ok = verificar_registro("TXT", dominio)
    dkim_ok = verificar_registro("TXT", f"default._domainkey.{dominio}")
    dmarc_ok = verificar_registro("TXT", f"_dmarc.{dominio}")

    print(f"  SPF: {Fore.GREEN + '✔️' if spf_ok else Fore.RED + '❌'}{Style.RESET_ALL}")
    print(f"  DKIM: {Fore.GREEN + '✔️' if dkim_ok else Fore.RED + '❌'}{Style.RESET_ALL}")
    print(f"  DMARC: {Fore.GREEN + '✔️' if dmarc_ok else Fore.RED + '❌'}{Style.RESET_ALL}")

    consistencia = consistencia_received(cabecera, dominio)
    print(f"\n{Fore.MAGENTA}[4]{Style.RESET_ALL} Consistencia con 'Received': {Fore.GREEN + '✔️' if consistencia else Fore.RED + '❌'}{Style.RESET_ALL}")

    print(f"\n{Fore.MAGENTA}[5]{Style.RESET_ALL} Reputación del dominio (VirusTotal):")
    vt_ok, vt_info = reputacion_dominio_virustotal(dominio)
    
    if isinstance(vt_info, dict):
        print(f"  {Fore.GREEN}Seguras: {vt_info.get('harmless', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Sospechosas: {vt_info.get('suspicious', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Maliciosas: {vt_info.get('malicious', 0)}{Style.RESET_ALL}")
    else:
        print(Fore.RED + f"  ❌ Error VirusTotal: {vt_info}" + Style.RESET_ALL)

    # EXTRAER URLs de cabeceras + cuerpo
    urls = extraer_urls(cabecera + "\n" + cuerpo_texto)
    print(f"\n{Fore.MAGENTA}URLs detectadas:{Style.RESET_ALL} {Fore.CYAN}{urls if urls else 'Ninguna'}{Style.RESET_ALL}")

    resultados_urls = reputacion_urls_virustotal(urls)
    total_malas_urls = mostrar_resultado_urls(resultados_urls)

    puntuacion = puntuar_confiabilidad(spf_ok, dkim_ok, dmarc_ok, consistencia, vt_ok, total_malas_urls)
    clasificacion = clasificar_confiabilidad(puntuacion)

    print(Fore.MAGENTA + Style.BRIGHT + f"\n✅ Puntuación de confiabilidad: {puntuacion}/11" + Style.RESET_ALL)
    print(Fore.MAGENTA + Style.BRIGHT + f"🔎 Clasificación: {clasificacion}\n" + Style.RESET_ALL)


if __name__ == "__main__":
    print(Fore.BLUE + Style.BRIGHT + "📥 Pega todo el correo (cabeceras y cuerpo). Finaliza con Ctrl+D (Linux/macOS) o Ctrl+Z (Windows) y Enter:\n" + Style.RESET_ALL)
    try:
        full_input = sys.stdin.read()
        if "\n\n" in full_input:
            header_text, cuerpo_texto = full_input.split("\n\n", 1)
            analizar_cabecera_texto(header_text.strip(), cuerpo_texto.strip())
        else:
            print(Fore.RED + "❌ Entrada inválida. Asegúrate de incluir una línea vacía entre cabeceras y cuerpo." + Style.RESET_ALL)
    except KeyboardInterrupt:
        print(Fore.RED + "\n❌ Entrada cancelada por el usuario." + Style.RESET_ALL)
