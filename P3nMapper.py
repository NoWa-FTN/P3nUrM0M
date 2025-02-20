import subprocess
import xml.etree.ElementTree as ET
import argparse
import requests
import re
import ipaddress
from colorama import Fore, Style

# Fonction pour déterminer le niveau de criticité
def get_severity(cvss_score):
    """Détermine le niveau de criticité en fonction du score CVSS."""
    if cvss_score >= 9:
        return Fore.RED + "Critique" + Style.RESET_ALL
    elif cvss_score >= 7:
        return Fore.YELLOW + "Haute" + Style.RESET_ALL
    elif cvss_score >= 4:
        return Fore.BLUE + "Moyenne" + Style.RESET_ALL
    else:
        return Fore.GREEN + "Faible" + Style.RESET_ALL

# Fonction pour obtenir le score CVSS d'un CVE via l'API Vulners
def get_cve_cvss_score(cve_id):
    """Obtient le score CVSS d'un CVE depuis l'API Vulners."""
    try:
        vulners_url = f"https://vulners.com/api/v3/search/lucene/?query={cve_id}&type=cve"
        response = requests.get(vulners_url)
        response.raise_for_status()

        data = response.json()
        if 'data' in data and 'documents' in data['data']:
            cve_data = data['data']['documents'][0]
            return cve_data.get('cvss', None)
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Erreur lors de l'obtention du score CVSS pour {cve_id} : {e}{Style.RESET_ALL}")
        return None

# Fonction pour exécuter Nmap sur une seule IP
def nmap_scan(ip):
    """Exécute un scan Nmap sur une seule adresse IP."""
    print(f"{Fore.YELLOW}[+] Scanning IP: {ip}...{Style.RESET_ALL}")
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-O", "-sV", "--script", "vulners", "-oX", "-", ip],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"{Fore.RED}[!] Erreur lors du scan de {ip} : {result.stderr}{Style.RESET_ALL}")
            return None

        print(f"{Fore.GREEN}[+] Scan terminé pour {ip}.{Style.RESET_ALL}")
        return result.stdout
    except Exception as e:
        print(f"{Fore.RED}[!] Erreur lors de l'appel à Nmap : {e}{Style.RESET_ALL}")
        return None

# Fonction pour analyser et afficher les résultats du scan
def parse_nmap_output(nmap_output):
    """Analyse et affiche les résultats du scan Nmap avec les vulnérabilités détectées."""
    try:
        root = ET.fromstring(nmap_output)

        for host in root.findall("host"):
            ip_address = host.find("address").get("addr")
            print(f"\n{Fore.YELLOW}Hôte détecté : {ip_address}{Style.RESET_ALL}")

            ports_data = {}

            # Extraction des services détectés
            print(f"{Fore.CYAN}[+] Services et Ports détectés :{Style.RESET_ALL}")
            for port in host.findall(".//port"):
                portid = port.get("portid")
                service = port.find("service")
                service_name = service.get("name", "Inconnu") if service is not None else "Inconnu"
                service_product = service.get("product", "Non spécifié") if service is not None else "Non spécifié"
                service_version = service.get("version", "Non spécifié") if service is not None else "Non spécifié"
                cpe = service.find("cpe").text if service is not None and service.find("cpe") is not None else "Aucun"

                print(f"  {Fore.MAGENTA}Port {portid} - {service_name} ({service_product} {service_version}){Style.RESET_ALL}")
                print(f"    [CPE] : {cpe}")

                ports_data[portid] = {"service": service_name, "vulns": []}

                # Extraction des vulnérabilités détectées
                for script in port.findall("script"):
                    if script.get("id") == "vulners":
                        output = script.get("output")
                        if output:
                            for line in output.splitlines():
                                match = re.search(r"(CVE-\d{4}-\d+)\s+(\d+\.\d+)", line)
                                if match:
                                    cve_id, cvss_score = match.groups()
                                    cvss_score = float(cvss_score)
                                    severity = get_severity(cvss_score)
                                    vulners_link = f"https://vulners.com/cve/{cve_id}"

                                    ports_data[portid]["vulns"].append((cve_id, cvss_score, severity, vulners_link))

            # Affichage des vulnérabilités détectées
            print(f"\n{Fore.CYAN}[+] Vulnérabilités détectées :{Style.RESET_ALL}")
            for portid, data in ports_data.items():
                if data["vulns"]:
                    print(f"\n  {Fore.MAGENTA}Port {portid} - {data['service']} :{Style.RESET_ALL}")
                    for cve_id, cvss_score, severity, vulners_link in data["vulns"]:
                        print(f"    {cve_id} - CVSS {cvss_score} - {severity}")
                        print(f"      {Fore.BLUE}{vulners_link}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Erreur lors du filtrage des résultats : {e}{Style.RESET_ALL}")

# Fonction principale pour exécuter le scan sur un réseau ou une seule IP
def scan(target):
    """Scanne un réseau entier IP par IP ou une seule adresse."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        for ip in network.hosts():  # Génère toutes les adresses IP du réseau
            ip_str = str(ip)
            nmap_output = nmap_scan(ip_str)
            if nmap_output:
                parse_nmap_output(nmap_output)
    except ValueError:  # Si c'est une IP unique et pas un réseau
        nmap_output = nmap_scan(target)
        if nmap_output:
            parse_nmap_output(nmap_output)

# Execution du programme en ligne de commande
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scanner de sécurité Nmap avec détection des vulnérabilités, CPE et criticité CVSS")
    parser.add_argument("-t", "--target", required=True, help="Adresse IP ou réseau cible (ex: 192.168.1.1 ou 192.168.1.0/24)")
    args = parser.parse_args()

    scan(args.target)
