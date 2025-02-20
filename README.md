##  P3nUrM0M

##  Description : Un scanner de sécurité basé sur Nmap avec détection automatique des vulnérabilités, des CPE, et des scores CVSS via l'API Vulners. Il permet de scanner une IP unique ou un réseau entier (CIDR), tout en affichant l'IP en cours de scan pour suivre la progression.

🛠 Fonctionnalités
Scan Nmap avec détection des services (-sV), des OS (-O) et des vulnérabilités (--script vulners).
Extraction des CVE détectés et récupération de leur score CVSS.
Affichage du niveau de criticité basé sur le CVSS.
Possibilité de scanner une seule IP ou un réseau entier (CIDR).
Affichage en temps réel de l'IP en cours de scan.
🚀 Installation
Pré-requis :
Assure-toi d'avoir Python 3, Nmap et les bibliothèques nécessaires :

```sh
sudo apt update && sudo apt install -y nmap python3 python3-pip
pip3 install requests colorama
```

Clone le projet :

```sh
git clone https://github.com/NoWa-FTN/P3nUrM0M.git
cd P3nUrM0M
```

---

## 📌 Utilisation

### 🔍 Scanner une seule IP  
```sh
sudo python3 P3nMapper.py -t 10.10.14.1
```

### 🌐 Scanner un réseau entier (CIDR)  
```sh
sudo python3 P3nMapper.py -t 10.10.14.0/24
```

### 📋 Exemple de sortie :
```
[+] Scanning IP: 10.10.14.1...
[+] Scan terminé pour 10.10.14.1.
[+] Services détectés :
  Port 80 - HTTP (Apache 2.4.41)
    [CPE] : cpe:/a:apache:http_server:2.4.41
[+] Vulnérabilités détectées :
    CVE-2021-41773 - CVSS 9.8 - Critique
      https://vulners.com/cve/CVE-2021-41773
```

---

## 🔥 Améliorations futures

- Ajouter la prise en charge de l'exportation des résultats en JSON/CSV.
- Améliorer l'affichage avec une **interface graphique** ou un **dashboard web**.
- Ajouter le support de **d'autres bases de vulnérabilités**.

---

## 📜 Avertissement

⚠ **Usage réservé aux tests de sécurité légaux !**  
Je ne suis **pas responsable** de l'utilisation illégale de cet outil. **Testez uniquement sur des machines dont vous avez l'autorisation !**

---

## 🤝 Contributions

Les contributions sont les bienvenues !  
Forke le projet, fais tes modifications et ouvre une **pull request**.

---

## 📌 Auteur

👤 **NoWa-FTN**  
📂 **GitHub** : [NoWa-FTN](https://github.com/NoWa-FTN)  
📧 **LinkedIn** : www.linkedin.com/in/noa-fontaine-683331250
