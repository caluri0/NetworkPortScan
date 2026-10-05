"""
Generates the learning guide PDF for the Network Port Scanner project.

Run:
    pip install fpdf2
    python docs/generate_learning_pdf.py

Output:
    docs/Network_Port_Scanner_Learning_Guide.pdf
"""

from __future__ import annotations

import textwrap
import urllib.request
from pathlib import Path

try:
    from fpdf import FPDF
except ImportError as exc:
    raise SystemExit("Install dependency: pip install fpdf2") from exc


DOCS_DIR = Path(__file__).resolve().parent
OUTPUT = DOCS_DIR / "Network_Port_Scanner_Learning_Guide.pdf"
FONTS_DIR = DOCS_DIR / "fonts"

FONT_URLS = {
    "DejaVuSans.ttf": "https://cdn.jsdelivr.net/npm/dejavu-fonts-ttf@2.37.3/ttf/DejaVuSans.ttf",
    "DejaVuSans-Bold.ttf": "https://cdn.jsdelivr.net/npm/dejavu-fonts-ttf@2.37.3/ttf/DejaVuSans-Bold.ttf",
    "DejaVuSans-Oblique.ttf": "https://cdn.jsdelivr.net/npm/dejavu-fonts-ttf@2.37.3/ttf/DejaVuSans-Oblique.ttf",
    "DejaVuSansMono.ttf": "https://cdn.jsdelivr.net/npm/dejavu-fonts-ttf@2.37.3/ttf/DejaVuSansMono.ttf",
}


def ensure_fonts() -> None:
    FONTS_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in FONT_URLS.items():
        path = FONTS_DIR / name
        if not path.exists():
            print(f"Downloading font: {name}")
            urllib.request.urlretrieve(url, path)


class GuidePDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("DejaVu", "I", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "Network Port Scanner - Learning Guide", new_x="RIGHT", new_y="TOP")
        self.cell(0, 8, f"Page {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, "Portfolio Cybersecurite - Usage educatif uniquement", align="C")

    def chapter(self, title: str):
        self.ln(3)
        self.set_font("DejaVu", "B", 15)
        self.set_text_color(20, 60, 120)
        self.multi_cell(self.epw, 9, title)
        self.set_draw_color(20, 60, 120)
        self.line(self.l_margin, self.get_y() + 1, self.w - self.r_margin, self.get_y() + 1)
        self.ln(5)
        self.set_text_color(0, 0, 0)

    def section(self, title: str):
        self.ln(1)
        self.set_font("DejaVu", "B", 11)
        self.multi_cell(self.epw, 7, title)
        self.ln(1)

    def p(self, text: str):
        self.set_font("DejaVu", "", 10)
        self.multi_cell(self.epw, 5.5, text)
        self.ln(1)

    def bullet(self, text: str):
        self.set_font("DejaVu", "", 10)
        self.multi_cell(self.epw, 5.5, f"  - {text}")

    def code(self, text: str):
        self.set_fill_color(245, 245, 245)
        self.set_font("DejaVuMono", "", 8)
        for line in text.strip().splitlines():
            self.multi_cell(self.epw, 4.5, "  " + line, fill=True)
        self.ln(2)

    def centered(self, text: str, size: int = 10, style: str = ""):
        self.set_font("DejaVu", style, size)
        self.multi_cell(self.epw, size * 0.5, text, align="C")

    def table3(self, rows: list[tuple[str, str, str]], header: bool = False):
        widths = [42, 52, 86]
        style = "B" if header else ""
        self.set_font("DejaVu", style, 8.5)
        for row in rows:
            for value, width in zip(row, widths):
                self.cell(width, 7, value, border=1)
            self.ln()


def build_pdf() -> None:
    ensure_fonts()

    pdf = GuidePDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_font("DejaVu", "", str(FONTS_DIR / "DejaVuSans.ttf"))
    pdf.add_font("DejaVu", "B", str(FONTS_DIR / "DejaVuSans-Bold.ttf"))
    pdf.add_font("DejaVu", "I", str(FONTS_DIR / "DejaVuSans-Oblique.ttf"))
    pdf.add_font("DejaVuMono", "", str(FONTS_DIR / "DejaVuSansMono.ttf"))

    # Cover
    pdf.add_page()
    pdf.ln(35)
    pdf.centered("Network Port Scanner", size=24, style="B")
    pdf.ln(4)
    pdf.centered("Guide d'apprentissage du code", size=15)
    pdf.ln(10)
    pdf.centered(
        "Portfolio Cybersécurité\n"
        "Architecture, bibliothèques Python et concepts réseau\n"
        "Objectif : comprendre un scanner de ports comme Nmap, en Python pur",
        size=11,
        style="I",
    )
    pdf.ln(25)
    pdf.centered("Projet v1.0  |  Python 3.10+  |  Bibliothèque standard uniquement", size=10)

    # 1 Introduction
    pdf.add_page()
    pdf.chapter("1. Introduction et objectifs pédagogiques")
    pdf.p(
        "Ce document explique en détail le projet Network Port Scanner : un programme "
        "Python qui teste les ports ouverts d'une adresse IP, identifie les services "
        "exposés et produit un rapport de risque. Il s'inscrit dans une démarche "
        "d'apprentissage pour une carrière en cybersécurité, notamment au Japon."
    )
    pdf.section("Objectifs d'apprentissage")
    pdf.bullet("Comprendre le scan TCP (handshake 3-way) et UDP.")
    pdf.bullet("Utiliser sockets, threads et queues en Python.")
    pdf.bullet("Pratiquer le banner grabbing et le fingerprinting de services.")
    pdf.bullet("Construire une CLI professionnelle avec argparse.")
    pdf.bullet("Documenter un audit réseau (rapports TXT / JSON).")
    pdf.bullet("Justifier le choix de n'utiliser que la bibliothèque standard.")
    pdf.section("Prérequis")
    pdf.bullet("Python : variables, fonctions, classes, exceptions, dictionnaires.")
    pdf.bullet("Réseau : adresse IP, ports, TCP/UDP, DNS.")
    pdf.bullet("Éthique : scanner uniquement des cibles autorisées.")
    pdf.section("Avertissement légal")
    pdf.p(
        "Ne scannez jamais un système sans autorisation écrite. Au Japon, la "
        "Unauthorized Computer Access Law (Act No. 128, 1999) interdit l'accès "
        "non autorisé. Cibles légales : scanme.nmap.org, 127.0.0.1, votre réseau "
        "local avec permission."
    )

    # 2 Architecture
    pdf.add_page()
    pdf.chapter("2. Architecture du projet")
    pdf.p(
        "Le code est organisé en trois modules avec des responsabilités distinctes. "
        "Cette séparation facilite la maintenance, les tests et la lecture pédagogique."
    )
    pdf.code(
        """ScannerPortReseau/
├── scanner.py    # Entrée, scan TCP/UDP, CLI, multithreading
├── utils.py      # DNS, bannières, CVE, utilitaires IP
├── report.py     # Rapports TXT et JSON
├── reports/      # Fichiers de sortie
└── README.md     # Documentation EN / JP"""
    )
    pdf.section("Flux d'exécution")
    pdf.bullet("L'utilisateur lance scanner.py (CLI ou interactif).")
    pdf.bullet("resolve_hostname() convertit le nom en IP.")
    pdf.bullet("PortScanner remplit une Queue de ports.")
    pdf.bullet("Des threads workers exécutent scan_tcp_port() ou scan_udp_port().")
    pdf.bullet("Les ports ouverts sont collectés avec bannière et niveau de risque.")
    pdf.bullet("ScanReport peut sauvegarder un rapport dans reports/.")
    pdf.code(
        """Utilisateur -> scanner.py -> utils.py (DNS)
              -> PortScanner (threads + Queue)
              -> report.py -> reports/scan_<IP>_<date>.txt|json"""
    )

    # 3 Libraries
    pdf.add_page()
    pdf.chapter("3. Choix des bibliothèques Python")
    pdf.p(
        "Le scanner n'utilise aucune dépendance externe (pip). Tous les modules "
        "provienent de la bibliothèque standard (stdlib). Ce choix est pédagogique "
        "et professionnel pour un premier projet portfolio."
    )
    pdf.section("Pourquoi la stdlib ?")
    pdf.bullet("Installation simple : python scanner.py suffit.")
    pdf.bullet("Compréhension directe des mécanismes réseau (pas de wrapper opaque).")
    pdf.bullet("Démontre la maîtrise des fondamentaux Python.")
    pdf.bullet("Évite la dette de maintenance liée aux packages tiers.")
    pdf.section("Modules utilisés et alternatives")
    pdf.table3(
        [
            ("Module", "Rôle dans le projet", "Alternative externe"),
            ("socket", "Connexions TCP/UDP bas niveau", "scapy, python-nmap"),
            ("threading", "Parallélisme I/O-bound", "asyncio, concurrent.futures"),
            ("queue.Queue", "Distribution des ports aux workers", "multiprocessing"),
            ("argparse", "Interface en ligne de commande", "click, typer"),
            ("json", "Export structuré des rapports", "pydantic, orjson"),
            ("re", "Extraction version depuis bannières", "-"),
            ("datetime", "Durée et horodatage du scan", "-"),
            ("os", "Création du dossier reports/", "pathlib"),
            ("sys", "Arguments CLI, codes de sortie", "-"),
        ],
        header=True,
    )
    pdf.ln(2)
    pdf.section("socket : fondation du scan")
    pdf.p(
        "socket expose l'API Berkeley Sockets. connect_ex() réalise un scan "
        "de type TCP connect (équivalent Nmap -sT). Il ne nécessite pas de droits "
        "administrateur, contrairement au SYN scan (-sS) qui utilise des raw sockets."
    )
    pdf.section("threading vs asyncio")
    pdf.p(
        "Le scan attend surtout des réponses réseau (I/O-bound). Les threads "
        "libèrent le GIL pendant les attentes socket. threading est plus simple "
        "à enseigner qu'asyncio pour un premier projet réseau."
    )
    pdf.section("argparse")
    pdf.p(
        "argparse valide les types, génère --help et définit des valeurs par défaut. "
        "Exemple : python scanner.py -t 192.168.1.1 --ports 1-1024 --threads 100"
    )

    # 4 scanner.py
    pdf.add_page()
    pdf.chapter("4. Explication de scanner.py")
    pdf.section("4.1 COMMON_PORTS et RISKY_PORTS")
    pdf.p(
        "COMMON_PORTS mappe ~20 ports courants (22 SSH, 80 HTTP, 443 HTTPS...). "
        "RISKY_PORTS liste les ports à risque élevé si ouverts (Telnet 23, RDP 3389, "
        "SMB 445, Redis 6379, MongoDB 27017...)."
    )
    pdf.section("4.2 scan_tcp_port()")
    pdf.p("Algorithme :")
    pdf.bullet("Créer socket(AF_INET, SOCK_STREAM) pour TCP/IPv4.")
    pdf.bullet("Définir un timeout pour éviter les blocages.")
    pdf.bullet("connect_ex((host, port)) == 0 signifie port ouvert.")
    pdf.bullet("Si ouvert : grab_banner() et calcul du risque HIGH/MEDIUM.")
    pdf.bullet("Gérer gaierror (DNS), timeout (filtered), OSError (closed).")
    pdf.code(
        """result = sock.connect_ex((host, port))
if result == 0:
    result['state'] = 'open'
    result['banner'] = grab_banner(sock, port)"""
    )
    pdf.section("4.3 scan_udp_port()")
    pdf.p(
        "Envoi d'un paquet UDP vide via sendto(). Réponse UDP = open. "
        "Timeout = open|filtered (ambigu). ConnectionResetError = closed (ICMP unreachable)."
    )
    pdf.section("4.4 Classe PortScanner")
    pdf.p(
        "Implémente le pattern Worker Pool : Queue + N threads. "
        "threading.Lock() protège la liste open_ports (évite race condition). "
        "scan() lance les workers et join() attend la fin. "
        "scan_common_ports() scanne uniquement COMMON_PORTS."
    )
    pdf.section("4.5 Interface CLI")
    pdf.bullet("build_parser() : définit -t, -p, --threads, --timeout, -o...")
    pdf.bullet("parse_ports() : interprète common, all, 1-1024, 80,443.")
    pdf.bullet("run_scan() : logique partagée CLI + mode interactif.")
    pdf.bullet("main() : sans arguments -> interactif ; sinon -> CLI.")

    # 5 utils.py
    pdf.add_page()
    pdf.chapter("5. Explication de utils.py")
    pdf.section("5.1 DNS")
    pdf.p(
        "resolve_hostname() : gethostbyname() retourne une IPv4. "
        "reverse_dns_lookup() : gethostbyaddr() pour OSINT (IP vers nom)."
    )
    pdf.section("5.2 Banner grabbing")
    pdf.p(
        "grab_banner() lit les octets renvoyés par le service. BANNER_PROBES "
        "contient des requêtes par port (ex: HEAD / HTTP/1.0 pour port 80). "
        "Le texte est nettoyé (première ligne, caractères imprimables, max 200 chars)."
    )
    pdf.section("5.3 Analyse CVE")
    pdf.p(
        "analyze_banner() applique des regex (VERSION_PATTERNS) pour extraire "
        "logiciel et version, puis compare à KNOWN_VULNERABILITIES. "
        "En production : API NVD ou searchsploit. Alertes contextuelles pour "
        "Telnet, FTP et HTTP non chiffré."
    )
    pdf.section("5.4 Utilitaires")
    pdf.bullet("get_service_name() : lookup local ou getservbyport().")
    pdf.bullet("is_valid_ip() : validation IPv4 via inet_aton().")
    pdf.bullet("is_private_ip() : plages RFC 1918 et loopback 127.x.")

    # 6 report.py
    pdf.add_page()
    pdf.chapter("6. Explication de report.py")
    pdf.section("6.1 Classe ScanReport")
    pdf.p(
        "Agrège les résultats du scan et produit un livrable d'audit. "
        "Enrichit les données avec reverse DNS et détection réseau privé."
    )
    pdf.section("6.2 Méthodes")
    pdf.bullet("_calculate_risk_summary() : comptage HIGH/MEDIUM/LOW.")
    pdf.bullet("_generate_recommendations() : conseils par port détecté.")
    pdf.bullet("to_dict() : structure JSON complète avec analyse de bannières.")
    pdf.bullet("to_text() : rapport lisible pour humain ou client.")
    pdf.bullet("save(fmt) : écrit reports/scan_<IP>_<timestamp>.txt|json.")
    pdf.section("6.3 Sections du rapport")
    pdf.bullet("Informations cible (IP, hostname, réseau privé).")
    pdf.bullet("Informations scan (durée, horodatage).")
    pdf.bullet("Résumé des risques et détail des ports ouverts.")
    pdf.bullet("Recommandations et disclaimer légal.")

    # 7 Network concepts
    pdf.add_page()
    pdf.chapter("7. Concepts réseau et sécurité")
    pdf.section("7.1 Ports")
    pdf.p("0-1023 : well-known. 1024-49151 : registered. 49152-65535 : dynamiques.")
    pdf.section("7.2 Handshake TCP")
    pdf.p("SYN -> SYN-ACK -> ACK. Notre scanner utilise un TCP connect scan, visible dans les logs serveur.")
    pdf.section("7.3 Comparaison Nmap")
    pdf.table3(
        [
            ("Fonctionnalité", "Ce projet", "Nmap"),
            ("TCP connect", "Oui", "Oui (-sT)"),
            ("SYN stealth", "Non", "Oui (-sS, root)"),
            ("UDP avancé", "Basique", "Oui (-sU)"),
            ("Détection OS", "Non", "Oui (-O)"),
            ("Scripts NSE", "Non", "Oui"),
        ],
        header=True,
    )
    pdf.ln(2)
    pdf.section("7.4 Surface d'attaque")
    pdf.p(
        "Chaque port ouvert augmente la surface d'attaque. Appliquer le principe "
        "du moindre privilège : fermer tout service inutile."
    )

    # 8 Exercises
    pdf.add_page()
    pdf.chapter("8. Exercices et prolongements")
    pdf.section("Débutant")
    pdf.bullet("Scanner scanme.nmap.org en CLI et interactif.")
    pdf.bullet("Comparer --threads 50 vs 200.")
    pdf.bullet("Analyser un rapport JSON dans reports/.")
    pdf.section("Intermédiaire")
    pdf.bullet("Implémenter --no-banner dans scan_tcp_port().")
    pdf.bullet("Ajouter une CVE réelle depuis NVD.")
    pdf.bullet("Supporter --output-file pour chemin personnalisé.")
    pdf.section("Avancé")
    pdf.bullet("Réécrire avec asyncio.")
    pdf.bullet("Intégrer lookup CVE via API NVD.")
    pdf.bullet("Étudier SYN scan avec scapy (lab isolé uniquement).")
    pdf.section("Ressources Japon")
    pdf.bullet("RISS (Registered Information Security Specialist) - certification JP.")
    pdf.bullet("Nom japonais (romaji) : Joho shori anzen kakuho shien shi")
    pdf.bullet("TryHackMe, HackTheBox - pratique légale.")
    pdf.bullet("Nmap Book, OWASP Testing Guide.")

    # 9 Glossary
    pdf.add_page()
    pdf.chapter("9. Glossaire")
    glossary = [
        ("Banner", "Texte envoyé par un service indiquant logiciel/version."),
        ("CVE", "Identifiant public d'une vulnérabilité connue."),
        ("DNS", "Traduction nom de domaine vers adresse IP."),
        ("Fingerprinting", "Identification précise d'un logiciel via signaux réseau."),
        ("GIL", "Verrou global Python limitant le parallélisme CPU."),
        ("I/O-bound", "Tâche limitée par le réseau/disque, pas le processeur."),
        ("OSINT", "Renseignement open source (DNS inverse, bannières...)."),
        ("Pentest", "Test d'intrusion autorisé."),
        ("Race condition", "Bug d'accès concurrent non synchronisé."),
        ("Worker Pool", "File de tâches + workers parallèles."),
        ("TCP connect scan", "Scan via connexion TCP complète (connect_ex)."),
        ("Filtered port", "Port bloqué par firewall sans réponse claire."),
    ]
    for term, definition in glossary:
        pdf.set_font("DejaVu", "B", 10)
        pdf.cell(pdf.epw, 6, term, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "", 10)
        pdf.multi_cell(pdf.epw, 5.5, definition)
        pdf.ln(1)

    pdf.ln(3)
    pdf.section("Conclusion")
    pdf.p(
        "En maîtrisant ce code, vous comprenez les briques essentielles d'un outil "
        "de reconnaissance réseau : sockets, parallélisme, DNS, bannières et "
        "documentation d'audit. C'est une base solide pour évoluer vers des outils "
        "professionnels et pour valoriser votre portfolio auprès d'employeurs en "
        "cybersécurité, au Japon et à l'international."
    )

    pdf.output(str(OUTPUT))
    print(f"PDF generated: {OUTPUT}")


if __name__ == "__main__":
    build_pdf()
