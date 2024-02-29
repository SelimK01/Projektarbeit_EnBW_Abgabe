import requests, re, subprocess, os, json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from pymetasploit3.msfrpc import MsfRpcClient
from time import sleep

class Metasploit():
    """
    Autor: Selim Karali
    Die Metasploit Klasse stellt Methoden zur Verfügung, um Metasploit zu aktualisieren,
    eine lokale Metasploit-Instanz zu starten, Informationen über Exploits zu erhalten und
    die lokale Metasploit-Instanz zu stoppen.
    """
    
    @staticmethod
    def get_latest_version():
        """
        Die Methode get_latest_version() gibt die neueste Version von Metasploit zurück.
        """
        url = 'https://windows.metasploit.com/LATEST'
        response = requests.get(url)
        html = BeautifulSoup(response.content, 'html.parser')  # Die Version wird aus dem HTML-Code extrahiert
        version_text = html.get_text()
        version_text = version_text.split('-')[2] 
        version_text = version_text.split('+')[0] 
        return version_text 
    
    @staticmethod
    def get_current_version(): 
        """
        Die Methode get_current_version() gibt die aktuelle Version von Metasploit zurück.
        """
        process = subprocess.Popen("msfconsole -v", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) # Die aktuelle Version wird aus der Konsole ausgelesen
        stdout, stderr = process.communicate()
        lines = stderr.decode("utf-8").splitlines()
        pattern = r'Framework Version: (\d+\.\d+\.\d+)' # Das Muster der Versionsnummer
        version_number = "Version not found"
        for line in lines:                              # Es wird durch die Zeilen der Ausgabe iteriert und die Versionsnummer gesucht 
            match = re.match(pattern, line)             # re.match() gibt None zurück, wenn kein Match gefunden wurde
            if match: 
                version_number = match.group(1)         
                break
            else:
                version_number = "Version not found"
        return version_number

    @staticmethod
    def update_metasploit_available():
        """
        Die Methode update_metasploit_available() gibt True zurück, wenn ein Update für Metasploit verfügbar ist, ansonsten False.
        """
        current_version = Metasploit.get_current_version()
        latest_version = Metasploit.get_latest_version()

        if current_version < latest_version:                                                    # Es wird geprüft, ob ein Update verfügbar ist
            return True

        return False
    
    @staticmethod
    def update_metasploit():
        """
        Die Methode update_metasploit() startet den Update-Prozess von Metasploit. 
        Durch ein Update kommen neue Exploits hinzu und bestehende Exploits werden verbessert.
        """
        subprocess.Popen("msfupdate", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) # Der Update-Prozess wird in der Konsole gestartet
        if os.path.exists('metasploit.json'):
            os.remove('metasploit.json')

    
    @staticmethod
    def start_local_metasploit_server():
        """
        Die Methode start_local_metasploit_server() startet einen lokalen Metasploit-Server.
        """
        subprocess.Popen("msfrpcd -P Passwort", shell=True)    # Die Metasploit-Instanz wird in der Konsole gestartet mit einem x-beliebigen Passwort
        connected = False
        while not connected:                                   # Es wird gewartet, bis die Verbindung zur Metasploit-Instanz hergestellt wurde
            global client 
            try:
                client = MsfRpcClient('Passwort', ssl=True)    # Es wird versucht, eine Verbindung zur Metasploit-Instanz herzustellen
                connected = True
            except:                                            # Wenn keine Verbindung hergestellt werden konnte, wird eine Sekunde gewartet und erneut versucht
                sleep(1)
                continue

    @staticmethod
    def make_json():
        """
        Die Methode make_json() erstellt eine JSON-Datei, die alle aktuell vorhandendenen Exploits von Metasploit enthält. 
        Die Exploits werden von der Netasploit-Community bereitgestellt und sind nicht immer vollständig und konsistent dokumentiert.
        Dadurch müssen beim parsen der Informationen viele Ausnahmenbehandlungen vorgenommen werden.
        """
        exploits_dictionary = []
        exploits = client.modules.exploits                     # Es werden alle Exploits von Metasploit abgerufen
        exploit_list = list(exploits)

        for exploit in exploit_list:                           # Es wird durch die Exploits iteriert und die Informationen zu jedem Exploit werden in ein Dictionary gespeichert
            try:
                info = client.modules.use('exploit',exploit)   # Es wird versucht, den Exploit zu laden
            except TypeError as e:                             # Wenn ein Exploit nicht geladen werden kann, wird fortgefahren, dies ist jedoch eine seltene Ausnahme
                continue
            url = "No URL available"
            cve = "No CVE assigned"
            if len(info.references)>1:                          # Es wird geprüft, ob eine URL verfügbar ist
                if info.references[1][1].startswith("http"):    # Es wird geprüft, ob dies wirklich eine URL ist, weil manchmal andere Informationen in der URL stehen, da diese Informationen von der Community bereitgestellt werden
                    url = info.references[1][1]
                else:                                           # Wenn keine URL verfügbar ist, wird nach einer URL gesucht, da sie manchmal an anderer Stelle im Array steht
                    for reference in info.references:
                        if reference[0] == "URL":
                            url = reference[1]
                            break
                        
            cve_pattern = r'^\b[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}\b$'      # Das Muster einer CVE-Nummer
        
            if len(info.references)>0:                                # Es wird geprüft, ob eine CVE-Nummer verfügbar ist
                if re.match(cve_pattern, str(info.references[0][1])): # Es wird geprüft, ob die Referenz eine CVE-Nummer ist
                    cve = "CVE-" + info.references[0][1]              # Wenn ja, wird die CVE-Nummer gespeichert und CVE- vorangestellt, da dies nicht dabei steht
                else:                                                 # Wenn keine CVE-Nummer verfügbar ist, wird nach einer CVE-Nummer gesucht, da sie manchmal an anderer Stelle im Array steht
                    for reference in info.references:
                        if reference[0] == "CVE":
                            cve = "CVE-" + reference[1]
                            break

            date = info.disclosuredate                               # Das Datum der Veröffentlichung des Exploits wird gespeichert

            if(len(date) == 10):                                      # Das Datum wird in das deutsche Format umgewandelt, falls ein Datum im Exploit verfügbar ist
                german_date = datetime.strptime(date, '%Y-%m-%d')
                date = german_date.strftime('%d.%m.%Y')
            else:                                                     # Wenn kein Datum verfügbar ist, wird "No date available" gespeichert
                date = "No date available"

            exploits_dictionary.append({                              # Die Informationen werden in ein Dictionary gespeichert
                "name": info.name,
                "CVE": cve,
                "disclosure date": date,
                "ranking": info.rank,
                "url": url,
                "description": info.description
            })

        file_path = 'metasploit.json'       # Die Informationen werden am Ende in eine JSON-Datei gespeichert
        if os.path.exists(file_path):       # Wenn die Datei bereits existiert, wird sie gelöscht
            os.remove(file_path)

        with open (file_path, 'w') as f:    # Die Informationen werden in die Datei geschrieben
            json.dump(exploits_dictionary, f, indent=4)

    @staticmethod
    def stop_metasploit_server():
        """
        Die Methode stop_metasploit_client() stoppt den lokalen Metasploit-Server.
        """
        process = subprocess.Popen("taskkill /F /IM ruby.exe", shell=True) # Die Metasploit-Instanz wird beendet, dies funktioniert nur durch beeenden der ruby Prozesse
        process.wait()                                                     # Es wird gewartet, bis die Prozesse beendet wurden


    @staticmethod
    def search_by_CVE_exploits(searched_CVE):
        """
        Die Methode search_by_CVE() gibt eine Liste von Exploits zurück, die zu einer bestimmten CVE-Nummer gehören.
        @param searched_CVE: Die gesuchte CVE-Nummer
        """
        exploits = []
        file_path = 'metasploit.json'
        with open(file_path, 'r') as f:                 # Die Informationen werden aus der JSON-Datei gelesen
            data = json.load(f) 
        for exploit in data:                            # Es wird durch die Exploits iteriert und geprüft, ob ein Exploit mit der gesuchten CVE-Nummer vorhanden ist
            if searched_CVE.lower() == exploit["CVE"].lower():
                exploits.append(exploit)                # Wenn ja, wird der Exploit in die Liste hinzugefügt
        return exploits

    
    @staticmethod
    def search_by_term_exploits(search_term): 
        """
        Die Methode search_by_term_exploits() gibt eine Liste von Exploits zurück, die ein bestimmtes Suchwort enthalten.
        @param search_term: Das gesuchte Wort
        """
        exploits=[]
        file_path = 'metasploit.json'
        with open (file_path, 'r') as f:
            data = json.load(f)
        for exploit in data:                            # Es wird durch die Exploits iteriert und geprüft, ob ein Exploit das gesuchte Wort enthält
            if search_term.lower() in exploit["name"].lower():
                exploits.append(exploit)
        return exploits
