from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from msedge.selenium_tools import Edge, EdgeOptions
from datetime import datetime
import json,os, signal

"""
Autor: Adrian Graf
Das ganze Skript dient dazu, die Daten von der Webseite des BSI zu scrapen und in eine JSON-Datei zu speichern.
Es wird die Bibliothek Selenium verwendet, um die Daten zu scrapen. 
Zudem wird die Häufigkeit der Vorkommen von Sicherheitslücken analysiert und in die JSON-Datei gespeichert.
"""


def get_data(days, update_available_queue=None):
    """
    Die Methode get_data() scrapet die Daten von der Webseite des BSI und speichert sie in einer JSON-Datei.
    @param days: Die Anzahl der Tage, die zurückgegangen werden sollen
    @param update_available_queue: Die Queue, in der gespeichert werden soll, ob ein Update verfügbar ist
    """
    url = "https://wid.cert-bund.de/portal/wid/kurzinformationen"
    current_page = 1
    options = EdgeOptions()            # EdgeOptions() ist eine Klasse, die die Optionen für den Edge-Browser enthält
    options.use_chromium = True
    options.add_argument("--headless") # Der Browser wird im Hintergrund ausgeführt und nicht angezeigt
    driver = Edge(options=options, executable_path=EdgeChromiumDriverManager().install()) # Der Edge-Browser wird gestartet und die Optionen werden übergeben, zudem wird der Treiber für den Browser installiert, falls noch nicht vorhanden
    driver.get(url)                                                                       # Die Webseite wird aufgerufen
    wait = WebDriverWait(driver, 20)                                                      #  Die Zeit, die gewartet wird, bis ein Element erscheint
    existing_data = []
    new_data = []
    file_path = "data.json"
    loop = True
    try:                                    # Es wird überprüft, ob die Datei bereits existiert
        with open(file_path, "r") as file:
            existing_data = json.load(file)
    except FileNotFoundError:               # Falls die Datei nicht existiert, wird eine leere Liste erstellt und es wird dem Programm mitgeteilt, dass ein Update verfügbar ist
        existing_data = []
        update_available_queue.put(True)
    if len(existing_data) != 0:             # Es wird überprüft, ob bereits Daten vorhanden sind
        newest_entry = existing_data[0]     # Falls ja, wird das neueste Datum gespeichert
    else:
        newest_entry = {                    # Falls nicht, wird ein Dummy-Eintrag erstellt
            "title": "abc",
            "date": "13.12.2021",
            "cvss": "",
            "programs": "",
            "cve": "",
            "url": "",
            "status": ""
        }

    while loop:                             # Es wird solange durch die Seiten iteriert, bis die Daten der letzten 365 Tage gescraped wurden
        element = wait.until(EC.presence_of_element_located( # Es wird gewartet, bis die Tabelle mit allen CVEs geladen wurde
            (By.XPATH, '/html/body/portal-app/portal/div/portal-module/portal-content-wrapper/main/portal-page/portal-page-section/portal-component-instance/content-ui-wid-security-advisory-list/div/div/common-tables-table/div/div[3]/div/table/tbody')))
        date_format = "%d.%m.%Y, %H:%M"
        for row_number in range(1, 51):     # Es wird durch die Tabelle iteriert und die Daten werden gescraped
            xpath_date = f'tr[{row_number}]/td[1]/div/div'
            xpath_title = f'tr[{row_number}]/td[5]/div/div'
            xpath_cvss = f'tr[{row_number}]/td[3]/div/div'
            xpath_programs = f'tr[{row_number}]/td[6]/div/div'
            xpath_cve = f'tr[{row_number}]/td[7]/div/div'
            xpath_status = f'tr[{row_number}]/td[8]/div/div'
            xpath_id = f'tr[{row_number}]/td[4]/div/div'
            date = element.find_element(By.XPATH, xpath_date).get_attribute("textContent").strip() 
            if row_number == 1:             # Das Datum des ersten Eintrags auf der BSI-Seite wird gespeichert, um zu überprüfen, ob die Daten der letzten 365 Tage bereits gescraped wurden
                date_first_element = date
            status = element.find_element(By.XPATH, xpath_status).get_attribute("textContent").strip()  
            title = element.find_element(By.XPATH, xpath_title).get_attribute("textContent").strip()
            cvss = element.find_element(By.XPATH, xpath_cvss).get_attribute("textContent").strip()
            programs = element.find_element(By.XPATH, xpath_programs).get_attribute("textContent").strip()
            id = element.find_element(By.XPATH, xpath_id).get_attribute("textContent").strip()
            url = "https://wid.cert-bund.de/portal/wid/securityadvisory?name=" + id  # Die URL der BSI-Seite konkaketeniert mit der ID des Eintrags, ist die spezielle URL eines Eintrags
            if "..." in programs:                          # Es wird überprüft, ob ein "...", vorhanden ist, falls ja, wird es entfernt
                programs = programs.replace("...", "")     # Die "..." werden entfernt
                programs = programs.strip()                                          # Die Leerzeichen am Anfang und am Ende des Strings werden entfernt
            cve = element.find_element(By.XPATH, xpath_cve).get_attribute("textContent").strip() # Die CVE-Nummer wird gescraped
            if "..." in cve:                              # Es wird überprüft, ob ein "...", vorhanden ist, was darauf hinweist, dass es weitere CVE-Nummern gibt, welche jedoch auf einer ausführlicheren Seite zu finden sind
                cve = ""
                driver.execute_script("window.open('');")               # Ein neuer Tab wird geöffnet
                driver.switch_to.window(driver.window_handles[-1])      # Dem Browser wird mitgeteilt, dass er auf den neuen Tab wechseln soll
                driver.get(url)                                         # Die Seite wird im neuen Tab geladen
                xpath_expression_button=f'/html/body/portal-app/portal/div/portal-module/portal-content-wrapper/main/portal-page/portal-page-section/portal-component-instance/content-ui-wid-security-advisory-view/content-ui-public-content-view/content-ui-common-content-wrapper/div/content-ui-common-content-element-wrapper/div/div/content-ui-common-content-switch/content-ui-common-dynamic-content-type-view/div/content-ui-wid-expansion-panel[1]/div/a/content-ui-wid-extension-panel-title'
                button = wait.until(EC.presence_of_element_located((By.XPATH, xpath_expression_button)))
                driver.execute_script("arguments[0].scrollIntoView();", button)                     # Es wird zum Button gescrollt
                driver.execute_script("arguments[0].click();", button)                              # Der Button wird geklickt
                xpath_expression_cve = '/html/body/portal-app/portal/div/portal-module/portal-content-wrapper/main/portal-page/portal-page-section/portal-component-instance/content-ui-wid-security-advisory-view/content-ui-public-content-view/content-ui-common-content-wrapper/div/content-ui-common-content-element-wrapper/div/div/content-ui-common-content-switch/content-ui-common-dynamic-content-type-view/div/content-ui-wid-expansion-panel[1]/div/div/content-ui-common-content-element-wrapper/div/div/div/div/div'
                cves = wait.until(EC.presence_of_element_located( # Es wird gewartet, bis eie Tabelle mit allen CVEs geladen wurde
                    (By.XPATH, xpath_expression_cve)))
                cve=cves.get_attribute("textContent").strip()
                driver.close()                                                                                          # Der Tab wird geschlossen
                driver.switch_to.window(driver.window_handles[0])                                                       # Der Browser wechselt zurück zum ersten Tab
            entry = {                                                                                                   # Die gescrapeten Daten werden in ein Dictionary gespeichert
                "title": title,
                "date": date,
                "cvss": cvss,
                "programs": programs,
                "cve": cve,
                "url": url,
                "status": status
            }
            given_date = datetime.strptime(date, date_format)                                          # Das Datum wird in das deutsche Format umgewandelt
            current_date_time = datetime.now() 
            difference = current_date_time - given_date 
            if difference.days > days:                                                                 # Es wird überprüft, ob bereits Daten von den letzten 365 Tagen gescraped wurden und falls ja, wird die Schleife beendet
                loop = False
            else:                                                                                      # Falls nicht, werden die Daten in die Liste der neuen Daten hinzugefügt
                if newest_entry["title"] == entry["title"] and newest_entry["date"] == entry["date"]:
                    loop = False                                                                       # Nur wenn die Daten des neuesten Eintrags auf der BSI-Seite bereits in der JSON-Datei vorhanden sind, wird die Schleife beendet
                    update_available_queue.put(False)                                                  # Es wird dem Hauptprozess mitgeteilt, dass kein Update
                    break
            new_data.append(entry)
            update_available_queue.put(True)                                                           # Es wird dem Hauptprozess mitgeteilt, dass ein Update verfügbar ist, wenn der neueste Eintrag auf der BSI-Seite noch nicht in der JSON-Datei vorhanden ist
        xpath_button = f'/html/body/portal-app/portal/div/portal-module/portal-content-wrapper/main/portal-page/portal-page-section/portal-component-instance/content-ui-wid-security-advisory-list/div/div/common-tables-table/div/div[4]/common-table-pagination/div/ul/li[9]/a/button'
        button = driver.find_element(By.XPATH, xpath_button) 
        driver.execute_script("arguments[0].scrollIntoView();", button)
        driver.execute_script("arguments[0].click();", button)                                         # Es wird auf einen Button geklickt, um zur nächsten Seite zu gelangen, die weiteren Einträge enthält
        try:
            wait.until(
                lambda driver: element.find_element(By.XPATH, 'tr[1]/td[1]/div/div').get_attribute("textContent").strip() != date_first_element # Es wird gewartet, bis die Seite geladen wurde
            )
        except TimeoutException: 
            continue
        except StaleElementReferenceException: 
            continue
        current_page += 1
    whole_data = new_data + existing_data                                   # Die neuen Daten werden mit den bereits vorhandenen Daten zusammengefügt
    with open(file_path, "w") as file:                                      # Die Daten werden in die JSON-Datei geschrieben
        json.dump(whole_data, file, indent=4)                                  
    driver.quit()                                                           # Der Browser wird geschlossen                 
    os.kill(os.getpid(), signal.SIGTERM)                                    # Das Programm wird beendet

def exploit_for_CVE_exists(cve):
    """
    Die Methode exploit_for_CVE_exists() überprüft, ob ein Exploit für eine bestimmte CVE-Nummer existiert.
    @param cve: Die gesuchte CVE-Nummer
    @return: True, falls ein Exploit für die gesuchte CVE-Nummer existiert, ansonsten False
    """
    exploit_exists = False
    existing_exploits = []
    file_path = "metasploit.json"
    try:
        with open(file_path, "r") as file:
            existing_exploits = json.load(file)
    except FileNotFoundError:
        return
    cves = cve.split(", ")
    for exploit in existing_exploits:
        for currentcve in cves:
            if exploit["CVE"] == currentcve:
                exploit_exists = True
                break
    return exploit_exists

def get_all_exploits_matching_with_CVE_BSI():
    """
    Die Methode get_all_exploits_matching_with_CVE_BSI() gibt eine Liste von Exploit und CVE Paaren zurück.
    @return: Eine Liste von Exploit und CVE Paaren
    """
    matching_exploits = []
    existing_data = []
    existing_exploits = []
    file_path = "data.json"
    try:
        with open(file_path, "r") as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        return
    file_path = "metasploit.json"
    try:
        with open(file_path, "r") as file:
            existing_exploits = json.load(file)
    except FileNotFoundError:
        return
    for data in existing_data:
        cves = data["cve"].split(", ")
        for exploit in existing_exploits:           # Es wird durch die Exploits iteriert und geprüft, ob ein Exploit zu einer CVE-Nummer der BSI-Seite passt
            for cve in cves:
                if exploit["CVE"] == cve:
                    summary = [data["title"], data["date"], exploit["name"], exploit["disclosure date"], exploit["CVE"], data["programs"], exploit["url"], exploit["description"]]
                    matching_exploits.append(summary)
                    break
    return matching_exploits

def determine_Trend(tage): 
    """
    Die Methode determine_Trend() analysiert die Häufigkeit der Vorkommen von Sicherheitslücken und speichert den kalkulierten Trend in der JSON-Datei.
    @param tage: Die Anzahl der Tage, die für die Analyse berücksichtigt werden sollen
    """
    datum_format = "%d.%m.%Y, %H:%M" 
    categories_7_days = {}
    categories_28_days = {}
    fallend = 0
    gleich = 0
    steigend = 0
    neu = 0
    existing_data = []
    file_path = "data.json"
    try:
        with open(file_path, "r") as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        existing_data = []
    for data_row in existing_data: 
        if data_row["status"] == "UPDATE":      # Es wird überprüft, ob es sich um ein Update handelt, falls ja, wird der Eintrag übersprungen
            continue
        gegebenes_datum = datetime.strptime(data_row["date"], datum_format) 
        aktuelles_datum_zeit = datetime.now()
        differenz = aktuelles_datum_zeit - gegebenes_datum
        title = data_row["title"].split(":")[0].strip() 
        if differenz.days < tage:               # Es wird überprüft, ob das Datum des Eintrags innerhalb der letzten x Tage liegt
            if title in categories_7_days:      # Es wird überprüft, ob der Eintrag in den letzten 7 Tagen bereits vorgekommen ist
                categories_7_days[title] = categories_7_days[title] + 1 # Falls ja, wird die Anzahl der Vorkommen um 1 erhöht
            else:
                categories_7_days[title] = 1
        elif differenz.days < tage * 4: 
            if title in categories_28_days:
                categories_28_days[title] = categories_28_days[title] + 1 
            else:
                categories_28_days[title] = 1
        else:
            break

    for key in categories_7_days:
        trend = ""
        if key in categories_28_days:
            if categories_7_days[key] / categories_28_days[key] <= 0.33:
                trend = "fallend"
                fallend = fallend + 1
            elif categories_7_days[key] / categories_28_days[key] >= 1:
                trend = "steigend"
                steigend = steigend + 1
            else:
                gleich = gleich + 1
        count = 0
        for entry in existing_data:
            gegebenes_datum = datetime.strptime(entry["date"], datum_format)
            aktuelles_datum_zeit = datetime.now()
            differenz = aktuelles_datum_zeit - gegebenes_datum
            if differenz.days < 180:
                title = entry["title"].split(":")[0]
                if key == title:
                    count += 1
                    if count > 1:
                        break
            else:
                break
        if count == 1:
            trend = "Newcomer"
            neu = neu + 1
        else:
            gleich = gleich + 1
        for data_row in existing_data:
            if key in data_row["title"]:
                sum = 0
                if key in categories_28_days:
                    sum += categories_28_days[key]
                if key in categories_7_days:
                    sum += categories_7_days[key]
                if sum > tage:
                    trend = "Dauerbrenner"
                data_row["trend"] = trend
    with open(file_path, "w") as file:
        json.dump(existing_data, file, indent=4)

def search_by_term_CVE(search_term):
    """
    Die Methode search_by_term_CVE() gibt eine Liste von CVEs zurück, die ein bestimmtes Suchwort enthalten.
    @param search_term: Das gesuchte Wort
    @return: Eine Liste von CVEs die das gesuchte Wort enthalten
    """
    cves = []
    file_path = 'data.json'
    with open(file_path, 'r') as f:
        data = json.load(f)
    for cve in data:
        if search_term.lower() in cve["title"].lower():
            cves.append(cve)
    return cves