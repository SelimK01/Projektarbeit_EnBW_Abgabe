import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import webbrowser
import os, sys, ctypes, json
import multiprocessing
from datetime import datetime
import webscraping as wsc

current_pid = os.getpid()
def check_for_updates(update_available_queue, root_destroyed):
    """
    Autor: Selim Karali
    Die Methode check_for_updates() prüft, ob ein Update für Metasploit verfügbar ist und führt das Update durch, falls ein Update verfügbar ist.
    Die Methode muss außerhalb der Klasse definiert werden um so genannte "pickle" Fehler zu vermeiden. Pickle ist ein Modul, das Objekte in Python serialisiert und deserialisiert.
    Dies ist aber nicht möglich, weil manche Objekte nicht serialisiert werden können, wie z.B. Methoden diese Methode.
    @param update_available_queue: Die Queue, in die das Ergebnis geschrieben wird, ob ein Update verfügbar ist um den Hauptprozess zu informieren
    @param root_destroyed: Das Event, das gesetzt wird, wenn das Hauptfenster geschlossen wird um die Prozesse zu beenden
    """
    from metasploit import Metasploit as msp 
    update_available = False 
    update_available = msp.update_metasploit_available()    # Es wird geprüft, ob ein Update verfügbar ist
    if update_available:                                    # Wenn ein Update verfügbar ist, wird das Update durchgeführt
        update_available_queue.put(update_available)        # Das Ergebnis wird in die Queue geschrieben, um den Hauptprozess zu informieren
        msp.update_metasploit()                             # Das Update wird durchgeführt
        update_exploits_json(root_destroyed)                # Die JSON-Datei mit den Exploits wird aktualisiert
    elif not os.path.exists("metasploit.json"):             # Wird ausgeführt, wenn die JSON-Datei nicht existiert
        update_available = True
        update_available_queue.put(update_available)        # Das Ergebnis wird in die Queue geschrieben, um den Hauptprozess zu informieren
        update_exploits_json(root_destroyed)                # Die JSON-Datei mit den Exploits wird aktualisiert
    else:
        update_available_queue.put(update_available)        # Wenn kein Update verfügbar ist, wird das Ergebnis in die Queue geschrieben

def update_exploits_json(root_destroyed):
    """
    Autor: Selim Karali
    Die Methode update_exploits_json() aktualisiert die JSON-Datei, die die Informationen über die Exploits enthält.
    @param root_destroyed: Das Event, das gesetzt wird, wenn das Hauptfenster geschlossen wird um die Prozesse zu beenden
    """
    from metasploit import Metasploit as msp
    update_steps = [msp.start_local_metasploit_server, msp.make_json, msp.stop_metasploit_server]
    
    for step in update_steps:
        if not root_destroyed.is_set():
            step()

class Data_Table_App():
    """
    Die Klasse Data_Table_App ist die Hauptklasse der Anwendung. Sie erstellt das Hauptfenster und die GUI-Elemente.
    """
    root_destroyed = multiprocessing.Event()            # Ein Event, das gesetzt wird, wenn das Hauptfenster geschlossen wird
    lock = multiprocessing.Lock()                       # Ein Lock, um die gemeinsame Nutzung von Ressourcen zu verhindern, in dem das Event root_destroyed gesetzt wird
    
    def __init__(self, root):
        """
        Autoren: Selim Karali, Adrian Graf
        Der Konstruktor der Klasse Data_Table_App erstellt das Hauptfenster und die GUI-Elemente. 
        Wobei zuerst ein Ladebildschirm angezeigt wird, während im Hintergrund geprüft wird, ob Updates verfügbar sind.
        @param root: Das Hauptfenster der Anwendung
        """
        root.protocol("WM_DELETE_WINDOW", self.before_closing)  # Die Methode before_closing wird aufgerufen, wenn das Hauptfenster geschlossen wird
        root.title("Frühwarnsystem für Cybergefahren")
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        position_top = int(screen_height / 2 - 200 / 2) 
        position_right = int(screen_width / 2 - 400 / 2)
        root.geometry(f"400x200+{position_right}+{position_top}")

        self.check_update_frame = tk.Frame(root)                # Der Ladebildschirm wird erstellt
        self.check_update_frame.place(relx=0.5, rely=0.5, anchor="center")
        label = tk.Label(self.check_update_frame, text="Überprüfen auf Updates...")
        label.pack(pady=20)
        root.update()
        self.set_metasploit_path()                              # Der Pfad zum metasploit-framework/bin Ordner wird abgefragt und gesetzt
        self.start_app()                                        # Die Methode start_app() wird aufgerufen, um die Anwendung zu starten
        if not self.get_root_destroyed():                       # Wenn das Hauptfenster nicht geschlossen wurde wird das Update-Fenster geschlossen, dies wird überprüft, um Fehlermeldungen zu vermeiden
            self.check_update_frame.destroy()                   # Der Ladebildschirm wird geschlossen

   
    def set_metasploit_path(self):
        """
        Autor: Selim Karali
        Die Methode set_metasploit_path() setzt den Pfad zum metasploit-framework/bin Ordner. Dieser wird benötigt, um die Metasploit-Instanz zu verwenden.
        """
        json_file = 'metasploit_path.json'
        json_file_path = os.path.join(os.getcwd(), json_file)    # Der Pfad zur JSON-Datei wird erstellt, diese ist im gleichen Ordner wie das Programm
        if os.path.exists(json_file_path):                       # Wenn die JSON-Datei existiert, wird der Pfad aus der JSON-Datei gelesen und gesetzt
            with open(json_file_path, 'r') as f:
                metasploit_path = json.load(f)['path']
            if not os.path.exists(metasploit_path):              
                os.remove(json_file_path)                        # Wenn der Pfad nicht existiert, wird die JSON-Datei gelöscht, der Pfad wird neu abgefragt und in die JSON-Datei geschrieben
                self.get_metasploit_path(json_file_path)         # Die Methode get_metasploit_path() wird aufgerufen, um den Pfad neu abzufragen
        else:                                                    
            self.get_metasploit_path(json_file_path)             # Wenn die JSON-Datei nicht existiert, wird die Methode get_metasploit_path() aufgerufen, um den Pfad abzufragen und in die JSON-Datei zu schreiben
        with open(json_file_path, 'r') as f:                    
            metasploit_path = json.load(f)['path'] 
        os.chdir(metasploit_path)                                # Es wird in den metasploit-framework/bin Ordner gewechselt, dies ist notwendig, um die Metasploit-Instanz zu verwenden
        ctypes.windll.kernel32.SetFileAttributesW(json_file_path, 2)  # Die JSON-Datei wird versteckt, da sie im Verzeichnis des Benutzers nicht sichtbar sein soll

    
    def get_metasploit_path(self, json_file_path):
        """
        Autor: Selim Karali
        Die Methode get_metasploit_path() fragt den Pfad zum metasploit-framework/bin Ordner ab und schreibt ihn in eine JSON-Datei.
        @param json_file_path: Der Pfad zur JSON-Datei
        
        """
        root.withdraw()                                                    # Das Hauptfenster wird versteckt, da ein neues Fenster geöffnet wird
        window = tk.Tk()
        window.protocol("WM_DELETE_WINDOW", sys.exit)                      # Damit das Programm beendet wird, wenn das Hauptfenster geschlossen wird
        window.title("Wählen Sie den metasploit-framework/bin Ordner aus") 
        window.eval('tk::PlaceWindow . center')

        label = tk.Label(window, text="Wählen Sie den metasploit-framework/bin Ordner aus.")
        label.pack(pady=20)

        def select_folder_and_make_json():
 
            while True:                                                                                         # Es wird solange nach dem Pfad gefragt, bis der richtige Ordner ausgewählt wurde
                folder_path = filedialog.askdirectory(title="Auswählen des metasploit-framework/bin Ordners")
                if folder_path is None or folder_path == "":                                                    # Wenn der Dialog geschlossen wird, wird das Programm beendet
                    sys.exit()  
                path_parts = os.path.split(folder_path)                                                         # Der ausgewählte Ordner wird die einzelnen Teile des Pfades aufgeteilt
                if path_parts[-1] != 'bin' or os.path.split(path_parts[0])[-1] != 'metasploit-framework':       # Es wird geprüft, ob der ausgewählte Ordner der 'bin' Ordner im 'metasploit-framework' Ordner ist
                    messagebox.showerror("Error", "Der ausgeählte Ordner ist nicht der 'bin' Ordner im 'metasploit-framework' Ordner. Bitte wählen Sie den 'bin' Ordner aus.")
                    continue

                with open(json_file_path, 'w') as f:                                                            # Der Pfad wird in die JSON-Datei geschrieben
                    json.dump({'path': folder_path}, f)

                ctypes.windll.kernel32.SetFileAttributesW(json_file_path, 2) 
                window.quit()                                                                                   # Stoppt durch das Schließen des Fensters die mainloop
                window.destroy()                                                                                # Das Fenster wird zerstört
                break
            root.deiconify()                                                                                    # Das Hauptfenster wird wieder sichtbar

        button = tk.Button(window, text="OK", command=select_folder_and_make_json, width=10)                    # Der "OK"-Button welcher das Fenster öffnet um den Ordner auszuwählen
        button.pack(pady=10) 

        window.mainloop()                                                                                       # Die mainloop des Fensters wird gestartet


    def start_app(self):
        """
        Autor: Selim Karali
        Die Methode start_app() startet die Anwendung und prüft, ob Updates verfügbar sind.
        """
        update_available_queue_metasploit = multiprocessing.Queue()                                             # Eine Queue, in die das Ergebnis geschrieben wird, ob ein Update für Metasploit verfügbar ist
        update_available_queue_bsi = multiprocessing.Queue()                                                    # Eine Queue, in die das Ergebnis geschrieben wird, ob ein Update für die BSI-Daten verfügbar ist
        
        global process_get_data_BSI
        process_get_data_BSI = multiprocessing.Process(target=wsc.get_data, args=(365,update_available_queue_bsi,)) # Der Prozess, der die BSI-Daten abfragt

        global process_metasploit_updates
        process_metasploit_updates = multiprocessing.Process(target=check_for_updates, args=(update_available_queue_metasploit, self.root_destroyed,)) # Der Prozess, der prüft, ob ein Update für Metasploit verfügbar ist

        process_get_data_BSI.start()                                                                         # Starten der Prozesse
        process_metasploit_updates.start()

        update_available_bsi, update_available_metasploit = False, False                                        # Die Variablen, die das Ergebnis des Update-Checks enthalten
        while update_available_queue_bsi.empty() and not self.get_root_destroyed():                             # Solange die Queue, welche das Ergebnis des Update-Checks für die BSI-Daten enthält, leer ist, wird das Hauptfenster aktualisiert
            root.update()
        
        if not self.get_root_destroyed():                                                                       # Wenn das Hauptfenster nicht geschlossen wurde, wird das Ergebnis aus der Queue gelesen
            update_available_bsi = update_available_queue_bsi.get()                                             # Das Ergebnis wird aus der Queue gelesen

        while update_available_queue_metasploit.empty() and not self.get_root_destroyed():                      # Das selbe wird für die Queue, welche das Ergebnis des Update-Checks für Metasploit enthält, durchgeführt
            root.update()

        if not self.get_root_destroyed():
            update_available_metasploit = update_available_queue_metasploit.get()

        if update_available_metasploit or update_available_bsi and not self.get_root_destroyed(): 
            update_window = self.open_update_window()                                                            # Wenn ein Update verfügbar ist, wird das Update-Fenster geöffnet
            while process_metasploit_updates.is_alive() or process_get_data_BSI.is_alive() and not self.get_root_destroyed(): # Solange die Prozesse noch am laufen sind, wird das Hauptfenster aktualisiert, damit es nicht einfriert
                root.update()
               
            if not self.get_root_destroyed():                                                                    # Wenn das Hauptfenster nicht geschlossen wurde, wird das Update-Fenster geschlossen, dies wird überprüft, um Fehlermeldungen zu vermeiden
                update_window.destroy()

        process_metasploit_updates.join()                                                                        # Die Prozesse münden wieder in den Hauptprozess, sobald sie beendet sind
        process_get_data_BSI.join() 

    def open_update_window(self):
        """
        Die Methode open_update_window() öffnet das Update-Fenster, wenn ein Update verfügbar ist.
        """  
        update_window = tk.Frame(root)                                                                           
        update_window.place(relx=0.5, rely=0.5, anchor="center")
        label = tk.Label(update_window, wraplength=400, text="Es ist ein Update verfügbar!\nBitte warten Sie bis das Update abgeschlossen ist.\nDies kann einige Minuten dauern.",justify='center', anchor='center' )
        label.pack(pady=20,anchor='center')
        update_window.pack(fill="both", expand=True)
        root.update()
        return update_window    

    def build_app(self):
        """
        Autoren: Maja Magschok, Adrian Graf
        Die Methode build_app() erstellt die App und die in ihr vorhandenen GUI-Elemente.
        """
        # BSI Teil
        root.title("Frühwarnsystem für Cybergefahren")
        root.state("zoomed")
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        cell_frame = tk.Frame(root)
        cell_frame.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.font_size=int(screen_height/1000*11)
        self.header_label = tk.Label(cell_frame, text="Neueste CVEs der letzten", font=("Helvetica", 16, "bold"))
        self.header_label.grid(row=0,column=0)

        self.entry_days = tk.Entry(cell_frame, width=5)
        self.entry_days.grid(row=0,column=1)
        self.entry_days.insert(0, "14")
        self.entry_days.bind('<Return>', lambda event: self.prepareData())

        self.header_label2 = tk.Label(cell_frame, text="Tage", font=("Helvetica", 16, "bold"))
        self.header_label2.grid(row=0,column=2)
        
        self.collect_button = tk.Button(cell_frame, text="Daten aktualisieren", command=self.prepareData)
        self.collect_button.grid(row=0,column=3,padx=10)

        self.progress_bar = ttk.Progressbar(cell_frame,mode="determinate")
        self.progress_bar.grid(row=0,column=4,padx=10)

        self.tree_BSI = ttk.Treeview(root, columns=("CVE Name", "CVE","Datum", "Trend","url"),
                                  show="headings")
        self.tree_BSI.grid(row=1,column=0,rowspan=5,columnspan=3)
        
        self.tree_BSI.heading("CVE Name", text="CVE Name")
        self.tree_BSI.column("CVE Name", anchor="w", width=int(screen_width*0.4))
        self.tree_BSI.heading("CVE", text="CVE")
        self.tree_BSI.column("CVE", anchor="w", width=int(screen_width*0.25))
        self.tree_BSI.heading("Datum", text="Datum")
        self.tree_BSI.column("Datum", anchor="center", width=int(screen_width*0.2))
        self.tree_BSI.heading("Trend", text="Trend")
        self.tree_BSI.column("Trend", anchor="center", width=int(screen_width*0.15))
        self.tree_BSI.heading("url", text="url")
        self.tree_BSI.column("url", anchor="center", width=0,minwidth=0)


        s = ttk.Style()
        s.configure('Treeview', rowheight=int(screen_height/50))
        self.tree_BSI.bind("<Double-1>", self.double_click_bsi)
        self.y_scrollbar_bsi = ttk.Scrollbar(root, orient="vertical", command=self.tree_BSI.yview)
        self.tree_BSI.configure(yscrollcommand=self.y_scrollbar_bsi.set)
        self.prepareData()
        
        # BSI und Metasploit Matching
        self.header_matches = tk.Label(root, text="Neueste CVEs mit Exploits", font=("Helvetica", 16, "bold"))
        self.header_matches.grid(row=6,column=0,padx=10, pady=20, sticky="w")
        self.tree_matches = ttk.Treeview(root, columns=("CVE Name","CVE Datum", "Exploit Name", "Disclosure Datum","CVE","Betroffene Programme","url","description"),
                                  show="headings")
        self.tree_matches.grid(row=7,column=0,rowspan=5,columnspan=3)
        self.tree_matches.heading("Exploit Name", text="Exploit Name")
        self.tree_matches.column("Exploit Name", anchor="w", width=int(screen_width*0.18))
        self.tree_matches.heading("Disclosure Datum", text="Disclosure Datum")
        self.tree_matches.column("Disclosure Datum", anchor="center", width=int(screen_width*0.075))
        self.tree_matches.heading("CVE Name", text="CVE Name")
        self.tree_matches.column("CVE Name", anchor="w", width=int(screen_width*0.3))
        self.tree_matches.heading("CVE Datum", text="CVE Datum")
        self.tree_matches.column("CVE Datum", anchor="center", width=int(screen_width*0.075))
        self.tree_matches.heading("CVE", text="CVE")
        self.tree_matches.column("CVE", anchor="center", width=int(screen_width*0.15))
        self.tree_matches.heading("Betroffene Programme", text="Betroffene Programme")
        self.tree_matches.column("Betroffene Programme", anchor="w", width=int(screen_width*0.22))
        self.tree_matches.heading("url", text="url")
        self.tree_matches.column("url", anchor="center", width=0,minwidth=0)
        self.tree_matches.heading("description", text="description")
        self.tree_matches.column("description", anchor="center", width=0,minwidth=0)
        self.y_scrollbar_exploits = ttk.Scrollbar(root, orient="vertical", command=self.tree_matches.yview)
        self.tree_matches.configure(yscrollcommand=self.y_scrollbar_exploits.set)
        self.tree_matches.bind("<Double-1>", self.double_click_matches)
        self.show_data_tree_matches()

        # Suche
        self.header_search = tk.Label(root, text="Suche", font=("Helvetica", 16, "bold"))
        self.header_search.grid(row=12,column=0,padx=10, pady=20, sticky="w")
        cell_frame2 = tk.Frame(root)
        cell_frame2.grid(row=13, column=0, padx=10, pady=10, sticky="w")
        options = ["Suche nach Exploits anhand Suchbegriff","Suche nach Exploits anhand von CVE-Nummer", "Suche nach CVEs anhand Suchbegriff"]
        self.selected_option = tk.StringVar()
        self.combobox = ttk.Combobox(cell_frame2, textvariable=self.selected_option, values=options, width=45, state="readonly")
        self.combobox.grid(row=0,column=0)
        self.combobox.set("Suche nach Exploits anhand Suchbegriff")
        self.combobox.bind('<<ComboboxSelected>>', self.on_combobox_selected)
        self.entry_term = tk.Entry(cell_frame2, width=30,fg="grey")
        self.entry_term.insert(0, "Suchbegriff eingeben")
        self.entry_term.bind('<FocusIn>', self.clear_entry)
        self.entry_term.bind('<FocusOut>', self.insert_placeholder)
        self.entry_term.bind('<Return>', lambda event: self.show_data_tree_search(self.entry_term.get()))
        self.entry_term.grid(row=0,column=1)
        self.search_button = tk.Button(cell_frame2, text="Suchen", command=lambda: self.show_data_tree_search(self.entry_term.get()))
        self.search_button.grid(row=0,column=2,padx=10)
        self.tree_search = ttk.Treeview(root, columns=("Name", "CVE","Datum","url","description"), show="headings")
        self.tree_search.grid(row=14,column=0,rowspan=3,columnspan=3)
        
        self.tree_search.heading("Name", text="Name")
        self.tree_search.column("Name", anchor="w", width=int(screen_width*0.5))
        self.tree_search.heading("CVE", text="CVE")
        self.tree_search.column("CVE", anchor="center", width=int(screen_width*0.3))
        self.tree_search.heading("Datum", text="Datum")
        self.tree_search.column("Datum", anchor="center", width=int(screen_width*0.2))
        self.tree_search.heading("url", text="url")
        self.tree_search.column("url", anchor="center", width=0,minwidth=0)
        self.tree_search.heading("description", text="url")
        self.tree_search.column("description", anchor="center", width=0,minwidth=0)
        self.tree_search.bind("<Double-1>", self.double_click_search)
    
    def on_combobox_selected(self, event=None):
        """
        Autor: Selim Karali
        Die Methode on_combobox_selected() wird aufgerufen, wenn ein Eintrag in der Combobox ausgewählt wird.
        Sie löscht die Tabelle und setzt den Platzhalter in das Eingabefeld.
        @param event: Das Event, das ausgelöst wird, wenn ein Eintrag in der Combobox ausgewählt wird
        """
        self.clear_table(event)
        self.update_placeholder(event)

    def clear_entry(self, event):
        """
        Autor: Selim Karali
        Die Methode clear_entry() löscht den Platzhalter im Eingabefeld, wenn das Eingabefeld angeklickt wird.
        @param event: Das Event, das ausgelöst wird, wenn das Eingabefeld angeklickt wird
        """
        if event.widget.get() == 'Suchbegriff eingeben' or event.widget.get() == 'CVE-XXXX-XXXXX': # Wenn der Platzhalter im Eingabefeld steht, wird er gelöscht
            event.widget.delete(0, tk.END) 
            event.widget.config(fg='black')                                                        # Die Schriftfarbe wird auf schwarz gesetzt, wenn der Platzhalter gelöscht wird, da dieser grau ist und die normale Schriftfarbe schwarz sein soll

    def insert_placeholder(self, event):
        """
        Autor: Selim Karali
        Die Methode insert_placeholder() setzt den benötigten Platzhalter in das Eingabefeld, wenn das Eingabefeld leer ist.
        @param event: Das Event, das ausgelöst wird, wenn das Eingabefeld verlassen wird
        """
        if event.widget.get() == '':
            if self.selected_option.get() == "Suche nach Exploits anhand von CVE-Nummer":          # Es wird überprüft, welcher Eintrag in der Combobox ausgewählt ist, um den passenden Platzhalter zu setzen
                event.widget.insert(0, "CVE-XXXX-XXXXX")
            else:
                event.widget.insert(0, "Suchbegriff eingeben")
            event.widget.config(fg='grey')

    def update_placeholder(self, event=None):
        """
        Autor: Selim Karali
        Die Methode update_placeholder() setzt den Platzhalter in das Eingabefeld, wenn das Eingabefeld leer ist.
        @param event: Das Event, das ausgelöst wird, wenn ein Eintrag in der Combobox ausgewählt wird
        """
        self.entry_term.delete(0, tk.END)
        if self.selected_option.get() == "Suche nach Exploits anhand von CVE-Nummer":               # Es wird überprüft, welcher Eintrag in der Combobox ausgewählt ist, um den passenden Platzhalter zu setzen
            self.entry_term.insert(0, "CVE-XXXX-XXXXX")
        else:
            self.entry_term.insert(0, "Suchbegriff eingeben")
        self.entry_term.config(fg='grey')                                                           # Die Schriftfarbe wird auf grau gesetzt, da der Platzhalter grau ist, im Gegensatz zur normalen Schriftfarbe, die schwarz ist

    def clear_table(self, event=None):
        """
        Autor: Selim Karali
        Die Methode clear_table() löscht die Tabelle, wenn ein anderer Eintrag in der Combobox ausgewählt wird.
        @param event: Das Event, das ausgelöst wird, wenn ein Eintrag in der Combobox ausgewählt wird
        """
        for i in self.tree_search.get_children():                                                   # Die Tabelle wird gelöscht
            self.tree_search.delete(i)

    def double_click_bsi(self, event):
        """
        Autor: Selim Karali, Adrian Graf
        Die Methode double_click_bsi() wird aufgerufen, wenn ein Eintrag in der BSI-Tabelle doppelt angeklickt wird.
        Sie öffnet die URL des Eintrags im Standard-Browser.
        @param event: Das Event, das ausgelöst wird, wenn ein Eintrag in der Tabelle doppelt angeklickt wird
        """
        item = self.tree_BSI.selection()                # Der ausgewählte Eintrag wird aus der Tabelle gelesen
        if item: 
            url = self.tree_BSI.item(item, "values")[4] # Die URL des Eintrags wird aus der Tabelle gelesen
            webbrowser.open(url, new=0, autoraise=True) # Die URL wird im Standard-Browser geöffnet

    def double_click_matches(self, event=None):
        """
        Autor: Selim Karali, Adrian Graf
        Die Methode double_click_matches() wird aufgerufen, wenn ein Eintrag in der Tabelle, der die CVEs mit Exploits enthält, doppelt angeklickt wird.
        Es wird ein neues Fenster geöffnet, das die Beschreibung des Exploits enthält und auch eine URL, falls vorhanden, für weitere Informationen.
        Sie öffnet die URL des Eintrags im Standard-Browser, wenn eine URL vorhanden ist und sie angeklickt wird.
        @param event: Das Event, das ausgelöst wird, wenn ein Eintrag in der Tabelle doppelt angeklickt wird
        """
        item = self.tree_matches.selection()
        if item:
            url = self.tree_matches.item(item, "values")[6] 
            description = self.tree_matches.item(item, "values")[7]
            popup = tk.Toplevel(root)                   # Ein neues Fenster wird geöffnet, das die Beschreibung des Exploits enthält
            popup.title("Exploit Beschreibung")
            popup.geometry("600x300")
            popup.resizable(True, True)                 # Das Fenster wird so eingestellt, dass es in der Größe verändert werden kann

            scroll = tk.Scrollbar(popup) 
            scroll.pack(side=tk.RIGHT, fill=tk.Y)

            text_widget = tk.Text(popup, height=10, width=60, font=("Helvetica", 12), yscrollcommand=scroll.set, wrap="word")
            text_widget.pack(padx=10, pady=10,expand=True, fill="both")
            text_widget.insert(tk.END, f"{description}\n\nURL: ") # Die Beschreibung des Exploits wird in das Fenster eingefügt	
            if not url == "No URL available": 
                text_widget.insert(tk.END, url, 'link')           # Wenn eine URL vorhanden ist, wird sie als link in das Fenster eingefügt
                text_widget.tag_config('link', foreground="blue", underline=True) 
            else:
                text_widget.insert(tk.END, url)                   # Wenn keine URL vorhanden ist, wird "No URL available" in das Fenster eingefügt
  
            text_widget.tag_bind('link', '<Button-1>', lambda e: webbrowser.open_new(url))        # Wenn die URL angeklickt wird, wird sie im Standard-Browser geöffnet
            text_widget.tag_bind('link', '<Enter>', lambda e: text_widget.config(cursor='hand2')) # Wenn die Maus über die URL bewegt wird, wird der Cursor zu einer Hand
            text_widget.tag_bind('link', '<Leave>', lambda e: text_widget.config(cursor=''))      # Wenn die Maus die URL verlässt, wird der Cursor wieder normal

            text_widget.config(state='disabled')                                                  # Der Inhalt des Fensters kann nicht verändert werden
            scroll.config(command=text_widget.yview)                                              # Das Scrollen im Fenster in der Y-Achse wird ermöglicht

            close_button = tk.Button(popup, text="Schließen", command=popup.destroy)              # Wenn der "Schließen"-Button angeklickt wird, wird das Fenster geschlossen
            close_button.pack(padx=10, pady=10) 

    def double_click_search(self, event=None):
        """
        Autor: Selim Karali, Adrian Graf
        Die Methode double_click_search() wird aufgerufen, wenn ein Eintrag in der Tabelle, die die Suchergebnisse enthält, doppelt angeklickt wird.
        Es wird ein neues Fenster geöffnet, das die Beschreibung des Exploits enthält und auch eine URL, falls vorhanden, für weitere Informationen.
        Sie öffnet die URL des Eintrags im Standard-Browser, wenn eine URL vorhanden ist und sie angeklickt wird.
        @param event: Das Event, das ausgelöst wird, wenn ein Eintrag in der Tabelle doppelt angeklickt wird
        """
        item = self.tree_search.selection()
        if item:
            url = self.tree_search.item(item, "values")[3]
            if self.selected_option.get() == "Suche nach CVEs anhand Suchbegriff":
                webbrowser.open(url, new=0, autoraise=True)
            else:
                
                description = self.tree_search.item(item, "values")[4]

                popup = tk.Toplevel(root)
                popup.title("Exploit Beschreibung")
                popup.geometry("600x300")
                popup.resizable(True, True) 

                scroll = tk.Scrollbar(popup)
                scroll.pack(side=tk.RIGHT, fill=tk.Y)
                text_widget = tk.Text(popup, height=10, width=60, font=("Helvetica", 12), yscrollcommand=scroll.set, wrap="word")
                text_widget.pack(padx=10, pady=10,expand=True, fill="both")
                text_widget.insert(tk.END, f"{description}\n\nURL: ")

                if not url == "No URL available":
                    text_widget.insert(tk.END, url, 'link')
                    text_widget.tag_config('link', foreground="blue", underline=True)
                else:
                    text_widget.insert(tk.END, url)

                text_widget.tag_bind('link', '<Button-1>', lambda e: webbrowser.open_new(url))
                text_widget.tag_bind('link', '<Enter>', lambda e: text_widget.config(cursor='hand2'))
                text_widget.tag_bind('link', '<Leave>', lambda e: text_widget.config(cursor=''))

                text_widget.config(state='disabled') 

                scroll.config(command=text_widget.yview)

                close_button = tk.Button(popup, text="Schließen", command=popup.destroy)
                close_button.pack(padx=10, pady=10)
        else:
            messagebox.showinfo("No Selection", "Please select an item.")    


    def show_data_tree_search(self, search_term):
        """
        Autor: Adrian Graf
        Die Methode show_data_tree_search() zeigt die Suchergebnisse in der Tabelle an.
        @param search_term: Der Suchbegriff, nach dem gesucht wird
        """
        from metasploit import Metasploit as msp
        type = self.selected_option.get()                   # Der ausgewählte Eintrag in der Combobox wird gelesen
        data = []
        if type == "Suche nach Exploits anhand Suchbegriff":
            data = msp.search_by_term_exploits(search_term) # Es wird nach Exploits anhand des Suchbegriffs gesucht
        elif type == "Suche nach CVEs anhand Suchbegriff":
            data = wsc.search_by_term_CVE(search_term)      # Es wird nach CVEs anhand des Suchbegriffs gesucht
        else:
            data = msp.search_by_CVE_exploits(search_term)           # Es wird nach Exploits anhand der CVE-Nummer gesucht
        if len(data) == 0:
            messagebox.showwarning("Achtung", "Keine Einträge für diesen Suchbegriff gefunden") # Wenn keine Einträge gefunden wurden, wird eine Warnung angezeigt
        for i in self.tree_search.get_children():                                               # Die Tabelle wird gelöscht, um die neuen Suchergebnisse anzuzeigen
            self.tree_search.delete(i)
        row_id = 0
        for entry in data:                                   # Die Suchergebnisse werden in die Tabelle eingefügt
            if row_id % 2 == 0: 
                tags = ('even',)                             # Die Zeilen werden als gerade markiert
            else:
                tags = ('odd',)                              # Die Zeilen werden als ungerade markiert
            if type == "Suche nach Exploits anhand Suchbegriff" or type == "Suche nach Exploits anhand von CVE-Nummer":   # Es wird überprüft, ob nach Exploits gesucht wurde, um die passenden Daten in die Tabelle einzufügen
                data_list = [entry["name"], entry["CVE"], entry["disclosure date"], entry["url"], entry["description"]] 
            else:                                                                                                         # Es wird überprüft, ob nach CVEs gesucht wurde, um die passenden Daten in die Tabelle einzufügen
                data_list = [entry["title"], entry["cve"], entry["date"], entry["url"]]
            self.tree_search.insert("", "end", values=data_list, tags=tags)
            row_id += 1
        font = ("", self.font_size)
        self.tree_search.tag_configure('odd', background='white', font=font)      # Die ungegeraden Zeilen werden weiß hinterlegt
        self.tree_search.tag_configure('even', background='lightgray', font=font) # Die geraden Zeilen werden hellgrau hinterlegt

    def prepareData(self):
        """
        Autor: Adrian Graf
        Die Methode prepareData() sammelt die Daten der BSI-Datenbank und ruft die Methode show_data_tree_BSI() auf, 
        um die Daten in der Tabelle anzuzeigen.
        """
        try:
            tage = int(self.entry_days.get())                                                           # Die Anzahl an Tagen, die in der App angegeben wurde, wird gelesen
            if tage > 90:
                messagebox.showwarning("Achtung", "Maximal 90 Tage möglich! Tage wurde auf 90 gesetzt") # Wenn die Anzahl an Tagen, die angegeben wurde, größer als 90 ist, wird eine Warnung angezeigt und die Anzahl auf 90 gesetzt
                tage = 90
        except:
            messagebox.showwarning("Achtung", "Bitte prüfe die angegebene Anzahl an Tagen!")            # Wenn die Anzahl an Tagen, die angegeben wurde, keine Zahl oder leer ist, wird eine Warnung angezeigt
            return
        self.progress_bar.start() 
        process_trend = multiprocessing.Process(target=wsc.determine_Trend, args=(tage,)) 
        process_trend.start()                                                                     # Der Prozess, der die Häufigkeit der CVEs in den letzten x Tagen abfragt, wird gestartet
        while process_trend.is_alive() and not self.get_root_destroyed():                         # Solange der Prozess noch am laufen ist, wird das Hauptfenster aktualisiert, damit es nicht einfriert
            root.update()
        process_trend.join()

        self.progress_bar.stop()
        self.show_data_tree_BSI(tage)                                                                   # Die Daten der BSI-Datenbank werden in der Tabelle angezeigt

    def show_data_tree_BSI(self, tage):
        """
        Autor: Adrian Graf
        Die Methode show_data_tree_BSI() zeigt die Daten der BSI-Datenbank in der Tabelle an.
        Falls ein Exploit zu einem CVE einer Zeile vorliegt, wird diese Zeile Rot gefärbt.
        @param tage: Die Anzahl an Tagen, für die die Daten angezeigt werden sollen
        """
        file_path = "data.json"
        try:
            with open(file_path, "r") as file:         # Die Daten der BSI-Datenbank werden aus der JSON-Datei gelesen
                existing_data = json.load(file)
        except FileNotFoundError:
                return
        for i in self.tree_BSI.get_children():         # Die Tabelle wird gelöscht, um die neuen Daten anzuzeigen
            self.tree_BSI.delete(i)
        aktuelles_datum_zeit = datetime.now() 
        datum_format = "%d.%m.%Y, %H:%M"
        row_id = 0
        for data_row in existing_data:                 # Die Daten der BSI-Datenbank werden in die Tabelle eingefügt
            if data_row["status"] == "UPDATE":         # Wenn der Status der Daten "UPDATE" ist, werden sie nicht in die Tabelle eingefügt, da nur neue CVEs angezeigt werden sollen
                continue
            gegebenes_datum = datetime.strptime(data_row["date"], datum_format) 
            differenz = aktuelles_datum_zeit - gegebenes_datum 
            if differenz.days < tage:                  # Es wird überprüft, ob das CVE-Datum in den letzten x Tagen liegt
                if row_id % 2 == 0: 
                    tags = ('even',)
                else:
                    tags = ('odd',)

                if wsc.exploit_for_CVE_exists(data_row["cve"]):                                 # Es wird überprüft, ob es für das CVE einen Exploit gibt
                    tags = ('exploit',) 

                data_list = [data_row["title"], data_row["cve"], data_row["date"], data_row["trend"],data_row["url"]]
                self.tree_BSI.insert("", "end", values=data_list, tags=tags)                    # Die Daten werden in die Tabelle eingefügt
                self.progress_bar["value"] = self.progress_bar["value"] + (1 / len(existing_data)) 
            else:
                break
            row_id += 1
        root.update()
        font = ("", self.font_size)
        self.tree_BSI.tag_configure('odd', background='white', font=font)      # Die ungeraden Zeilen werden weiß hinterlegt
        self.tree_BSI.tag_configure('even', background='lightgray', font=font) # Die geraden Zeilen werden hellgrau hinterlegt
        self.tree_BSI.tag_configure('exploit', background='red', font=font)    # Die Zeilen, die ein CVE mit Exploit enthalten, werden rot hinterlegt

    def show_data_tree_matches(self):
        """
        Autor: Adrian Graf
        Die Methode show_data_tree_matches() zeigt die Daten der BSI-Datenbank, die ein CVE mit Exploit enthalten, in der Tabelle an.
        """
        matching_exploits = wsc.get_all_exploits_matching_with_CVE_BSI()       # Die Daten der BSI-Datenbank, die ein CVE mit Exploit enthalten, werden abgefragt
        row_id = 0
        for exploit_and_data_BSI in matching_exploits:                         # Die Daten werden in die Tabelle eingefügt
            if row_id % 2 == 0:
                tags = ('even',)
            else:
                tags = ('odd',)
            data_list = [exploit_and_data_BSI[0], exploit_and_data_BSI[1], exploit_and_data_BSI[2], exploit_and_data_BSI[3],\
            exploit_and_data_BSI[4], exploit_and_data_BSI[5], exploit_and_data_BSI[6], exploit_and_data_BSI[7]]
            self.tree_matches.insert("", "end", values=data_list, tags=tags)
            row_id += 1
        font = ("", self.font_size)
        self.tree_matches.tag_configure('odd', background='white', font=font)
        self.tree_matches.tag_configure('even', background='lightgray', font=font)
    
    def before_closing(self):
        """
        Autor: Selim Karali
        Die Methode before_closing() wird automatisch aufgerufen, wenn das Hauptfenster geschlossen wird.
        Sie beendet alle Prozesse, die noch am laufen sind und schließt das Hauptfenster.
        """
        from metasploit import Metasploit as msp

        if root:                                    # Wenn das Hauptfenster noch existiert, wird es geschlossen
            root.destroy()
            self.set_root_destroyed_true()

        if process_metasploit_updates.is_alive():   # Wenn der Prozess, der prüft, ob ein Update für Metasploit verfügbar ist, noch am laufen ist, wird er beendet
            msp.stop_metasploit_server()
            process_metasploit_updates.terminate() 
            process_metasploit_updates.join()       # Es wird auf das joinen des Prozesses gewartet, weil manche Prozesse nicht sofort beendet werden, sobald terminate() aufgerufen wird

        if process_get_data_BSI.is_alive():         # Wenn der Prozess, der die BSI-Daten abfragt, noch am laufen ist, wird er beendet
            process_get_data_BSI.terminate()
            process_get_data_BSI.join()

    def get_root_destroyed(self):
        """
        Die Methode get_root_destroyed() gibt zurück, ob das Hauptfenster geschlossen wurde.
        @return: True, wenn das Hauptfenster geschlossen wurde, sonst False
        """
        return self.root_destroyed.is_set()

    def set_root_destroyed_true(self):
        """
        Die Methode set_root_destroyed_true() setzt das Attribut root_destroyed auf True.
        Mithilfe des Locks wird sichergestellt, dass das Attribut nur von einem Prozess geändert wird.
        """
        with self.lock:
           self.root_destroyed.set()


if __name__ == "__main__":              
    multiprocessing.freeze_support() # Die Methode freeze_support() wird aufgerufen, damit die Anwendung nicht mehrfach gestartet wird, wenn sie als .exe-Datei ausgeführt wird, da es durch das Modul multiprocessing zu Problemen kommen kann
    root = tk.Tk()                   # Das Hauptfenster wird erstellt
    app = Data_Table_App(root)       # Die Anwendung wird erstellt und die __init__-Methode wird aufgerufen
    if not app.get_root_destroyed(): # Wenn das Hauptfenster in der zwischenzeit nicht geschlossen wurde, wird die Anwendung gestartet
        app.build_app()              # Die App und ihre GUI-Elemente werden erstellt
    root.mainloop()                  # Die mainloop des Hauptfensters wird gestartet um die ganze Zeit auf Eingaben zu reagieren
