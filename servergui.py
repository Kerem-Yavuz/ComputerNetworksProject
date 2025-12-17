import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import sys
import os

class CAServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CA Sunucu Kontrol Paneli")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        # İşlem değişkeni
        self.process = None
        self.is_running = False

        self.create_widgets()

    def create_widgets(self):
        # --- ÜST PANEL (DURUM VE BUTONLAR) ---
        top_frame = tk.Frame(self.root, pady=10, padx=10, bg="#f0f0f0")
        top_frame.pack(fill="x")

        # Durum Etiketi
        self.lbl_status = tk.Label(top_frame, text="DURUM: KAPALI", fg="red", bg="#f0f0f0", font=("Arial", 12, "bold"))
        self.lbl_status.pack(side="left", padx=10)

        # Butonlar
        self.btn_stop = tk.Button(top_frame, text="DURDUR", command=self.stop_server, state="disabled", bg="#d9534f", fg="white", width=10)
        self.btn_stop.pack(side="right", padx=5)

        self.btn_start = tk.Button(top_frame, text="BAŞLAT", command=self.start_server, bg="#5cb85c", fg="white", width=10)
        self.btn_start.pack(side="right", padx=5)

        # --- ORTA PANEL (LOG EKRANI) ---
        log_frame = tk.Frame(self.root, padx=10, pady=5)
        log_frame.pack(fill="both", expand=True)

        tk.Label(log_frame, text="Sunucu Logları:", anchor="w").pack(fill="x")
        
        self.log_area = scrolledtext.ScrolledText(log_frame, state='disabled', height=15, bg="#2b2b2b", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True)

        # --- ALT PANEL (BİLGİ) ---
        bottom_frame = tk.Frame(self.root, pady=5, bg="#e0e0e0")
        bottom_frame.pack(fill="x")
        tk.Label(bottom_frame, text="Node.js: index.js | Port: 8000", bg="#e0e0e0", font=("Arial", 8)).pack()

    def log(self, message):
        """Log ekranına yazı yazar"""
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def start_server(self):
        if self.is_running:
            return

        # Node.js dosyasının varlığını kontrol et
        if not os.path.exists("index.js"):
            messagebox.showerror("Hata", "index.js dosyası bulunamadı!\nBu scripti index.js ile aynı klasöre koyun.")
            return

        try:
            self.process = subprocess.Popen(
                ["node", "index.js"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                encoding='utf-8', 
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            self.is_running = True
            self.btn_start.config(state="disabled")
            self.btn_stop.config(state="normal")
            self.lbl_status.config(text="DURUM: AÇIK", fg="green")
            self.log("--- Sunucu Başlatıldı ---")

            threading.Thread(target=self.read_output, args=(self.process.stdout,), daemon=True).start()
            threading.Thread(target=self.read_output, args=(self.process.stderr,), daemon=True).start()

        except Exception as e:
            messagebox.showerror("Hata", f"Node.js başlatılamadı.\n{e}")

    def stop_server(self):
        if self.process and self.is_running:
            try:
                self.process.terminate()
                self.process = None
            except:
                pass
            
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="DURUM: KAPALI", fg="red")
        self.log("--- Sunucu Durduruldu ---")

    def read_output(self, pipe):
        try:
            for line in iter(pipe.readline, ''):
                if line:
                    self.log(line.strip())
                else:
                    break
        except:
            pass
        finally:
            if self.is_running and (self.process is None or self.process.poll() is not None):
                self.root.after(0, self.stop_server)

    def on_closing(self):
        self.stop_server()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CAServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()