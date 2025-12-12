import tkinter as tk
from tkinter import scrolledtext, ttk
import socket
import json
import threading
import time
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BIM437 - Güvenli Mesajlaşma İstemcisi")
        self.root.geometry("650x700")
        
        # --- DEĞİŞKENLER ---
        self.sock = None
        self.is_running = False
        self.master_key = None 
        self.fernet = None     
        
        # RSA Key Üretimi
        self.my_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.my_public_key = self.my_private_key.public_key()
        self.pem_public = self.my_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # --- ARAYÜZ ELEMANLARI ---
        self.create_widgets()

    def create_widgets(self):
        # 1. AYARLAR KISMI
        settings_frame = tk.LabelFrame(self.root, text="Bağlantı Ayarları", padx=10, pady=10)
        settings_frame.pack(fill="x", padx=10, pady=5)

        # Rol Seçimi
        tk.Label(settings_frame, text="Rol:").grid(row=0, column=0)
        self.role_var = tk.StringVar(value="B")
        ttk.Combobox(settings_frame, textvariable=self.role_var, values=["A (Başlatan)", "B (Dinleyen)"], width=15).grid(row=0, column=1)

        # IP Adresleri
        tk.Label(settings_frame, text="CA IP:").grid(row=1, column=0)
        self.entry_ca_ip = tk.Entry(settings_frame, width=15)
        self.entry_ca_ip.insert(0, "127.0.0.1")
        self.entry_ca_ip.grid(row=1, column=1)

        tk.Label(settings_frame, text="Hedef IP:").grid(row=1, column=2)
        self.entry_target_ip = tk.Entry(settings_frame, width=15)
        self.entry_target_ip.insert(0, "127.0.0.1") 
        self.entry_target_ip.grid(row=1, column=3)

        # BUTONLAR
        self.btn_connect = tk.Button(settings_frame, text="BAŞLAT", command=self.start_thread, bg="#4CAF50", fg="white", width=10)
        self.btn_connect.grid(row=0, column=4, rowspan=1, padx=5, pady=2)

        self.btn_disconnect = tk.Button(settings_frame, text="KES", command=self.disconnect, state="disabled", bg="#f44336", fg="white", width=10)
        self.btn_disconnect.grid(row=1, column=4, rowspan=1, padx=5, pady=2)

        # 2. LOG EKRANI
        self.log_area = scrolledtext.ScrolledText(self.root, state='disabled', height=20, bg="#f0f0f0")
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 3. MESAJLAŞMA KISMI
        chat_frame = tk.LabelFrame(self.root, text="Şifreli Sohbet (Master Key Gerekli)", padx=10, pady=10)
        chat_frame.pack(fill="x", padx=10, pady=10)

        self.msg_entry = tk.Entry(chat_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.msg_entry.bind("<Return>", self.send_chat_message)

        self.btn_send = tk.Button(chat_frame, text="GÖNDER", command=self.send_chat_message, state="disabled")
        self.btn_send.pack(side="right")

    def log(self, message):
        """Log ekranına yazı yazar"""
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def start_thread(self):
        """Bağlantıyı başlatır"""
        self.is_running = True
        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="normal")
        
        t = threading.Thread(target=self.run_logic)
        t.daemon = True
        t.start()

    def disconnect(self):
        """Bağlantıyı manuel olarak keser"""
        self.is_running = False
        self.log("[!] Bağlantı sonlandırılıyor...")
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        
        self.sock = None
        self.master_key = None
        self.fernet = None
        
        # Butonları sıfırla
        self.root.after(0, lambda: self.btn_connect.config(state="normal"))
        self.root.after(0, lambda: self.btn_disconnect.config(state="disabled"))
        self.root.after(0, lambda: self.btn_send.config(state="disabled", bg="SystemButtonFace", fg="black"))
        self.log("[!] Bağlantı kesildi ve ayarlar sıfırlandı.")

    # --- KRİPTOGRAFİK YARDIMCILAR ---
    def setup_fernet(self, master_key_str):
        key_hash = hashlib.sha256(master_key_str.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_hash)
        self.fernet = Fernet(fernet_key)
        self.master_key = master_key_str
        
        self.root.after(0, lambda: self.btn_send.config(state="normal", bg="#2196F3", fg="white"))
        self.log(f"\n[***] GÜVENLİ HAT OLUŞTURULDU! (AES Key Hazır)")

    def encrypt_rsa(self, pub_key_pem, message_bytes):
        loaded_pub = serialization.load_pem_public_key(pub_key_pem.encode('utf-8'))
        return loaded_pub.encrypt(
            message_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def decrypt_rsa(self, ciphertext):
        return self.my_private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    # --- AĞ VE PROTOKOL ---
    def run_logic(self):
        try:
            role = self.role_var.get().split()[0]
            ca_ip = self.entry_ca_ip.get()
            target_ip = self.entry_target_ip.get()
            
            my_port = 6000 if role == "A" else 6001
            target_port = 6001 if role == "A" else 6000
            client_id = f"Client_{role}"

            self.log(f"--- {client_id} Başlatılıyor (Port: {my_port}) ---")

            cert = self.get_certificate(ca_ip, client_id)
            if not cert:
                self.log("[-] CA Bağlantısı Başarısız. Yerel anahtarlarla devam ediliyor...")

            if role == "B":
                self.start_server_mode(my_port)
            else:
                self.start_client_mode(target_ip, target_port, client_id)
        except Exception as e:
            self.log(f"Genel Hata: {e}")
            self.disconnect()

    def get_certificate(self, ca_ip, client_id):
        self.log(f"[*] CA'ya bağlanılıyor ({ca_ip})...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ca_ip, 8000))
            
            req = json.dumps({"subject_id": client_id, "public_key": self.pem_public})
            s.send(req.encode())
            
            buffer = b""
            while True:
                try:
                    part = s.recv(4096)
                    if not part: break
                    buffer += part
                except socket.timeout:
                    break
            s.close()
            
            if not buffer: return None
            cert = json.loads(buffer.decode())
            self.log(f"[+] Sertifika Alındı. Serial: {cert.get('serial_number')}")
            return cert
        except Exception as e:
            self.log(f"[-] CA Hatası: {e}")
            return None

    def start_server_mode(self, port):
        """Client B (Responder)"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = s
        try:
            s.bind(('0.0.0.0', port))
            s.listen(1)
            self.log(f"[*] Dinleniyor... (Client A bekleniyor)")
            
            conn, addr = s.accept()
            self.sock = conn
            self.log(f"[+] Bağlantı Geldi: {addr}")

            initial = conn.recv(1024)
            if b"GIVE_ME_KEY" in initial:
                self.log("[*] Public Key gönderiliyor...")
                conn.send(self.pem_public.encode())
                self.handle_protocol_loop(conn, role="B")
            else:
                self.log("[-] Hatalı protokol.")
                conn.close()
        except OSError:
            pass # Disconnect için normal
        except Exception as e:
            self.log(f"[-] Sunucu hatası: {e}")

    def start_client_mode(self, ip, port, client_id):
        """Client A (Initiator)"""
        self.log(f"[*] {ip}:{port} hedefine bağlanılıyor...")
        
        s = None
        for i in range(10):
            if not self.is_running: return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5) # Bağlanırken timeout gerekli
                s.connect((ip, port))
                
                # --- KRİTİK DÜZELTME ---
                # Bağlandıktan sonra Timeout'u KAPATIYORUZ.
                # Yoksa 5 saniye mesaj gelmezse bağlantıyı keser.
                s.settimeout(None)
                # -----------------------
                
                self.sock = s
                break
            except Exception:
                self.log(f"   ...Deneme {i+1} başarısız. Bekleniyor...")
                time.sleep(2)
        
        if not s:
            self.log("[-] Hedefe ulaşılamadı.")
            self.disconnect()
            return

        try:
            s.send(b"GIVE_ME_KEY")
            target_pub_key = s.recv(8192).decode()
            
            if "BEGIN PUBLIC KEY" not in target_pub_key:
                self.log("[-] Anahtar alınamadı.")
                return

            self.log("[+] Key alındı. Senkronizasyon...")
            time.sleep(1)

            n1 = "NONCE_A_GUI"
            msg = f"{n1}||{client_id}"
            enc_msg = self.encrypt_rsa(target_pub_key, msg.encode())
            
            packet = json.dumps({
                "step": 1, 
                "payload": enc_msg.hex(), 
                "sender_pub_key": self.pem_public
            })
            s.send(packet.encode())
            
            self.handle_protocol_loop(s, role="A", target_pub_key=target_pub_key)

        except Exception as e:
            self.log(f"[-] İstemci Hatası: {e}")

    def handle_protocol_loop(self, conn, role, target_pub_key=None):
        try:
            while self.is_running:
                try:
                    data = conn.recv(8192)
                    if not data: break
                except OSError:
                    break

                try:
                    packet = json.loads(data.decode())
                except json.JSONDecodeError:
                    # Gelen veri bozuk veya birleşik olabilir, görmezden gel
                    continue
                
                if packet.get("type") == "CHAT":
                    enc_text = packet["payload"]
                    try:
                        decrypted_text = self.fernet.decrypt(enc_text.encode()).decode()
                        self.log(f"\n[GELEN]: {decrypted_text}")
                    except:
                        self.log("\n[HATA] Mesaj çözülemedi.")
                    continue
                
                step = packet.get("step")
                encrypted_bytes = bytes.fromhex(packet["payload"])
                sender_key_pem = packet.get("sender_pub_key")
                
                decrypted_msg = self.decrypt_rsa(encrypted_bytes).decode()

                if role == "B":
                    if step == 1:
                        parts = decrypted_msg.split("||")
                        self.log(f"-> Handshake N1: {parts[0]}")
                        
                        n2 = "NONCE_B_GUI"
                        reply = f"{parts[0]}||{n2}"
                        key_to_use = sender_key_pem if sender_key_pem else target_pub_key
                        enc_reply = self.encrypt_rsa(key_to_use, reply.encode())
                        
                        conn.send(json.dumps({
                            "step": 2, 
                            "payload": enc_reply.hex(), 
                            "sender_pub_key": self.pem_public
                        }).encode())
                        
                    elif step == 3:
                         self.log("-> Kimlik Doğrulama Başarılı.")
                         
                    elif step == 4:
                        self.log(f"-> MASTER KEY ALINDI.")
                        self.setup_fernet(decrypted_msg)

                elif role == "A":
                    if step == 2:
                        parts = decrypted_msg.split("||")
                        self.log(f"-> N2 Alındı: {parts[1]}")
                        
                        key_to_use = sender_key_pem if sender_key_pem else target_pub_key
                        enc_n2 = self.encrypt_rsa(key_to_use, parts[1].encode())
                        conn.send(json.dumps({"step": 3, "payload": enc_n2.hex()}).encode())
                        
                        time.sleep(0.5)
                        master_key = "IZU_SECURE_KEY_2025"
                        self.setup_fernet(master_key)
                        
                        enc_mk = self.encrypt_rsa(key_to_use, master_key.encode())
                        conn.send(json.dumps({"step": 4, "payload": enc_mk.hex()}).encode())
                        self.log(f"-> Master Key Gönderildi.")

        except Exception as e:
            if self.is_running:
                self.log(f"Bağlantı koptu: {e}")
        finally:
            self.disconnect()

    def send_chat_message(self, event=None):
        msg = self.msg_entry.get()
        if not msg or not self.fernet or not self.sock: return
        
        try:
            encrypted_token = self.fernet.encrypt(msg.encode()).decode()
            packet = json.dumps({"type": "CHAT", "payload": encrypted_token})
            self.sock.send(packet.encode())
            
            self.log(f"[SEN]: {msg}")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            self.log(f"Gönderme hatası: {e}")
            self.disconnect()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()