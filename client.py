import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import socket
import json
import threading
import time
import base64
import hashlib
import os

# Kriptografi Kütüphaneleri
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BIM437 - Güvenli İstemci (Protokol Uyumlu)")
        self.root.geometry("700x750")
        
        # --- DURUM DEĞİŞKENLERİ ---
        self.sock = None
        self.is_running = False
        self.internal_buffer = "" # JSON parçalama tamponu
        
        # Anahtarlar
        self.master_key_bytes = None
        self.session_key_bytes = None
        self.fernet = None
        
        # RSA Key Üretimi
        self.my_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.my_public_key = self.my_private_key.public_key()
        self.pem_public = self.my_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.my_certificate_json = None
        self.peer_certificate = None
        self.peer_public_key = None

        self.create_widgets()

    def create_widgets(self):
        # 1. AYARLAR
        settings_frame = tk.LabelFrame(self.root, text="Bağlantı Ayarları", padx=10, pady=10)
        settings_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(settings_frame, text="Rol:").grid(row=0, column=0)
        self.role_var = tk.StringVar(value="B")
        ttk.Combobox(settings_frame, textvariable=self.role_var, values=["A (Başlatan)", "B (Dinleyen)"], width=15).grid(row=0, column=1)

        tk.Label(settings_frame, text="CA IP:").grid(row=1, column=0)
        self.entry_ca_ip = tk.Entry(settings_frame, width=15)
        self.entry_ca_ip.insert(0, "127.0.0.1")
        self.entry_ca_ip.grid(row=1, column=1)

        tk.Label(settings_frame, text="Hedef IP:").grid(row=1, column=2)
        self.entry_target_ip = tk.Entry(settings_frame, width=15)
        self.entry_target_ip.insert(0, "127.0.0.1") 
        self.entry_target_ip.grid(row=1, column=3)

        self.btn_connect = tk.Button(settings_frame, text="BAŞLAT", command=self.start_thread, bg="#4CAF50", fg="white", width=10)
        self.btn_connect.grid(row=0, column=4, rowspan=2, padx=10)

        self.btn_disconnect = tk.Button(settings_frame, text="KES", command=self.disconnect, state="disabled", bg="#f44336", fg="white", width=10)
        self.btn_disconnect.grid(row=0, column=5, rowspan=2, padx=5)

        # 2. LOG EKRANI
        self.log_area = scrolledtext.ScrolledText(self.root, state='disabled', height=18, bg="#f0f0f0", font=("Consolas", 9))
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 3. MESAJLAŞMA
        chat_frame = tk.LabelFrame(self.root, text="Güvenli Sohbet (Session Key Ks)", padx=10, pady=10)
        chat_frame.pack(fill="x", padx=10, pady=10)

        self.msg_entry = tk.Entry(chat_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.msg_entry.bind("<Return>", self.send_chat_message)

        self.btn_send = tk.Button(chat_frame, text="GÖNDER", command=self.send_chat_message, state="disabled")
        self.btn_send.pack(side="right")

    def log(self, message):
        self.root.after(0, lambda: self._log_thread_safe(message))

    def _log_thread_safe(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def start_thread(self):
        self.is_running = True
        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="normal")
        t = threading.Thread(target=self.run_logic)
        t.daemon = True
        t.start()

    def disconnect(self):
        self.is_running = False
        self.internal_buffer = "" # Buffer temizle
        self.log("[!] Bağlantı sonlandırılıyor...")
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.sock = None
        self.fernet = None
        self.root.after(0, lambda: self.btn_connect.config(state="normal"))
        self.root.after(0, lambda: self.btn_disconnect.config(state="disabled"))
        self.root.after(0, lambda: self.btn_send.config(state="disabled"))

    # =========================================================================
    #  YENİ EKLENEN: GÜVENLİ PAKET ALICISI (EXTRA DATA HATASINI ÇÖZER)
    # =========================================================================
    def receive_packet(self, conn):
        """
        TCP akışından gelen birleşik JSON paketlerini ayıklar.
        'Extra data' hatasını engeller.
        """
        decoder = json.JSONDecoder()
        while self.is_running:
            # 1. Önce bufferda tam bir JSON var mı diye bak
            if self.internal_buffer:
                try:
                    # raw_decode stringin başından geçerli bir JSON objesi arar
                    # ve bittiği indexi döner.
                    obj, idx = decoder.raw_decode(self.internal_buffer)
                    # Okunan kısmı buffer'dan at, kalanı sakla
                    self.internal_buffer = self.internal_buffer[idx:].lstrip()
                    return obj
                except json.JSONDecodeError:
                    # Bufferda henüz tam bir JSON yok, devam et
                    pass
            
            # 2. Socketten yeni veri çek
            try:
                data = conn.recv(4096)
                if not data:
                    raise ConnectionResetError("Bağlantı koptu")
                self.internal_buffer += data.decode('utf-8', errors='ignore')
            except OSError:
                break
        return None

    # =========================================================================
    #  KRİPTOGRAFİK YARDIMCILAR
    # =========================================================================
    
    def encrypt_rsa(self, pub_key, message_bytes):
        return pub_key.encrypt(
            message_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def decrypt_rsa(self, ciphertext):
        return self.my_private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def sign_data(self, data_bytes):
        signature = self.my_private_key.sign(
            data_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, pub_key, data_bytes, signature_bytes):
        try:
            pub_key.verify(
                signature_bytes,
                data_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def verify_ca_certificate_logic(self, cert_dict):
        try:
            ca_pub_pem = cert_dict["ca_public_key"]
            ca_signature = base64.b64decode(cert_dict["ca_signature"])
            
            unsigned_cert = {
                "serial_number": cert_dict["serial_number"],
                "issuer": cert_dict["issuer"],
                "validity": cert_dict["validity"],
                "subject_id": cert_dict["subject_id"],
                "subject_public_key": cert_dict["subject_public_key"]
            }
            
            data_to_verify = json.dumps(unsigned_cert, separators=(',', ':')).encode('utf-8')
            ca_pub_obj = serialization.load_pem_public_key(ca_pub_pem.encode())
            
            if self.verify_signature(ca_pub_obj, data_to_verify, ca_signature):
                return True
            else:
                return False
        except Exception as e:
            self.log(f"Sertifika doğrulama hatası: {e}")
            return False

    def setup_fernet(self, key_bytes, is_session=False):
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        self.fernet = Fernet(fernet_key)
        type_str = "SESSION KEY (Ks)" if is_session else "MASTER KEY (Km)"
        self.log(f"[***] {type_str} KURULDU! Şifreli iletişim hazır.")
        self.root.after(0, lambda: self.btn_send.config(state="normal", bg="#2196F3", fg="white"))

    # =========================================================================
    #  AĞ VE PROTOKOL MANTIĞI
    # =========================================================================

    def run_logic(self):
        try:
            role = self.role_var.get().split()[0]
            ca_ip = self.entry_ca_ip.get()
            target_ip = self.entry_target_ip.get()
            my_port = 6000 if role == "A" else 6001
            target_port = 6001 if role == "A" else 6000
            my_id = f"Client_{role}"

            self.my_certificate_json = self.get_certificate_from_ca(ca_ip, my_id)
            if not self.my_certificate_json:
                self.log("[-] CA'dan sertifika alınamadı. İptal.")
                self.disconnect()
                return

            if role == "B":
                self.run_server_b(my_port, my_id)
            else:
                self.run_client_a(target_ip, target_port, my_id)

        except Exception as e:
            self.log(f"Genel Hata: {e}")
            self.disconnect()

    def get_certificate_from_ca(self, ca_ip, client_id):
        self.log(f"[*] CA ({ca_ip}) ile iletişim kuruluyor...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ca_ip, 8000))
            
            req = json.dumps({"subject_id": client_id, "public_key": self.pem_public})
            s.send(req.encode())
            
            buffer = b""
            while True:
                data = s.recv(4096)
                if not data: break
                buffer += data
            s.close()
            
            cert_str = buffer.decode()
            cert_dict = json.loads(cert_str)
            self.log(f"[+] Sertifika Alındı! Serial: {cert_dict.get('serial_number')}")
            return cert_str 
        except Exception as e:
            self.log(f"[-] CA Hatası: {e}")
            return None

    # -------------------------------------------------------------------------
    #  CLIENT B (RESPONDER)
    # -------------------------------------------------------------------------
    def run_server_b(self, port, my_id):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock = s
        try:
            s.bind(('0.0.0.0', port))
            s.listen(1)
            self.log(f"[*] Port {port} dinleniyor (Client A bekleniyor)...")
            
            conn, addr = s.accept()
            self.sock = conn
            self.log(f"[+] Bağlantı: {addr}")
            
            # 1. Sertifikaları Değiş
            conn.send(self.my_certificate_json.encode())
            
            # BURADA ARTIK receive_packet KULLANIYORUZ
            peer_cert_obj = self.receive_packet(conn)
            if not peer_cert_obj: return
            
            # JSON objesini stringe çevirip işlemcimize verelim (kod uyumu için)
            if not self.process_peer_certificate(json.dumps(peer_cert_obj)):
                return

            # Master Key Protokolü
            self.protocol_master_key_responder(conn, my_id)

        except OSError:
            pass
        except Exception as e:
            self.log(f"Sunucu Hatası: {e}")

    # -------------------------------------------------------------------------
    #  CLIENT A (INITIATOR)
    # -------------------------------------------------------------------------
    def run_client_a(self, ip, port, my_id):
        time.sleep(1) 
        self.log(f"[*] {ip}:{port} hedefine bağlanılıyor...")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, port))
            self.sock = s
            
            # 1. Sertifikaları Değiş
            peer_cert_obj = self.receive_packet(s)
            if not peer_cert_obj: return
            
            if not self.process_peer_certificate(json.dumps(peer_cert_obj)):
                return
            
            s.send(self.my_certificate_json.encode())

            # Master Key Protokolü
            self.protocol_master_key_initiator(s, my_id)

        except Exception as e:
            self.log(f"Bağlantı Hatası: {e}")

    # -------------------------------------------------------------------------
    #  ORTAK FONKSİYONLAR & PROTOKOL ADIMLARI
    # -------------------------------------------------------------------------
    
    def process_peer_certificate(self, cert_json_str):
        try:
            cert_dict = json.loads(cert_json_str)
            if not self.verify_ca_certificate_logic(cert_dict):
                self.log("[!] HATA: Karşı tarafın sertifikası CA tarafından doğrulanmadı! (Fake Cert)")
                self.disconnect()
                return False
            
            self.log(f"[✓] Karşı sertifika CA tarafından DOĞRULANDI. ({cert_dict['subject_id']})")
            pub_pem = cert_dict['subject_public_key']
            self.peer_public_key = serialization.load_pem_public_key(pub_pem.encode())
            self.peer_certificate = cert_dict
            return True
        except Exception as e:
            self.log(f"Sertifika işleme hatası: {e}")
            return False

    def protocol_master_key_initiator(self, conn, my_id):
        try:
            # ADIM 1: A -> B
            n1 = os.urandom(16).hex() 
            msg_1 = f"{n1}||{my_id}"
            enc_msg_1 = self.encrypt_rsa(self.peer_public_key, msg_1.encode())
            conn.send(json.dumps({"step": 1, "payload": enc_msg_1.hex()}).encode())
            self.log(f"-> [1] N1 gönderildi.")

            # ADIM 2: B -> A
            resp_2 = self.receive_packet(conn) # receive_packet
            dec_2 = self.decrypt_rsa(bytes.fromhex(resp_2["payload"])).decode()
            recv_n1, recv_n2 = dec_2.split("||")
            
            if recv_n1 != n1:
                self.log("[-] HATA: N1 eşleşmedi!")
                return
            self.log(f"<- [2] N2 alındı: {recv_n2}")

            # ADIM 3: A -> B
            enc_msg_3 = self.encrypt_rsa(self.peer_public_key, recv_n2.encode())
            conn.send(json.dumps({"step": 3, "payload": enc_msg_3.hex()}).encode())
            self.log(f"-> [3] N2 onayı yollandı.")
            
            # --- TCP COALESCING ÖNLEMEK İÇİN UFAK UYKU ---
            time.sleep(0.2)

            # ADIM 4: A -> B
            master_key = os.urandom(32)
            self.master_key_bytes = master_key
            signature = self.sign_data(master_key)
            enc_key = self.encrypt_rsa(self.peer_public_key, master_key)
            
            packet_4 = {
                "step": 4,
                "enc_key": enc_key.hex(),
                "signature": signature.hex()
            }
            conn.send(json.dumps(packet_4).encode())
            self.log(f"-> [4] Master Key yollandı.")
            
            time.sleep(0.2)
            
            self.protocol_session_key_initiator(conn, my_id)

        except Exception as e:
            self.log(f"Master Key Hatası (A): {e}")

    def protocol_master_key_responder(self, conn, my_id):
        try:
            # ADIM 1
            pkg_1 = self.receive_packet(conn)
            dec_1 = self.decrypt_rsa(bytes.fromhex(pkg_1["payload"])).decode()
            n1, id_a = dec_1.split("||")
            self.log(f"<- [1] Handshake başladı. {id_a}, N1: {n1}")

            # ADIM 2
            n2 = os.urandom(16).hex()
            msg_2 = f"{n1}||{n2}"
            enc_msg_2 = self.encrypt_rsa(self.peer_public_key, msg_2.encode())
            conn.send(json.dumps({"step": 2, "payload": enc_msg_2.hex()}).encode())
            self.log(f"-> [2] N1 ve N2 gönderildi.")

            # ADIM 3
            pkg_3 = self.receive_packet(conn)
            dec_3 = self.decrypt_rsa(bytes.fromhex(pkg_3["payload"])).decode()
            if dec_3 != n2:
                self.log("[-] HATA: N2 doğrulaması başarısız!")
                return
            self.log("<- [3] N2 doğrulandı.")

            # ADIM 4
            pkg_4 = self.receive_packet(conn)
            enc_mk = bytes.fromhex(pkg_4["enc_key"])
            signature = bytes.fromhex(pkg_4["signature"])
            
            master_key = self.decrypt_rsa(enc_mk)
            if self.verify_signature(self.peer_public_key, master_key, signature):
                self.master_key_bytes = master_key
                self.log("[✓] Master Key alındı ve doğrulandı.")
                self.protocol_session_key_responder(conn, my_id)
            else:
                self.log("[-] HATA: Master Key imzası geçersiz!")
                self.disconnect()

        except Exception as e:
            self.log(f"Master Key Hatası (B): {e}")

    # -------------------------------------------------------------------------
    #  DIAGRAM 3: SESSION KEY
    # -------------------------------------------------------------------------
    
    def simple_hash_f(self, nonce_str):
        return hashlib.sha256(nonce_str.encode()).hexdigest()[:16]

    def protocol_session_key_initiator(self, conn, my_id):
        try:
            temp_fernet = Fernet(base64.urlsafe_b64encode(self.master_key_bytes))
            
            # ADIM 1
            n1 = os.urandom(8).hex()
            msg_1 = f"{my_id}||{n1}"
            conn.send(json.dumps({"s_step": 1, "payload": msg_1}).encode())
            
            # ADIM 2
            pkg_2 = self.receive_packet(conn)
            enc_payload = pkg_2["payload"]
            dec_payload = temp_fernet.decrypt(enc_payload.encode()).decode()
            
            parts = dec_payload.split("||")
            ks_hex = parts[0]
            f_n1 = parts[3]
            n2 = parts[4]
            
            if f_n1 != self.simple_hash_f(n1):
                self.log("[-] Session Handshake: N1 hash uyuşmadı!")
                return
            
            self.session_key_bytes = bytes.fromhex(ks_hex)
            self.setup_fernet(self.session_key_bytes, is_session=True)
            
            # ADIM 3
            f_n2 = self.simple_hash_f(n2)
            enc_fin = self.fernet.encrypt(f_n2.encode()).decode()
            conn.send(json.dumps({"s_step": 3, "payload": enc_fin}).encode())
            
            self.chat_loop(conn)

        except Exception as e:
            self.log(f"Session Key Hatası (A): {e}")

    def protocol_session_key_responder(self, conn, my_id):
        try:
            temp_fernet = Fernet(base64.urlsafe_b64encode(self.master_key_bytes))
            
            # ADIM 1
            pkg_1 = self.receive_packet(conn)
            id_a, n1 = pkg_1["payload"].split("||")
            
            # ADIM 2
            session_key = os.urandom(32)
            self.session_key_bytes = session_key
            n2 = os.urandom(8).hex()
            f_n1 = self.simple_hash_f(n1)
            
            raw_payload = f"{session_key.hex()}||{id_a}||{my_id}||{f_n1}||{n2}"
            enc_payload = temp_fernet.encrypt(raw_payload.encode()).decode()
            
            conn.send(json.dumps({"s_step": 2, "payload": enc_payload}).encode())
            
            self.setup_fernet(self.session_key_bytes, is_session=True)
            
            # ADIM 3
            pkg_3 = self.receive_packet(conn)
            enc_fin = pkg_3["payload"]
            dec_fin = self.fernet.decrypt(enc_fin.encode()).decode()
            
            if dec_fin == self.simple_hash_f(n2):
                self.log("[✓] Session Key Handshake tamamlandı. Sohbet Başlıyor.")
                self.chat_loop(conn)
            else:
                self.log("[-] Session Key doğrulaması başarısız.")

        except Exception as e:
            self.log(f"Session Key Hatası (B): {e}")

    def chat_loop(self, conn):
        while self.is_running:
            try:
                pkg = self.receive_packet(conn)
                if not pkg: break
                
                if pkg.get("type") == "CHAT":
                    try:
                        dec_msg = self.fernet.decrypt(pkg["payload"].encode()).decode()
                        self.log(f"\n[GELEN]: {dec_msg}")
                    except:
                        self.log("[!] Şifre çözme hatası.")
            except:
                break
        self.disconnect()

    def send_chat_message(self, event=None):
        msg = self.msg_entry.get()
        if not msg or not self.fernet or not self.sock: return
        
        try:
            enc = self.fernet.encrypt(msg.encode()).decode()
            self.sock.send(json.dumps({"type": "CHAT", "payload": enc}).encode())
            self.log(f"[SEN]: {msg}")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            self.log(f"Gönderme hatası: {e}")
            self.disconnect()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.disconnect)
    root.mainloop()