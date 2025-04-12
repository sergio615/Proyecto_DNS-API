#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import dns.resolver
import shodan
import requests
from threading import Thread
from typing import List, Dict, Tuple, Union

class DNSAuditorColombiaSimpleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Auditor Colombia")
        self.root.geometry("1400x800")
        
        # Configuración inicial
        try:
            from config import SHODAN_API_KEY
            self.api = shodan.Shodan(SHODAN_API_KEY)
            self.api_key_valid = True
        except ImportError:
            self.api_key_valid = False
            messagebox.showwarning("Configuración", "Crea un archivo config.py con tu API key de Shodan")
        
        # Dominios principales para prueba
        self.dominio_google = "google.com"
        self.dominio_facebook = "facebook.com"
        
        # Listas negras públicas
        self.listas_negras = [
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        ]
        
        # Filtro de país (CO = Colombia)
        self.pais_filtro = "CO"
        
        self.setup_ui()
        self.scan_active = False

    def setup_ui(self):
        # Frame de configuración
        config_frame = ttk.LabelFrame(self.root, text="Configuración", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(config_frame, text="Límite resultados:").grid(row=0, column=0, sticky=tk.W)
        self.limit_entry = ttk.Entry(config_frame, width=10)
        self.limit_entry.insert(0, "20")
        self.limit_entry.grid(row=0, column=1, padx=5, sticky=tk.W)

        # Frame de controles
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.start_btn = ttk.Button(control_frame, text="Iniciar Auditoría", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Detener", state=tk.DISABLED, command=self.stop_scan)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Frame de resultados
        results_frame = ttk.LabelFrame(self.root, text=f"Resultados DNS - Servidores en Colombia", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = (
            'IP', 'Organización', 
            'Resuelve Google', 'IPs Google',
            'Resuelve Facebook', 'IPs Facebook',
            'Lista Negra', 'Estado'
        )
        
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings')
        
        # Configurar columnas
        self.tree.heading('IP', text='Dirección IP')
        self.tree.heading('Organización', text='Organización')
        self.tree.heading('Resuelve Google', text='Resuelve Google')
        self.tree.heading('IPs Google', text='IPs Google')
        self.tree.heading('Resuelve Facebook', text='Resuelve Facebook')
        self.tree.heading('IPs Facebook', text='IPs Facebook')
        self.tree.heading('Lista Negra', text='Lista Negra')
        self.tree.heading('Estado', text='Estado')
        
        # Ajustar anchos de columnas
        self.tree.column('IP', width=150, anchor=tk.CENTER)
        self.tree.column('Organización', width=250, anchor=tk.W)
        self.tree.column('Resuelve Google', width=120, anchor=tk.CENTER)
        self.tree.column('IPs Google', width=180, anchor=tk.W)
        self.tree.column('Resuelve Facebook', width=120, anchor=tk.CENTER)
        self.tree.column('IPs Facebook', width=180, anchor=tk.W)
        self.tree.column('Lista Negra', width=120, anchor=tk.CENTER)
        self.tree.column('Estado', width=120, anchor=tk.CENTER)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Frame de logs
        log_frame = ttk.LabelFrame(self.root, text="Detalles de Ejecución", padding=10)
        log_frame.pack(fill=tk.BOTH, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Barra de estado
        self.status_var = tk.StringVar()
        self.status_var.set("Listo para comenzar - Filtro: Colombia (CO)")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, padx=10, pady=5)

    def log(self, message):
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.configure(state='disabled')
        self.log_text.see(tk.END)
        self.root.update()

    def start_scan(self):
        if not self.api_key_valid:
            messagebox.showerror("Error", "API key de Shodan no configurada")
            return

        self.clear_results()
        self.scan_active = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("Escaneo en progreso...")

        try:
            limit = int(self.limit_entry.get())
        except ValueError:
            limit = 20

        Thread(target=self.run_scan, args=(limit,), daemon=True).start()

    def stop_scan(self):
        self.scan_active = False
        self.status_var.set("Escaneo detenido por el usuario")

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')

    def run_scan(self, limit):
        try:
            self.log(f"Buscando servidores DNS en Colombia ({self.pais_filtro})...")
            ips_info = self.buscar_dns_colombia(limit)
            
            if not ips_info:
                self.log("No se encontraron servidores DNS en Colombia")
                messagebox.showinfo("Información", "No se encontraron servidores DNS en Colombia")
                return

            self.log(f"Encontradas {len(ips_info)} IPs con DNS expuesto en Colombia")

            for ip_info in ips_info:
                if not self.scan_active:
                    break

                ip = ip_info['ip_str']
                org = ip_info.get('org', 'Desconocido')
                self.log(f"\nAnalizando IP: {ip} ({org})")
                
                # 1. Verificación con Google
                resuelve_google, ips_google = self.verificar_resolucion_dns(ip, self.dominio_google)
                
                # 2. Verificación con Facebook
                resuelve_facebook, ips_facebook = self.verificar_resolucion_dns(ip, self.dominio_facebook)
                
                # 3. Verificación de lista negra
                en_blacklist = self.verificar_blacklist(ip)
                
                # Determinar estado general
                estado = "✅ Activo" if (resuelve_google or resuelve_facebook) else "❌ Inactivo"
                blacklist_status = "⚠️ Lista Negra" if en_blacklist else "✅ Limpia"
                if en_blacklist is None:
                    blacklist_status = "❓ Error"
                
                # Insertar en la tabla
                self.tree.insert('', tk.END, values=(
                    ip,
                    org,
                    "✅" if resuelve_google else "❌",
                    ", ".join(ips_google) if ips_google else "N/A",
                    "✅" if resuelve_facebook else "❌",
                    ", ".join(ips_facebook) if ips_facebook else "N/A",
                    blacklist_status,
                    estado
                ))
                
                # Log detallado
                self.log(f"Google: {'✅' if resuelve_google else '❌'} → {ips_google or 'Error'}")
                self.log(f"Facebook: {'✅' if resuelve_facebook else '❌'} → {ips_facebook or 'Error'}")
                self.log(f"Lista negra: {blacklist_status}")

                self.root.update()

            self.status_var.set(f"Escaneo completado - Servidores en Colombia: {len(ips_info)}")

        except Exception as e:
            self.log(f"[ERROR] {str(e)}")
            self.status_var.set(f"Error: {str(e)}")
        finally:
            self.scan_active = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def buscar_dns_colombia(self, limit: int) -> List[Dict]:
        """Busca solo servidores DNS en Colombia usando filtro de país"""
        try:
            # Filtro: puerto 53 y país CO (Colombia)
            resultados = self.api.search(f'port:53 country:"{self.pais_filtro}"', limit=limit)
            return resultados['matches']
        except shodan.APIError as e:
            self.log(f"Error en Shodan: {str(e)}")
            return []
        except Exception as e:
            self.log(f"Error inesperado: {str(e)}")
            return []

    def verificar_resolucion_dns(self, ip: str, dominio: str) -> Tuple[bool, List[str]]:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = 3
        resolver.lifetime = 3
        
        try:
            respuesta = resolver.resolve(dominio, 'A')
            return True, [r.to_text() for r in respuesta]
        except dns.resolver.NXDOMAIN:
            return False, ["Dominio no existe"]
        except dns.resolver.Timeout:
            return False, ["Timeout"]
        except dns.resolver.NoNameservers:
            return False, ["Sin servidores DNS"]
        except Exception as e:
            return False, [str(e)]

    def verificar_blacklist(self, ip: str) -> Union[bool, None]:
        try:
            for url in self.listas_negras:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        if ip in response.text.split('\n'):
                            return True
                except:
                    continue
            return False
        except Exception:
            return None

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSAuditorColombiaSimpleGUI(root)
    
    # Mostrar información inicial
    app.log("=== DNS Auditor Colombia ===")
    app.log(f"Filtro de país activado: Colombia ({app.pais_filtro})")
    app.log("Columnas principales:")
    app.log("- Resolución DNS para google.com")
    app.log("- Resolución DNS para facebook.com")
    app.log("- Verificación contra listas negras")
    app.log("\nNOTA: Solo para fines educativos y de investigación autorizada")
    
    root.mainloop()
