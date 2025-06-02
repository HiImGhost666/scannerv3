#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MÃ³dulo de interfaz grÃ¡fica para la herramienta de escaneo de red (adaptado para miproyectored)

Este mÃ³dulo implementa la interfaz grÃ¡fica de usuario utilizando ttkbootstrap
para mostrar y controlar el escaneo de red.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import threading
import time
import os
import sys
import logging
import socket
import sqlite3
import webbrowser
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from PIL import Image, ImageTk  # AÃ±adido para manejar imÃ¡genes

# Importar mÃ³dulos del proyecto miproyectored
from miproyectored.scanner.nmap_scanner import NmapScanner
from miproyectored.scanner.wmi_scanner import WmiScanner
from miproyectored.scanner.ssh_scanner import SshScanner
from miproyectored.scanner.snmp_scanner import SnmpScanner
from miproyectored.model.device import Device
from miproyectored.risk.risk_analyzer import RiskAnalyzer
from miproyectored.inventory.inventory_manager import InventoryManager
from miproyectored.export import csv_exporter, json_exporter, html_exporter
from miproyectored.auth.network_credentials import NetworkCredentials
# Importar nuevos mÃ³dulos para escaneo detallado

# ConfiguraciÃ³n del sistema de logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    log_file_path = os.path.join(os.path.dirname(__file__), 'network_scanner_gui.log')
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

class NetworkScannerGUI(ttk.Window):
    """
    Clase principal para la interfaz grÃ¡fica de la herramienta de escaneo de red.
    """
    def __init__(self):
        """Inicializa la interfaz grÃ¡fica."""
        try:
            # DefiniciÃ³n de colores corporativos
            self.COLORES = {
                'azul_oscuro': "#091F2C",    # Pantone 5395 C (color primario)
                'rojo': "#C10016",           # Pantone 3517 C (color primario)
                'purpura_suave': "#B4B5DF",  # Pantone 270 C (complementario)
                'azul_medio': "#7A99AC",     # Pantone 5425 C (complementario)
                'azul_claro': "#A6BBC8",     # Pantone 5435 C (complementario)
                'blanco': "#FFFFFF"
            }
            
            # Inicializar con un tema existente
            super().__init__(themename="litera")
            
            # Personalizar el tema con colores corporativos
            self._apply_corporate_colors()
            
            self.title("Herramienta de Escaneo de Red - MiProyectoRed")
            self.geometry("1300x750") # Aumentado el tamaÃ±o para mÃ¡s detalles
            self.minsize(1000, 600)

            self.nmap_scanner = NmapScanner() # Usar NmapScanner del proyecto
            self.risk_analyzer = RiskAnalyzer() # Usar RiskAnalyzer del proyecto

            # Inicializar escÃ¡neres especÃ­ficos
            self.wmi_scanner = WmiScanner()
            self.ssh_scanner = SshScanner()
            self.snmp_scanner = SnmpScanner()

            # Inicializar base de datos
            self.inventory_manager = InventoryManager()

            # Variables para almacenar los resultados del escaneo
            self.scan_results: List[Device] = []
            self.filtered_results: List[Device] = []
            self.selected_device_ip: Optional[str] = None

            # Variable para el arrastre de columnas
            self._drag_data = {"x": 0, "y": 0, "item": None}

            # Contadores para tipos de dispositivos
            self.windows_devices_count = 0
            self.linux_devices_count = 0
            self.snmp_devices_count = 0

            # Variables para las credenciales
            self.ssh_username = ttk.StringVar()
            self.ssh_password = ttk.StringVar()
            self.ssh_key_file = ttk.StringVar()
            self.snmp_community = ttk.StringVar(value="public") # Valor por defecto para SNMP
            self.wmi_username = ttk.StringVar()
            self.wmi_password = ttk.StringVar()
            self.wmi_domain = ttk.StringVar() # AÃ±adido para WMI

            # Variable para habilitar/deshabilitar escaneo WMI
            self.wmi_scan_enabled = ttk.BooleanVar(value=False)

            # Variable para habilitar/deshabilitar escaneo automÃ¡tico
            self.auto_scan_enabled = ttk.BooleanVar(value=True)

            self.network_range = ttk.StringVar(value=self._get_local_network_range())

            self.search_filter = ttk.StringVar()
            self.search_filter.trace_add("write", self._apply_filter)

            self.scan_status = ttk.StringVar(value="Listo para escanear.")

            self._create_widgets()

            self.protocol("WM_DELETE_WINDOW", self._on_closing)

            logger.info("Interfaz grÃ¡fica inicializada correctamente")
        except Exception as e:
            logger.error(f"Error al inicializar la interfaz grÃ¡fica: {e}", exc_info=True)
            messagebox.showerror("Error de InicializaciÃ³n", f"Error al inicializar la aplicaciÃ³n: {e}")
            self.destroy()

    def _apply_corporate_colors(self):
        """Aplica los colores corporativos al tema actual"""
        style = ttk.Style()

        # Configurar colores base
        style.configure("TButton",
                        background=self.COLORES['azul_oscuro'],
                        foreground=self.COLORES['blanco'])

        style.configure("TLabel",
                        foreground=self.COLORES['azul_oscuro'])

        style.configure("TFrame",
                        background=self.COLORES['blanco'])

        style.configure("TLabelframe",
                        background=self.COLORES['blanco'],
                        foreground=self.COLORES['azul_oscuro'])

        style.configure("TLabelframe.Label",
                        foreground=self.COLORES['azul_oscuro'],
                        font=('TkDefaultFont', 10, 'bold'))

        # Configurar Treeview
        style.configure("Treeview",
                        background=self.COLORES['blanco'],
                        foreground=self.COLORES['azul_oscuro'],
                        fieldbackground=self.COLORES['blanco'])

        style.configure("Treeview.Heading",
                        background=self.COLORES['azul_oscuro'],
                        foreground=self.COLORES['blanco'],
                        font=('TkDefaultFont', 10, 'bold'))

        style.map("Treeview",
                  background=[('selected', self.COLORES['azul_medio'])],
                  foreground=[('selected', self.COLORES['blanco'])])

        # Configurar Notebook
        style.configure("TNotebook",
                        background=self.COLORES['blanco'])

        style.configure("TNotebook.Tab",
                        background=self.COLORES['azul_claro'],
                        foreground=self.COLORES['azul_oscuro'],
                        padding=[10, 2])

        style.map("TNotebook.Tab",
                  background=[('selected', self.COLORES['azul_medio'])],
                  foreground=[('selected', self.COLORES['blanco'])])

        # Configurar Entry
        style.configure("TEntry",
                        foreground=self.COLORES['azul_oscuro'])

        # Estilos especÃ­ficos
        style.configure("Section.TLabel",
                        font=('TkDefaultFont', 11, 'bold'),
                        foreground=self.COLORES['azul_oscuro'])

        # Botones especiales
        style.configure("Primary.TButton",
                        background=self.COLORES['azul_oscuro'],
                        foreground=self.COLORES['blanco'])

        style.configure("Action.TButton",
                        background=self.COLORES['rojo'],
                        foreground=self.COLORES['blanco'])

        # Botones de estado
        style.configure("success.TButton",
                        background=self.COLORES['rojo'],
                        foreground=self.COLORES['blanco'])

        style.configure("info.TButton",
                        background=self.COLORES['azul_medio'],
                        foreground=self.COLORES['blanco'])

        # Checkbutton
        style.configure("round-toggle.Toolbutton",
                        background=self.COLORES['azul_claro'],
                        foreground=self.COLORES['azul_oscuro'])

        style.map("round-toggle.Toolbutton",
                  background=[('selected', self.COLORES['azul_medio'])],
                  foreground=[('selected', self.COLORES['blanco'])])

    def _get_local_network_range(self) -> str:
        """Intenta detectar el rango de red local (ej. 192.168.1.0/24)."""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)

            if local_ip.startswith("127."): # IP de Loopback, no Ãºtil para escanear la LAN
                # Intenta obtener una IP no loopback conectÃ¡ndose a un host externo (dummy)
                # Esto ayuda a identificar la interfaz de red principal usada para salir.
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.1) # Timeout corto para no bloquear mucho
                try:
                    s.connect(('10.254.254.254', 1)) # IP dummy, no necesita ser alcanzable
                    local_ip = s.getsockname()[0]
                except Exception:
                    logger.warning("No se pudo determinar la IP no-loopback mediante conexiÃ³n dummy. Usando IP de hostname si es vÃ¡lida.")
                    # Re-evaluar la IP del hostname, podrÃ­a ser una IP de LAN si hay mÃºltiples interfaces
                    local_ip = socket.gethostbyname(hostname) # Obtener de nuevo por si acaso
                    if local_ip.startswith("127."): # Si sigue siendo loopback
                        logger.warning("La IP del hostname sigue siendo loopback. Usando rango por defecto.")
                        return "192.168.1.0/24" # Fallback a un rango comÃºn
                finally:
                    s.close()

            if local_ip and not local_ip.startswith("127."):
                ip_parts = local_ip.split('.')
                if len(ip_parts) == 4: # Asegurarse de que es una IPv4 vÃ¡lida
                    network_base = ".".join(ip_parts[:3])
                    detected_range = f"{network_base}.0/24"
                    logger.info(f"Rango de red local detectado: {detected_range}")
                    return detected_range
                else:
                    logger.warning(f"Formato de IP local inesperado: {local_ip}. Usando rango por defecto.")
            else:
                logger.warning(f"No se pudo determinar una IP local adecuada (IP actual: {local_ip}). Usando rango por defecto.")

        except socket.gaierror:
            logger.error("Error al obtener hostname o IP (gaierror). La red podrÃ­a estar desconectada o mal configurada. Usando rango por defecto.", exc_info=False)
        except Exception as e:
            logger.error(f"Error inesperado al detectar la red local: {e}. Usando rango por defecto.", exc_info=True)

        return "192.168.1.0/24" # Rango por defecto como fallback

    def _create_widgets(self):
        """Crea los widgets de la interfaz grÃ¡fica."""
        # Crear la barra de menÃº principal
        self._create_menu_bar()

        main_pane = ttk.PanedWindow(self, orient=HORIZONTAL)
        main_pane.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Panel Izquierdo: Controles y ConfiguraciÃ³n
        left_frame_container = ttk.Frame(main_pane, padding=10)
        left_frame_container.configure(borderwidth=1, relief="solid")
        main_pane.add(left_frame_container, weight=1)

        # AÃ±adir logo encima de la secciÃ³n de escaneo - TAMAÃ‘O FIJO
        logo_frame = ttk.Frame(left_frame_container)
        logo_frame.pack(fill=X, pady=(0, 5))

        # Ruta al archivo de logo PNG
        logo_path = os.path.join(os.path.dirname(__file__), 'resources', 'SG - Logo Laberit principal.png')

        # Cargar y mostrar el logo con tamaÃ±o fijo
        if os.path.exists(logo_path):
            try:
                # Cargar la imagen original
                original_img = Image.open(logo_path)

                # AQUÃ PUEDES CAMBIAR EL TAMAÃ‘O FIJO DE LA IMAGEN
                # Modifica estos valores para ajustar el tamaÃ±o
                fixed_width = 225  # Ancho fijo en pÃ­xeles
                fixed_height = 45  # Altura fija en pÃ­xeles

                # Redimensionar la imagen a un tamaÃ±o fijo
                resized_img = original_img.resize((fixed_width, fixed_height), Image.LANCZOS)

                # Convertir a formato que tkinter puede mostrar
                self.logo_photo = ImageTk.PhotoImage(resized_img)

                # Crear y centrar el label con la imagen
                self.logo_label = ttk.Label(logo_frame, image=self.logo_photo)
                self.logo_label.pack(pady=5)
            except Exception as e:
                logger.error(f"Error al cargar el logo: {e}")

        # SecciÃ³n de Escaneo
        scan_frame = ttk.Labelframe(left_frame_container, text="ConfiguraciÃ³n de Escaneo", padding=10)
        scan_frame.pack(fill=X, pady=5)

        ttk.Label(scan_frame, text="Rango de Red (ej: 192.168.1.0/24):", style="Section.TLabel").pack(fill=X, pady=(0,2))
        ttk.Entry(scan_frame, textvariable=self.network_range).pack(fill=X, pady=(0,5))

        # OpciÃ³n para escaneo automÃ¡tico
        auto_scan_check = ttk.Checkbutton(
            scan_frame,
            text="Escaneo automÃ¡tico detallado (SSH, SNMP)",
            variable=self.auto_scan_enabled,
            bootstyle="round-toggle"
        )
        auto_scan_check.pack(fill=X, pady=2)

        # OpciÃ³n para escaneo WMI
        wmi_scan_check = ttk.Checkbutton(
            scan_frame,
            text="Incluir escaneo WMI (Windows)",
            variable=self.wmi_scan_enabled,
            bootstyle="round-toggle"
        )
        wmi_scan_check.pack(fill=X, pady=2)

        self.scan_button = ttk.Button(scan_frame, text="Iniciar Escaneo", command=self._start_nmap_scan, style="Action.TButton")
        self.scan_button.pack(fill=X, pady=5)

        self.scan_progress = ttk.Progressbar(scan_frame, mode='indeterminate')
        self.scan_progress.pack(fill=X, pady=5)

        ttk.Label(scan_frame, textvariable=self.scan_status).pack(fill=X, pady=2)

        # SecciÃ³n de Credenciales para escaneo detallado
        creds_frame = ttk.Labelframe(left_frame_container, text="Credenciales para Escaneo Detallado", padding=10)
        creds_frame.pack(fill=X, pady=10)

        # SSH
        ssh_label = ttk.Label(creds_frame, text="SSH (Linux/Unix):", style="Section.TLabel")
        ssh_label.pack(anchor=W)
        ssh_form = ttk.Frame(creds_frame)
        ssh_form.pack(fill=X, padx=10)
        ttk.Label(ssh_form, text="Usuario:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(ssh_form, textvariable=self.ssh_username, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(ssh_form, text="ContraseÃ±a:").grid(row=1, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(ssh_form, textvariable=self.ssh_password, show="*", width=15).grid(row=1, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(ssh_form, text="Ruta Clave:").grid(row=2, column=0, sticky=W, padx=2, pady=2)
        key_frame = ttk.Frame(ssh_form)
        key_frame.grid(row=2, column=1, sticky=EW)
        ttk.Entry(key_frame, textvariable=self.ssh_key_file, width=10).pack(side=LEFT, expand=True, fill=X)
        ttk.Button(key_frame, text="...", command=self._browse_ssh_key, width=3).pack(side=LEFT)

        # WMI
        wmi_label = ttk.Label(creds_frame, text="WMI (Windows):", style="Section.TLabel")
        wmi_label.pack(anchor=W, pady=(5,0))
        wmi_form = ttk.Frame(creds_frame)
        wmi_form.pack(fill=X, padx=10)
        ttk.Label(wmi_form, text="Usuario:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_username, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(wmi_form, text="ContraseÃ±a:").grid(row=1, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_password, show="*", width=15).grid(row=1, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(wmi_form, text="Dominio:").grid(row=2, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_domain, width=15).grid(row=2, column=1, sticky=EW, padx=2, pady=2)

        # SNMP
        snmp_label = ttk.Label(creds_frame, text="SNMP:", style="Section.TLabel")
        snmp_label.pack(anchor=W, pady=(5,0))
        snmp_form = ttk.Frame(creds_frame)
        snmp_form.pack(fill=X, padx=10)
        ttk.Label(snmp_form, text="Comunidad:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(snmp_form, textvariable=self.snmp_community, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)

        ssh_form.columnconfigure(1, weight=1)
        wmi_form.columnconfigure(1, weight=1)
        snmp_form.columnconfigure(1, weight=1)

        # SecciÃ³n de ExportaciÃ³n
        export_frame = ttk.Labelframe(left_frame_container, text="Exportar Resultados", padding=10)
        export_frame.pack(fill=X, pady=10)
        self.export_button = ttk.Button(export_frame, text="Exportar Datos", command=self._export_data, state=DISABLED, style="Primary.TButton")
        self.export_button.pack(fill=X)

        # Panel Derecho: Resultados y Detalles
        right_frame_container = ttk.Frame(main_pane, padding=0) # No padding for container, let PanedWindow handle it
        right_frame_container.configure(borderwidth=1, relief="solid")
        main_pane.add(right_frame_container, weight=3)

        results_pane = ttk.PanedWindow(right_frame_container, orient=VERTICAL)
        results_pane.pack(fill=BOTH, expand=True)

        # Frame para la tabla de resultados y bÃºsqueda
        results_table_frame = ttk.Frame(results_pane, padding=(10,10,10,0)) # Padding solo arriba y a los lados
        results_pane.add(results_table_frame, weight=2)

        # Frame de bÃºsqueda con estilo moderno
        search_frame = ttk.Frame(results_table_frame)
        search_frame.pack(fill=X, pady=(0,5))
        ttk.Label(search_frame, text="Buscar:", font=('', 10)).pack(side=LEFT, padx=(0,5))
        search_entry = ttk.Entry(search_frame, textvariable=self.search_filter, font=('', 10))
        search_entry.pack(side=LEFT, fill=X, expand=True)

        # ConfiguraciÃ³n de la tabla de resultados
        style = ttk.Style()
        style.configure("Treeview", font=('', 10))  # Fuente base para la tabla
        style.configure("Treeview.Heading", font=('', 10, 'bold'))  # Fuente para encabezados

        # DefiniciÃ³n de columnas con nombres en espaÃ±ol
        columns = {
            "ip": ("IP", 120),
            "hostname": ("Hostname", 150),
            "mac": ("MAC", 150),
            "vendor": ("Fabricante", 150),
            "os": ("Sistema Operativo", 200),
            "ports": ("Puertos", 250) # Aumentar el ancho de la columna de puertos
        }

        # Crear Treeview con aspecto de tabla
        self.results_tree = ttk.Treeview(
            results_table_frame,
            columns=list(columns.keys()),
            show='headings',  # Solo mostrar los encabezados, sin la columna de Ã¡rbol
            style="Treeview",
            height=20  # Altura aproximada en filas
        )

        # Configurar cada columna
        for col_id, (header, width) in columns.items():
            self.results_tree.heading(col_id, text=header, anchor=W)
            self.results_tree.column(col_id, width=width, stretch=True, anchor=W)

            # AÃ±adir ordenamiento al hacer clic en el encabezado
            self.results_tree.heading(
                col_id,
                text=header,
                command=lambda _col=col_id: self._treeview_sort_column(_col, False)
            )

        # Configurar selecciÃ³n y estilo de la tabla
        self.results_tree.tag_configure('oddrow', background='#f0f0f0')  # Filas alternas
        self.results_tree.tag_configure('evenrow', background='#ffffff')

        # Scrollbars con estilo moderno
        tree_ysb = ttk.Scrollbar(results_table_frame, orient=VERTICAL, command=self.results_tree.yview)
        tree_xsb = ttk.Scrollbar(results_table_frame, orient=HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscroll=tree_ysb.set, xscroll=tree_xsb.set)

        # Empaquetar todo con el layout correcto
        tree_ysb.pack(side=RIGHT, fill=Y)
        tree_xsb.pack(side=BOTTOM, fill=X)
        self.results_tree.pack(fill=BOTH, expand=True)

        # Eventos
        self.results_tree.bind("<<TreeviewSelect>>", self._on_device_select)
        self.results_tree.bind('<Button-1>', self._on_click)
        self.results_tree.bind('<B1-Motion>', self._on_drag)
        self.results_tree.bind('<ButtonRelease-1>', self._on_release)

        # Frame para detalles del dispositivo
        details_frame = ttk.Labelframe(results_pane, text="Detalles del Dispositivo Seleccionado", padding=10)
        results_pane.add(details_frame, weight=1)

        self.details_notebook = ttk.Notebook(details_frame)
        self.details_notebook.pack(fill=BOTH, expand=True)

        self.general_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.ports_services_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.ssh_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.wmi_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.snmp_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0) # Nueva pestaÃ±a SNMP

        self.details_notebook.add(self.general_details_text, text="General")
        self.details_notebook.add(self.ports_services_text, text="Puertos/Servicios")
        self.details_notebook.add(self.wmi_details_text, text="Info WMI")
        self.details_notebook.add(self.ssh_details_text, text="Info SSH")
        self.details_notebook.add(self.snmp_details_text, text="Info SNMP") # AÃ±adir pestaÃ±a SNMP

    def _browse_ssh_key(self):
        """Abre un diÃ¡logo para seleccionar un archivo de clave SSH."""
        filepath = filedialog.askopenfilename(title="Seleccionar archivo de clave SSH")
        if filepath:
            self.ssh_key_file.set(filepath)

    def _update_scan_ui(self, scanning: bool, status_message: Optional[str] = None):
        """Actualiza la UI durante el escaneo."""
        if scanning:
            self.scan_button.config(state=DISABLED)
            self.export_button.config(state=DISABLED)
            self.scan_progress.start()
            if status_message:
                self.scan_status.set(status_message)
        else:
            self.scan_button.config(state=NORMAL)
            self.scan_progress.stop()
            if status_message:
                self.scan_status.set(status_message)
            else:
                self.scan_status.set(f"{len(self.scan_results)} dispositivos encontrados. Listo.")

            if self.scan_results:
                self.export_button.config(state=NORMAL)

    def _start_nmap_scan(self):
        """Inicia el escaneo Nmap en un hilo separado."""
        target = self.network_range.get().strip()
        if not target:
            messagebox.showwarning("Advertencia", "Por favor, ingrese un rango de red vÃ¡lido.")
            return

        self.scan_results.clear() # Limpiar resultados anteriores
        self._populate_results_tree() # Limpiar tabla
        self._clear_details_view() # Limpiar vistas de detalle

        self._update_scan_ui(True, "Escaneando red (Nmap)...")

        scan_thread = threading.Thread(target=self._perform_nmap_scan_thread, args=(target,), daemon=True)
        scan_thread.start()

    def _perform_nmap_scan_thread(self, target: str):
        """LÃ³gica de escaneo Nmap que se ejecuta en el hilo."""
        try:
            self.scan_results = []

            # 1. Escaneo rÃ¡pido inicial para encontrar hosts activos
            self.after(0, lambda: self._update_scan_ui(True, "Buscando dispositivos activos..."))
            active_ips = self.nmap_scanner.quick_scan(target)

            if not active_ips:
                self.after(0, lambda: messagebox.showwarning(
                    "Escaneo Completado",
                    "No se encontraron dispositivos activos en la red especificada.",
                    parent=self
                ))
                self.after(0, lambda: self._update_scan_ui(False, "No se encontraron dispositivos."))
                return

            total_ips = len(active_ips)
            self.after(0, lambda: self._update_scan_ui(True, f"Encontrados {total_ips} dispositivos. Iniciando escaneo detallado..."))

            # 2. Escaneo detallado en paralelo
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=10) as executor:
                # Iniciar todos los escaneos
                future_to_ip = {executor.submit(self.nmap_scanner.detailed_scan, ip): ip
                                for ip in active_ips}

                # Procesar resultados conforme van llegando
                completed = 0
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1

                    try:
                        device = future.result()
                        if device:
                            self.scan_results.append(device)
                            # Actualizar la UI con el nuevo dispositivo
                            self.after(0, lambda d=device: self.on_device_found(d))
                    except Exception as e:
                        logger.error(f"Error escaneando {ip}: {e}")

                    # Actualizar progreso
                    progress = (completed / total_ips) * 100
                    self.after(0, lambda msg=f"Escaneando... {completed}/{total_ips} ({progress:.1f}%)":
                    self._update_scan_ui(True, msg))

            # 3. Finalizar y actualizar UI
            if self.scan_results:
                self._count_device_types()
                logger.info(f"Escaneo completado. Encontrados {len(self.scan_results)} dispositivos.")

                # Si el escaneo automÃ¡tico estÃ¡ habilitado, iniciar escaneos detallados
                if self.auto_scan_enabled.get():
                    self._start_automatic_detailed_scans()
                else:
                    self.after(0, lambda: self._update_scan_ui(False, "Escaneo completado."))
            else:
                self.after(0, lambda: self._update_scan_ui(False, "No se encontraron dispositivos."))

        except Exception as e:
            logger.error(f"Error durante el escaneo: {e}", exc_info=True)
            self.after(0, lambda: messagebox.showerror(
                "Error de Escaneo",
                f"OcurriÃ³ un error durante el escaneo: {e}",
                parent=self
            ))
            self.after(0, lambda: self._update_scan_ui(False, "Error durante el escaneo."))

    def _count_device_types(self):
        """Cuenta los dispositivos por tipo y marca si tienen puertos relevantes."""
        self.windows_devices_count = 0
        self.linux_devices_count = 0
        self.snmp_devices_count = 0

        for device in self.scan_results:
            os_lower = device.get_os().lower() if device.get_os() else ""
            device.has_wmi_potential = False # Usar un nombre mÃ¡s descriptivo
            device.has_ssh_potential = False
            device.has_snmp_potential = False

            if "windows" in os_lower:
                self.windows_devices_count += 1
                device.has_wmi_potential = True

            if any(x in os_lower for x in ["linux", "unix", "ubuntu", "debian", "centos", "fedora", "mac", "os x"]):
                self.linux_devices_count += 1
                device.has_ssh_potential = True

            # Nmap puede detectar el servicio SNMP en otros puertos, pero 161/udp es el estÃ¡ndar
            if 161 in device.get_open_ports().get('udp', {}):
                self.snmp_devices_count += 1
                device.has_snmp_potential = True
            elif any('snmp' in service_info.get('name','').lower() for port_info in device.get_open_ports().values() for service_info in port_info.values()):
                self.snmp_devices_count += 1
                device.has_snmp_potential = True


    def _populate_results_tree(self):
        """Actualiza el Ã¡rbol de resultados con los dispositivos encontrados."""
        # Limpiar Ã¡rbol existente
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        if not self.scan_results:
            return

        # Insertar dispositivos en el Treeview
        for i, device in enumerate(self.scan_results):
            # Formatear puertos con mÃ¡s detalles
            if device.services:
                port_details = []
                for port, service in device.services.items():
                    service_name = service.get('name', 'unknown')
                    service_state = service.get('state', 'unknown')
                    port_details.append(f"{port}/{service_name}/{service_state}")
                ports_str = ", ".join(sorted(port_details, key=lambda x: int(x.split('/')[0])))
            else:
                ports_str = "N/A"

            values = (
                device.ip_address,
                device.hostname or "N/A",
                device.mac_address or "N/A",
                device.vendor or "N/A",
                device.get_os() or "N/A",
                ports_str
            )
            self.results_tree.insert('', 'end', values=values, tags=('oddrow' if i % 2 else 'evenrow'))

    def _apply_filter(self, *args):
        """Filtra los resultados del Treeview segÃºn el texto de bÃºsqueda."""
        search_term = self.search_filter.get().lower()
        if not search_term:
            self.filtered_results = self.scan_results[:]
        else:
            self.filtered_results = [
                dev for dev in self.scan_results
                if search_term in str(dev.ip_address).lower() or \
                   search_term in str(dev.hostname).lower() or \
                   search_term in str(dev.mac_address).lower() or \
                   search_term in str(dev.vendor).lower() or \
                   search_term in str(dev.get_os()).lower()
            ]
        self._populate_results_tree()

    def _on_device_select(self, event=None):
        """Maneja la selecciÃ³n de un dispositivo en el Treeview."""
        selected_item = self.results_tree.focus()
        if not selected_item:
            self.selected_device_ip = None
            self._clear_details_view()
            return

        item_values = self.results_tree.item(selected_item, "values")
        if item_values:
            self.selected_device_ip = item_values[0]
            device = next((dev for dev in self.scan_results if dev.ip_address == self.selected_device_ip), None)
            if device:
                self._update_device_details_view(device)
            else:
                self._clear_details_view()
        else:
            self.selected_device_ip = None
            self._clear_details_view()

    def _clear_details_view(self):
        """Limpia todas las pestaÃ±as de detalles."""
        text_widgets = [
            self.general_details_text, self.ports_services_text,
            self.wmi_details_text, self.ssh_details_text, self.snmp_details_text
        ]
        for text_widget in text_widgets:
            text_widget.config(state=NORMAL)
            text_widget.delete(1.0, END)
            text_widget.config(state=DISABLED)

    def _update_text_widget(self, widget, content):
        """Actualiza un widget ScrolledText con el contenido dado."""
        widget.config(state=NORMAL)
        widget.delete(1.0, END)
        if isinstance(content, (dict, list)):
            import json
            widget.insert(END, json.dumps(content, indent=2, ensure_ascii=False))
        elif content:
            widget.insert(END, str(content))
        else:
            widget.insert(END, "No hay datos disponibles.")
        widget.config(state=DISABLED)

    def _update_device_details_view(self, device: Device):
        """Actualiza las pestaÃ±as de detalles con la informaciÃ³n del dispositivo."""
        if not device:
            self._clear_details_view()
            return

        # PestaÃ±a General
        general_info = f"""InformaciÃ³n General:
  - IP: {device.ip_address}
  - Hostname: {device.hostname or 'N/A'}
  - MAC: {device.mac_address or 'N/A'}
  - Vendor: {device.vendor or 'N/A'}
  - OS: {device.os_info.get('name', 'N/A')}
  - Tipo: {device.type}
  - Ãšltimo escaneo: {device.last_scan or 'N/A'}
  - Estado: {device.status}
"""
        if device.scan_error:
            general_info += f"\nError en el Ãºltimo escaneo: {device.scan_error}"

        self._update_text_widget(self.general_details_text, general_info)

        # PestaÃ±a Puertos/Servicios
        services_info = "Puertos y Servicios:\n"
        if device.services:
            for port, service_info in device.services.items():
                protocol = service_info.get('protocol', 'unknown')
                name = service_info.get('name', 'unknown')
                version = service_info.get('version', '')
                state = service_info.get('state', 'unknown')

                service_str = f"  - {port}/{protocol} ({state}): {name}"
                if version:
                    service_str += f" - {version}"
                services_info += service_str + "\n"
        else:
            services_info += "  No se encontraron puertos abiertos.\n"
        self._update_text_widget(self.ports_services_text, services_info)

        # PestaÃ±a Hardware
        hardware_info = "InformaciÃ³n de Hardware:\n"
        if device.hardware_info:
            for key, value in device.hardware_info.items():
                hardware_info += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        else:
            hardware_info += "  No disponible.\n"
        self._update_text_widget(self.wmi_details_text, hardware_info)

        # PestaÃ±a Info SNMP
        snmp_info = "InformaciÃ³n SNMP:\n"

        # InformaciÃ³n del sistema
        snmp_info += "\nInformaciÃ³n del Sistema:\n"
        if device.os_info:
            if 'description_snmp' in device.os_info:
                snmp_info += f"  - DescripciÃ³n: {device.os_info['description_snmp']}\n"
            if 'name' in device.os_info:
                snmp_info += f"  - Sistema Operativo: {device.os_info['name']}\n"
            if 'uptime_snmp' in device.os_info:
                snmp_info += f"  - Tiempo de actividad: {device.os_info['uptime_snmp']}\n"
            if 'location' in device.os_info:
                snmp_info += f"  - UbicaciÃ³n: {device.os_info['location']}\n"
            if 'contact' in device.os_info:
                snmp_info += f"  - Contacto: {device.os_info['contact']}\n"

        # InformaciÃ³n de hardware
        snmp_info += "\nInformaciÃ³n de Hardware:\n"
        if device.hardware_info:
            if 'total_memory_kb' in device.hardware_info:
                mem_total = int(device.hardware_info['total_memory_kb']) / 1024
                snmp_info += f"  - Memoria Total: {mem_total:.2f} MB\n"
            if 'available_memory_kb' in device.hardware_info:
                mem_avail = int(device.hardware_info['available_memory_kb']) / 1024
                snmp_info += f"  - Memoria Disponible: {mem_avail:.2f} MB\n"
            if 'memory_usage_percent' in device.hardware_info:
                snmp_info += f"  - Uso de Memoria: {device.hardware_info['memory_usage_percent']}\n"
            if 'cpu_load' in device.hardware_info:
                snmp_info += f"  - Carga de CPU: {device.hardware_info['cpu_load']}%\n"
            if 'running_processes' in device.hardware_info:
                snmp_info += f"  - Procesos en ejecuciÃ³n: {device.hardware_info['running_processes']}\n"
            if 'system_users' in device.hardware_info:
                snmp_info += f"  - Usuarios del sistema: {device.hardware_info['system_users']}\n"

        # InformaciÃ³n de interfaces de red
        snmp_info += "\nInterfaces de Red:\n"
        if 'interfaces' in device.network_info:
            for i, interface in enumerate(device.network_info['interfaces']):
                if 'description' in interface:
                    snmp_info += f"  - Interfaz {i+1}: {interface['description']}\n"
                    if 'mac_address' in interface:
                        snmp_info += f"    MAC: {interface['mac_address']}\n"
                    if 'ip_addresses' in interface and interface['ip_addresses']:
                        snmp_info += f"    IPs: {', '.join(interface['ip_addresses'])}\n"
                    if 'admin_status' in interface:
                        snmp_info += f"    Estado Admin: {interface['admin_status']}\n"
                    if 'oper_status' in interface:
                        snmp_info += f"    Estado Operativo: {interface['oper_status']}\n"
                    if 'speed' in interface:
                        try:
                            speed_mbps = int(interface['speed']) / 1000000
                            snmp_info += f"    Velocidad: {speed_mbps:.0f} Mbps\n"
                        except (ValueError, TypeError):
                            snmp_info += f"    Velocidad: {interface['speed']}\n"

        # Si no hay informaciÃ³n SNMP
        if not device.snmp_info or (len(device.os_info) == 0 and len(device.hardware_info) == 0 and len(device.network_info) == 0):
            snmp_info += "  No disponible o no escaneado.\n"

        self._update_text_widget(self.snmp_details_text, snmp_info)

        # PestaÃ±a Info SSH
        ssh_info_str = "InformaciÃ³n SSH:\n"
        if device.ssh_specific_info and device.ssh_specific_info.get("Estado") != "Desconocido" and not device.ssh_specific_info.get("error"):
            for key, value in device.ssh_specific_info.items():
                ssh_info_str += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        elif device.ssh_specific_info and device.ssh_specific_info.get("error"):
            ssh_info_str += f"  Error: {device.ssh_specific_info['error']}\n"
        else:
            ssh_info_str += "  No disponible o no escaneado.\n"
        self._update_text_widget(self.ssh_details_text, ssh_info_str)

        # PestaÃ±a Info WMI
        wmi_info_str = "InformaciÃ³n WMI:\n"
        if device.wmi_specific_info and device.wmi_specific_info.get("Estado") != "Desconocido" and not device.wmi_specific_info.get("error"):
            for key, value in device.wmi_specific_info.items():
                wmi_info_str += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        elif device.wmi_specific_info and device.wmi_specific_info.get("error"):
            wmi_info_str += f"  Error: {device.wmi_specific_info['error']}\n"
        else:
            wmi_info_str += "  No disponible o no escaneado.\n"
        self._update_text_widget(self.wmi_details_text, wmi_info_str)


    def _save_scan_to_db(self):
        """Guarda los resultados del escaneo en la base de datos."""
        try:
            if not self.scan_results:
                logging.warning("No hay dispositivos para guardar en la base de datos.")
                return

            logging.info(f"Guardando {len(self.scan_results)} dispositivos en la base de datos.")

            # Crear reporte de red
            report = NetworkReport(
                target=self.network_range.get(),
                timestamp=int(time.time()),
                engine_info="Nmap Scanner"
            )

            # AÃ±adir dispositivos al reporte
            for device in self.scan_results:
                report.add_device(device)

            # Guardar en la base de datos
            self.inventory_manager.save_report(report)
            logging.info("Reporte guardado exitosamente en la base de datos.")

        except Exception as e:
            logging.error(f"Error inesperado al guardar en la base de datos: {str(e)}")
            logging.debug(f"Detalles del error:", exc_info=True)
            messagebox.showerror(
                "Error al Guardar",
                f"No se pudieron guardar los resultados en la base de datos:\n{str(e)}"
            )

    def _export_data(self):
        """Exporta los datos del escaneo a un formato seleccionado por el usuario."""
        if not self.scan_results:
            messagebox.showwarning("Sin Datos", "No hay datos para exportar.", parent=self)
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("HTML files", "*.html"), ("All files", "*.*")],
            title="Guardar Reporte Como"
        )
        if not file_path:
            return

        report = NetworkReport(devices=self.scan_results)
        file_ext = os.path.splitext(file_path)[1].lower()

        try:
            if file_ext == ".csv":
                csv_exporter.export_to_csv(report, file_path)
            elif file_ext == ".json":
                json_exporter.export_to_json(report, file_path)
            elif file_ext == ".html":
                html_exporter.export_to_html(report, file_path)
            else:
                messagebox.showerror("Error de Formato", f"Formato de archivo no soportado: {file_ext}", parent=self)
                return

            messagebox.showinfo("ExportaciÃ³n Exitosa", f"Datos exportados correctamente a:\n{file_path}", parent=self)
            logger.info(f"Datos exportados a {file_path}")
        except Exception as e:
            messagebox.showerror("Error de ExportaciÃ³n", f"No se pudo exportar el archivo: {e}", parent=self)
            logger.error(f"Error al exportar datos a {file_path}: {e}", exc_info=True)

    def _on_closing(self):
        """Maneja el evento de cierre de la ventana."""
        if messagebox.askokcancel("Salir", "Â¿EstÃ¡ seguro de que desea salir?", parent=self):
            logger.info("Cerrando la aplicaciÃ³n.")
            if self.inventory_manager:
                self.inventory_manager.close() # Cerrar conexiÃ³n a la base de datos
            self.destroy()

    def _treeview_sort_column(self, col, reverse):
        l = [(self.results_tree.set(k, col), k) for k in self.results_tree.get_children('')]
        l.sort(key=lambda t: t[0], reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.results_tree.move(k, '', index)

        self.results_tree.heading(col, command=lambda _col=col: self._treeview_sort_column(_col, not reverse))

    def _on_click(self, event):
        self._drag_data["x"] = event.x
        self._drag_data["y"] = event.y
        self._drag_data["item"] = self.results_tree.identify_row(event.y)

    def _on_drag(self, event):
        dx = event.x - self._drag_data["x"]
        dy = event.y - self._drag_data["y"]
        self._drag_data["x"] = event.x
        self._drag_data["y"] = event.y
        item = self._drag_data["item"]
        if item:
            self.results_tree.move(item, '', self.results_tree.index(item) + dy // 20)

    def _on_release(self, event):
        self._drag_data["item"] = None

    def on_device_found(self, device: Device):
        """Callback cuando se encuentra un dispositivo"""
        if device and device.ip_address:  # Asegurarse de que el dispositivo es vÃ¡lido
            # Actualizar la tabla
            self.after(0, self._populate_results_tree)

            # Actualizar la UI con el progreso
            self.after(0, lambda: self._update_scan_ui(True, f"Dispositivo encontrado: {device.ip_address}"))

    def _create_menu_bar(self):
        """Crea la barra de menÃº principal de la aplicaciÃ³n."""
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # MenÃº Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="Nuevo escaneo", command=self._reset_scan)
        file_menu.add_command(label="Guardar resultados", command=self._save_results)
        file_menu.add_command(label="Cargar resultados guardados", command=self._load_saved_results)
        file_menu.add_separator()
        file_menu.add_command(label="Importar resultados", command=self._import_results)

        # SubmenÃº de exportaciÃ³n
        export_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Exportar", menu=export_menu)
        export_menu.add_command(label="Exportar a CSV", command=lambda: self._export_results("csv"))
        export_menu.add_command(label="Exportar a JSON", command=lambda: self._export_results("json"))
        export_menu.add_command(label="Exportar a HTML", command=lambda: self._export_results("html"))
        export_menu.add_command(label="Exportar a PDF", command=lambda: self._export_results("pdf"))
        export_menu.add_separator()
        export_menu.add_command(label="Informe detallado", command=self._generate_detailed_report)
        export_menu.add_command(label="Informe de seguridad", command=self._generate_security_report)

        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self._on_closing)

        # MenÃº Escaneo
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Escaneo", menu=scan_menu)
        scan_menu.add_command(label="Iniciar escaneo", command=self._start_nmap_scan)
        scan_menu.add_command(label="Detener escaneo", command=self._stop_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="ConfiguraciÃ³n de escaneo", command=self._configure_scan_options)
        scan_menu.add_command(label="Escaneo programado", command=self._schedule_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Escaneo rÃ¡pido", command=self._quick_scan)
        scan_menu.add_command(label="Escaneo completo", command=self._full_scan)
        scan_menu.add_command(label="Escaneo personalizado", command=self._custom_scan)

        # MenÃº Ver
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ver", menu=view_menu)
        view_menu.add_command(label="TopologÃ­a de red", command=self._show_topology)
        view_menu.add_command(label="Mapa de red interactivo", command=self._show_interactive_map)
        view_menu.add_command(label="EstadÃ­sticas", command=self._show_statistics)
        view_menu.add_command(label="GrÃ¡ficos", command=self._show_charts)
        view_menu.add_command(label="Historial de cambios", command=self._show_change_history)
        view_menu.add_separator()
        view_menu.add_command(label="Filtrar resultados", command=self._filter_results)
        view_menu.add_command(label="Ordenar resultados", command=self._sort_results)
        view_menu.add_separator()
        view_menu.add_command(label="Refrescar", command=self._refresh_view)

        # MenÃº Herramientas
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Herramientas", menu=tools_menu)

        # SubmenÃº de anÃ¡lisis de seguridad
        security_menu = tk.Menu(tools_menu, tearoff=0)
        tools_menu.add_cascade(label="AnÃ¡lisis de seguridad", menu=security_menu)
        security_menu.add_command(label="Ejecutar anÃ¡lisis", command=self._run_security_analysis)
        security_menu.add_command(label="Configurar anÃ¡lisis", command=self._configure_security_analysis)
        security_menu.add_command(label="Ver vulnerabilidades", command=self._view_vulnerabilities)
        security_menu.add_command(label="Recomendaciones de seguridad", command=self._show_security_recommendations)

        # SubmenÃº de monitoreo
        monitoring_menu = tk.Menu(tools_menu, tearoff=0)
        tools_menu.add_cascade(label="Monitoreo", menu=monitoring_menu)
        monitoring_menu.add_command(label="Iniciar monitoreo en tiempo real", command=self._start_monitoring)
        monitoring_menu.add_command(label="Detener monitoreo", command=self._stop_monitoring)
        monitoring_menu.add_command(label="Configurar monitoreo", command=self._configure_monitoring)
        monitoring_menu.add_command(label="Ver historial de alertas", command=self._view_alert_history)

        # SubmenÃº de alertas
        alerts_menu = tk.Menu(tools_menu, tearoff=0)
        tools_menu.add_cascade(label="Alertas", menu=alerts_menu)
        alerts_menu.add_command(label="Configurar alertas", command=self._configure_alerts)
        alerts_menu.add_command(label="Crear regla personalizada", command=self._create_custom_alert_rule)
        alerts_menu.add_command(label="Gestionar reglas", command=self._manage_alert_rules)
        alerts_menu.add_command(label="Configurar notificaciones", command=self._configure_notifications)

        tools_menu.add_separator()
        tools_menu.add_command(label="GestiÃ³n de credenciales", command=self._manage_credentials)
        tools_menu.add_command(label="ConexiÃ³n SSH", command=self._connect_ssh)
        tools_menu.add_command(label="ConexiÃ³n RDP", command=self._connect_rdp)
        tools_menu.add_command(label="Abrir interfaz web", command=self._open_web_interface)
        tools_menu.add_separator()
        tools_menu.add_command(label="Ping", command=self._ping_device)
        tools_menu.add_command(label="Traceroute", command=self._traceroute)
        tools_menu.add_command(label="Escaneo de puertos", command=self._port_scan)

        # MenÃº Inventario
        inventory_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Inventario", menu=inventory_menu)
        inventory_menu.add_command(label="Ver inventario completo", command=self._show_inventory)
        inventory_menu.add_command(label="Buscar dispositivo", command=self._search_device)
        inventory_menu.add_separator()
        inventory_menu.add_command(label="Gestionar etiquetas", command=self._manage_tags)
        inventory_menu.add_command(label="Categorizar dispositivos", command=self._categorize_devices)
        inventory_menu.add_command(label="AÃ±adir dispositivo manualmente", command=self._add_device_manually)
        inventory_menu.add_command(label="Editar dispositivo", command=self._edit_device)
        inventory_menu.add_separator()
        inventory_menu.add_command(label="Exportar inventario", command=self._export_inventory)
        inventory_menu.add_command(label="Importar inventario", command=self._import_inventory)
        inventory_menu.add_separator()
        inventory_menu.add_command(label="Gestionar base de datos", command=self._manage_database)

        # MenÃº Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="Manual de usuario", command=self._show_user_manual)
        help_menu.add_command(label="GuÃ­a rÃ¡pida", command=self._show_quick_guide)
        help_menu.add_command(label="Tutoriales", command=self._show_tutorials)
        help_menu.add_command(label="Preguntas frecuentes", command=self._show_faq)
        help_menu.add_separator()
        help_menu.add_command(label="Acerca de", command=self._show_about)
        help_menu.add_command(label="Verificar actualizaciones", command=self._check_updates)
        help_menu.add_separator()
        help_menu.add_command(label="Reportar problema", command=self._report_issue)

    # MÃ©todos adicionales para las nuevas opciones del menÃº
    def _save_results(self):
        """Guarda los resultados del escaneo actual."""
        if not self.scan_results:
            messagebox.showwarning("Guardar", "No hay resultados para guardar.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Guardar resultados",
            defaultextension=".json",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        )
        if file_path:
            try:
                json_exporter.export_to_json(self.scan_results, file_path)
                messagebox.showinfo("Guardar", f"Resultados guardados exitosamente en {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar resultados: {e}")

    def _load_saved_results(self):
        """Carga resultados guardados previamente."""
        file_path = filedialog.askopenfilename(
            title="Cargar resultados guardados",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        )
        if file_path:
            try:
                # AquÃ­ irÃ­a la lÃ³gica para cargar resultados
                messagebox.showinfo("Cargar", "Carga de resultados guardados no implementada aÃºn.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar resultados: {e}")

    def _generate_detailed_report(self):
        """Genera un informe detallado de los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("Informe", "No hay resultados para generar un informe.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para generar el informe detallado
        messagebox.showinfo("Informe", "GeneraciÃ³n de informe detallado no implementada aÃºn.")

    def _generate_security_report(self):
        """Genera un informe de seguridad de los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("Informe", "No hay resultados para generar un informe de seguridad.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para generar el informe de seguridad
        messagebox.showinfo("Informe", "GeneraciÃ³n de informe de seguridad no implementada aÃºn.")

    def _stop_scan(self):
        """Detiene el escaneo en curso."""
        # AquÃ­ irÃ­a la lÃ³gica para detener el escaneo
        messagebox.showinfo("Escaneo", "DetenciÃ³n de escaneo no implementada aÃºn.")

    def _schedule_scan(self):
        """Programa un escaneo para ejecutarse en un momento especÃ­fico."""
        # AquÃ­ irÃ­a la lÃ³gica para programar un escaneo
        messagebox.showinfo("Escaneo", "ProgramaciÃ³n de escaneo no implementada aÃºn.")

    def _quick_scan(self):
        """Realiza un escaneo rÃ¡pido de la red."""
        # AquÃ­ irÃ­a la lÃ³gica para un escaneo rÃ¡pido
        messagebox.showinfo("Escaneo", "Escaneo rÃ¡pido no implementado aÃºn.")

    def _full_scan(self):
        """Realiza un escaneo completo y detallado de la red."""
        # AquÃ­ irÃ­a la lÃ³gica para un escaneo completo
        messagebox.showinfo("Escaneo", "Escaneo completo no implementado aÃºn.")

    def _custom_scan(self):
        """Permite configurar un escaneo personalizado."""
        # AquÃ­ irÃ­a la lÃ³gica para un escaneo personalizado
        messagebox.showinfo("Escaneo", "Escaneo personalizado no implementado aÃºn.")

    def _show_interactive_map(self):
        """Muestra un mapa interactivo de la red."""
        if not self.scan_results:
            messagebox.showwarning("Mapa", "No hay resultados para mostrar el mapa.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para mostrar el mapa interactivo
        messagebox.showinfo("Mapa", "VisualizaciÃ³n de mapa interactivo no implementada aÃºn.")

    def _show_charts(self):
        """Muestra grÃ¡ficos y visualizaciones de los datos de red."""
        if not self.scan_results:
            messagebox.showwarning("GrÃ¡ficos", "No hay resultados para mostrar grÃ¡ficos.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para mostrar grÃ¡ficos
        messagebox.showinfo("GrÃ¡ficos", "VisualizaciÃ³n de grÃ¡ficos no implementada aÃºn.")

    def _filter_results(self):
        """Permite filtrar los resultados del escaneo."""
        if not self.scan_results:
            messagebox.showwarning("Filtrar", "No hay resultados para filtrar.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para filtrar resultados
        messagebox.showinfo("Filtrar", "Filtrado de resultados no implementado aÃºn.")

    def _sort_results(self):
        """Permite ordenar los resultados del escaneo."""
        if not self.scan_results:
            messagebox.showwarning("Ordenar", "No hay resultados para ordenar.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para ordenar resultados
        messagebox.showinfo("Ordenar", "Ordenamiento de resultados no implementado aÃºn.")

    def _configure_security_analysis(self):
        """Configura las opciones del anÃ¡lisis de seguridad."""
        # AquÃ­ irÃ­a la lÃ³gica para configurar el anÃ¡lisis de seguridad
        messagebox.showinfo("AnÃ¡lisis", "ConfiguraciÃ³n de anÃ¡lisis de seguridad no implementada aÃºn.")

    def _view_vulnerabilities(self):
        """Muestra las vulnerabilidades detectadas en los dispositivos."""
        if not self.scan_results:
            messagebox.showwarning("Vulnerabilidades", "No hay resultados para mostrar vulnerabilidades.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para mostrar vulnerabilidades
        messagebox.showinfo("Vulnerabilidades", "VisualizaciÃ³n de vulnerabilidades no implementada aÃºn.")

    def _show_security_recommendations(self):
        """Muestra recomendaciones de seguridad para los dispositivos."""
        if not self.scan_results:
            messagebox.showwarning("Recomendaciones", "No hay resultados para mostrar recomendaciones.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para mostrar recomendaciones
        messagebox.showinfo("Recomendaciones", "VisualizaciÃ³n de recomendaciones no implementada aÃºn.")

    def _start_monitoring(self):
        """Inicia el monitoreo en tiempo real de la red."""
        # AquÃ­ irÃ­a la lÃ³gica para iniciar el monitoreo
        messagebox.showinfo("Monitoreo", "Inicio de monitoreo no implementado aÃºn.")

    def _stop_monitoring(self):
        """Detiene el monitoreo en tiempo real de la red."""
        # AquÃ­ irÃ­a la lÃ³gica para detener el monitoreo
        messagebox.showinfo("Monitoreo", "DetenciÃ³n de monitoreo no implementado aÃºn.")

    def _configure_monitoring(self):
        """Configura las opciones del monitoreo en tiempo real."""
        # AquÃ­ irÃ­a la lÃ³gica para configurar el monitoreo
        messagebox.showinfo("Monitoreo", "ConfiguraciÃ³n de monitoreo no implementada aÃºn.")

    def _view_alert_history(self):
        """Muestra el historial de alertas."""
        # AquÃ­ irÃ­a la lÃ³gica para mostrar el historial de alertas
        messagebox.showinfo("Alertas", "VisualizaciÃ³n de historial de alertas no implementada aÃºn.")

    def _create_custom_alert_rule(self):
        """Crea una regla personalizada para alertas."""
        # AquÃ­ irÃ­a la lÃ³gica para crear reglas de alertas
        messagebox.showinfo("Alertas", "CreaciÃ³n de reglas personalizadas no implementada aÃºn.")

    def _manage_alert_rules(self):
        """Gestiona las reglas de alertas existentes."""
        # AquÃ­ irÃ­a la lÃ³gica para gestionar reglas de alertas
        messagebox.showinfo("Alertas", "GestiÃ³n de reglas de alertas no implementada aÃºn.")

    def _configure_notifications(self):
        """Configura las notificaciones del sistema."""
        # AquÃ­ irÃ­a la lÃ³gica para configurar notificaciones
        messagebox.showinfo("Notificaciones", "ConfiguraciÃ³n de notificaciones no implementada aÃºn.")

    def _configure_alerts(self):
        """Configura las alertas del sistema."""
        # AquÃ­ irÃ­a la lÃ³gica para configurar alertas
        messagebox.showinfo("Alertas", "ConfiguraciÃ³n de alertas no implementada aÃºn.")

    def _connect_ssh(self):
        """Establece una conexiÃ³n SSH con un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("SSH", "No hay dispositivo seleccionado para conectar.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para conectar por SSH
        messagebox.showinfo("SSH", f"ConexiÃ³n SSH a {self.selected_device_ip} no implementada aÃºn.")

    def _connect_rdp(self):
        """Establece una conexiÃ³n RDP con un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("RDP", "No hay dispositivo seleccionado para conectar.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para conectar por RDP
        messagebox.showinfo("RDP", f"ConexiÃ³n RDP a {self.selected_device_ip} no implementada aÃºn.")

    def _open_web_interface(self):
        """Abre la interfaz web de un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Web", "No hay dispositivo seleccionado para abrir interfaz web.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para abrir la interfaz web
        messagebox.showinfo("Web", f"Apertura de interfaz web para {self.selected_device_ip} no implementada aÃºn.")

    def _ping_device(self):
        """Realiza un ping a un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Ping", "No hay dispositivo seleccionado para hacer ping.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para hacer ping
        messagebox.showinfo("Ping", f"Ping a {self.selected_device_ip} no implementado aÃºn.")

    def _traceroute(self):
        """Realiza un traceroute a un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Traceroute", "No hay dispositivo seleccionado para hacer traceroute.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para hacer traceroute
        messagebox.showinfo("Traceroute", f"Traceroute a {self.selected_device_ip} no implementado aÃºn.")

    def _port_scan(self):
        """Realiza un escaneo de puertos a un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Escaneo", "No hay dispositivo seleccionado para escanear puertos.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para escanear puertos
        messagebox.showinfo("Escaneo", f"Escaneo de puertos para {self.selected_device_ip} no implementado aÃºn.")

    def _categorize_devices(self):
        """Permite categorizar los dispositivos del inventario."""
        if not self.scan_results:
            messagebox.showwarning("Categorizar", "No hay dispositivos para categorizar.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para categorizar dispositivos
        messagebox.showinfo("Categorizar", "CategorizaciÃ³n de dispositivos no implementada aÃºn.")

    def _add_device_manually(self):
        """AÃ±ade un dispositivo manualmente al inventario."""
        # AquÃ­ irÃ­a la lÃ³gica para aÃ±adir dispositivos manualmente
        messagebox.showinfo("AÃ±adir", "AdiciÃ³n manual de dispositivos no implementada aÃºn.")

    def _edit_device(self):
        """Edita la informaciÃ³n de un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Editar", "No hay dispositivo seleccionado para editar.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para editar dispositivos
        messagebox.showinfo("Editar", f"EdiciÃ³n de dispositivo {self.selected_device_ip} no implementada aÃºn.")

    def _import_inventory(self):
        """Importa un inventario desde un archivo."""
        # AquÃ­ irÃ­a la lÃ³gica para importar inventario
        messagebox.showinfo("Importar", "ImportaciÃ³n de inventario no implementada aÃºn.")

    def _manage_database(self):
        """Gestiona la base de datos del inventario."""
        # AquÃ­ irÃ­a la lÃ³gica para gestionar la base de datos
        messagebox.showinfo("Base de datos", "GestiÃ³n de base de datos no implementada aÃºn.")

    def _show_quick_guide(self):
        """Muestra una guÃ­a rÃ¡pida de uso de la aplicaciÃ³n."""
        from .help_functions import show_html_content
        show_html_content(self, "GuÃ­a RÃ¡pida", "quick_guide.html")

    def _show_tutorials(self):
        """Muestra tutoriales de uso de la aplicaciÃ³n."""
        from .help_functions import show_html_content
        show_html_content(self, "Tutoriales", "tutorials.html")

    def _show_faq(self):
        """Muestra preguntas frecuentes sobre la aplicaciÃ³n."""
        from .help_functions import show_html_content
        show_html_content(self, "Preguntas Frecuentes", "faq.html")

    def _reset_scan(self):
        """Reinicia la aplicaciÃ³n para un nuevo escaneo."""
        if self.scan_results and messagebox.askyesno("Nuevo escaneo",
                                                     "Â¿Desea iniciar un nuevo escaneo? Se perderÃ¡n los resultados actuales si no han sido guardados."):
            self.scan_results = []
            self.filtered_results = []
            self._update_results_table()
            self.scan_status.set("Listo para escanear.")
        elif not self.scan_results:
            self.scan_status.set("Listo para escanear.")

    def _import_results(self):
        """Importa resultados de un archivo."""
        file_path = filedialog.askopenfilename(
            title="Importar resultados",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        )
        if file_path:
            try:
                # AquÃ­ irÃ­a la lÃ³gica para importar resultados
                messagebox.showinfo("Importar", "ImportaciÃ³n de resultados no implementada aÃºn.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al importar resultados: {e}")

    def _export_results(self, format_type):
        """Exporta los resultados al formato especificado."""
        if not self.scan_results:
            messagebox.showwarning("Exportar", "No hay resultados para exportar.")
            return

        try:
            if format_type == "csv":
                file_path = filedialog.asksaveasfilename(
                    title="Exportar a CSV",
                    defaultextension=".csv",
                    filetypes=[("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")])
                if file_path:
                    csv_exporter.export_to_csv(self.scan_results, file_path)
                    messagebox.showinfo("Exportar", f"Resultados exportados correctamente a {file_path}")

            elif format_type == "json":
                file_path = filedialog.asksaveasfilename(
                    title="Exportar a JSON",
                    defaultextension=".json",
                    filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")])
                if file_path:
                    json_exporter.export_to_json(self.scan_results, file_path)
                    messagebox.showinfo("Exportar", f"Resultados exportados correctamente a {file_path}")

            elif format_type == "html":
                file_path = filedialog.asksaveasfilename(
                    title="Exportar a HTML",
                    defaultextension=".html",
                    filetypes=[("Archivos HTML", "*.html"), ("Todos los archivos", "*.*")])
                if file_path:
                    html_exporter.export_to_html(self.scan_results, file_path)
                    messagebox.showinfo("Exportar", f"Resultados exportados correctamente a {file_path}")

            elif format_type == "pdf":
                file_path = filedialog.asksaveasfilename(
                    title="Exportar a PDF",
                    defaultextension=".pdf",
                    filetypes=[("Archivos PDF", "*.pdf"), ("Todos los archivos", "*.*")])
                if file_path:
                    # AquÃ­ irÃ­a la lÃ³gica para exportar a PDF
                    messagebox.showinfo("Exportar", "ExportaciÃ³n a PDF no implementada aÃºn.")

        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar resultados: {e}")

    def _show_topology(self):
        """Muestra la topologÃ­a de red."""
        if not self.scan_results:
            messagebox.showwarning("TopologÃ­a", "No hay resultados para mostrar la topologÃ­a.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para mostrar la topologÃ­a
        messagebox.showinfo("TopologÃ­a", "VisualizaciÃ³n de topologÃ­a no implementada aÃºn.")

    def _show_statistics(self):
        """Muestra estadÃ­sticas de los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("EstadÃ­sticas", "No hay resultados para mostrar estadÃ­sticas.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para mostrar estadÃ­sticas
        messagebox.showinfo("EstadÃ­sticas", "VisualizaciÃ³n de estadÃ­sticas no implementada aÃºn.")

    def _show_change_history(self):
        """Muestra el historial de cambios en la red."""
        # AquÃ­ irÃ­a la lÃ³gica para mostrar el historial de cambios
        messagebox.showinfo("Historial", "VisualizaciÃ³n de historial no implementada aÃºn.")

    def _refresh_view(self):
        """Refresca la vista actual."""
        self._update_results_table()

    def _run_security_analysis(self):
        """Ejecuta un anÃ¡lisis de seguridad en los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("AnÃ¡lisis", "No hay dispositivos para analizar.")
            return

        # AquÃ­ irÃ­a la lÃ³gica para el anÃ¡lisis de seguridad
        messagebox.showinfo("AnÃ¡lisis", "AnÃ¡lisis de seguridad no implementado aÃºn.")

    def _manage_credentials(self):
        """Gestiona las credenciales para acceso a dispositivos."""
        # AquÃ­ irÃ­a la lÃ³gica para gestionar credenciales
        messagebox.showinfo("Credenciales", "GestiÃ³n de credenciales no implementada aÃºn.")

    def _configure_scan_options(self):
        """Configura opciones avanzadas de escaneo."""
        # AquÃ­ irÃ­a la lÃ³gica para configurar opciones de escaneo
        messagebox.showinfo("Opciones", "ConfiguraciÃ³n de opciones de escaneo no implementada aÃºn.")

    def _show_inventory(self):
        """Muestra el inventario completo de dispositivos."""
        # AquÃ­ irÃ­a la lÃ³gica para mostrar el inventario
        messagebox.showinfo("Inventario", "VisualizaciÃ³n de inventario no implementada aÃºn.")

    def _search_device(self):
        """Busca un dispositivo especÃ­fico en el inventario."""
        # AquÃ­ irÃ­a la lÃ³gica para buscar dispositivos
        messagebox.showinfo("BÃºsqueda", "BÃºsqueda de dispositivos no implementada aÃºn.")

    def _manage_tags(self):
        """Gestiona las etiquetas para categorizar dispositivos."""
        # AquÃ­ irÃ­a la lÃ³gica para gestionar etiquetas
        messagebox.showinfo("Etiquetas", "GestiÃ³n de etiquetas no implementada aÃºn.")

    def _export_inventory(self):
        """Exporta el inventario completo."""
        # AquÃ­ irÃ­a la lÃ³gica para exportar el inventario
        messagebox.showinfo("Exportar", "ExportaciÃ³n de inventario no implementada aÃºn.")

    def _show_user_manual(self):
        """Muestra el manual de usuario."""
        from .help_functions import show_html_content
        show_html_content(self, "Manual de Usuario", "user_manual.md")

    def _show_about(self):
        """Muestra informaciÃ³n sobre la aplicaciÃ³n."""
        from .help_functions import show_about
        show_about(self)

    def _check_updates(self):
        """Verifica si hay actualizaciones disponibles."""
        # AquÃ­ irÃ­a la lÃ³gica para verificar actualizaciones
        messagebox.showinfo("Actualizaciones", "VerificaciÃ³n de actualizaciones no implementada aÃºn.")

    def _report_issue(self):
        """Permite reportar un problema con la aplicaciÃ³n."""
        # AquÃ­ irÃ­a la lÃ³gica para reportar problemas
        messagebox.showinfo("Reportar", "Reporte de problemas no implementado aÃºn.")

    def _start_automatic_detailed_scans(self):
        """Inicia escaneos detallados automÃ¡ticos (SNMP, SSH, WMI) para los dispositivos encontrados."""
        try:
            self.after(0, lambda: self._update_scan_ui(True, "Iniciando escaneos detallados automÃ¡ticos..."))
            
            # Crear credenciales para los escaneos
            credentials = NetworkCredentials(
                username=self.ssh_username.get(),
                password=self.ssh_password.get(),
                domain=self.wmi_domain.get(),
                ssh_key_path=self.ssh_key_file.get(),
                snmp_community=self.snmp_community.get()
            )
            
            # Contador para dispositivos escaneados con Ã©xito
            successful_scans = 0
            total_devices = len(self.scan_results)
            
            # Realizar escaneos SNMP para todos los dispositivos
            for device in self.scan_results:
                try:
                    # Actualizar estado
                    self.after(0, lambda ip=device.ip_address: self._update_scan_ui(
                        True, f"Escaneando {ip} con SNMP..."))
                    
                    # Intentar escaneo SNMP
                    if self.snmp_scanner.scan_device(device, credentials):
                        successful_scans += 1
                        self.snmp_devices_count += 1
                        
                        # Actualizar la vista de detalles si este es el dispositivo seleccionado actualmente
                        if self.selected_device_ip == device.ip_address:
                            self.after(0, lambda d=device: self._update_device_details_view(d))
                    
                    # Actualizar la tabla de resultados para reflejar los cambios
                    self.after(0, self._populate_results_tree)
                    
                except Exception as e:
                    logger.error(f"Error en escaneo SNMP para {device.ip_address}: {e}", exc_info=True)
            
            # Actualizar contadores y UI
            self._count_device_types()
            self.after(0, lambda: self._update_scan_ui(
                False, f"Escaneo completado. {successful_scans}/{total_devices} dispositivos escaneados con SNMP."))
            
        except Exception as e:
            logger.error(f"Error en escaneos detallados automÃ¡ticos: {e}", exc_info=True)
            self.after(0, lambda: self._update_scan_ui(False, "Error en escaneos detallados automÃ¡ticos."))

    def _update_results_table(self):
        """Actualiza la tabla de resultados."""
        # Limpiar la tabla
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Aplicar filtro si existe
        self._apply_filter()

if __name__ == '__main__':
    # Asegurarse que el directorio del proyecto estÃ¡ en sys.path para importaciones relativas
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Reimportar mÃ³dulos con el path actualizado (si es necesario para pruebas directas del GUI)
    from miproyectored.scanner.nmap_scanner import NmapScanner
    from miproyectored.scanner.wmi_scanner import WmiScanner
    from miproyectored.scanner.ssh_scanner import SshScanner
    from miproyectored.scanner.snmp_scanner import SnmpScanner
    from miproyectored.model.device import Device
    from miproyectored.risk.risk_analyzer import RiskAnalyzer
    from miproyectored.inventory.inventory_manager import InventoryManager
    from miproyectored.export import csv_exporter, json_exporter, html_exporter
    from miproyectored.auth.network_credentials import NetworkCredentials

    app = NetworkScannerGUI()
    app.mainloop()
