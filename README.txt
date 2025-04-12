
===============================
 DNS Auditor Colombia - GUI Tool
===============================

Herramienta educativa y de auditoría visual para analizar servidores DNS públicos ubicados en Colombia, utilizando la API de Shodan, pruebas de resolución DNS (Google y Facebook) y verificación contra listas negras públicas.

----------------------------------
 Configuración del Entorno (opcional pero recomendado)
----------------------------------

### Crear entorno virtual y activar

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
source venv/bin/activate      # En Linux/Mac
venv\Scripts\activate         # En Windows

# Instalar dependencias
pip install -r requirements.txt
```

----------------------------------
 Requisitos del sistema
----------------------------------
- Python 3.8 o superior
- Sistema operativo: Windows, Linux o macOS
- Conexión a Internet activa

----------------------------------
 Instalación de dependencias
----------------------------------
Abre una terminal y ejecuta el siguiente comando:
pip install -r requirements.txt

Contenido del archivo requirements.txt:
- shodan  
- dnspython  
- requests

----------------------------------
 Configurar la API Key de Shodan
----------------------------------
1. Ve a: https://account.shodan.io
2. Copia tu clave API personal.
3. Crea un archivo llamado config.py en el mismo directorio del código con el siguiente contenido:

```python
SHODAN_API_KEY = "TU_API_KEY_AQUI"
```

----------------------------------
 Ejecución de la herramienta
----------------------------------
1. Asegúrate de tener los archivos dns_auditor_22.py y config.py en la misma carpeta.
2. En la terminal, ejecuta:
```bash
python3 dns_auditor_22.py
```
3. Se abrirá la interfaz gráfica de usuario (GUI).
4. Ingresa la cantidad de servidores DNS a auditar (valor por defecto: 20).
5. Haz clic en el botón "Iniciar Auditoría" para comenzar.

----------------------------------
 ¿Qué hace esta herramienta?
----------------------------------
- Busca servidores DNS públicos activos ubicados en Colombia mediante la API de Shodan.
- Intenta resolver los dominios google.com y facebook.com usando cada servidor.
- Verifica si las direcciones IP están incluidas en listas negras públicas.
- Muestra los resultados en una tabla visual con íconos que indican el estado de cada verificación.

----------------------------------
 Nota legal y ética
----------------------------------
Esta herramienta debe ser utilizada únicamente con fines educativos o de investigación debidamente autorizada.
El uso indebido de esta herramienta podría tener consecuencias legales.
