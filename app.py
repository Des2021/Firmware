import streamlit as st
import json
import pathlib
import time
import io
import contextlib
from getpass import getpass # Importamos esto aunque no lo usaremos directamente

# --- Importamos las funciones de los scripts del laboratorio ---
# No te preocupes si tu editor marca errores; funcionarán al correr Streamlit
# porque están en la misma carpeta.

try:
    # Fase 1
    from device_insecure import run_device
    from attacker_sim import try_login
    
    # Fase 2
    import device_secure # Lo importamos completo para acceder a sus funciones
    from attacker_after import verify_login as verify_login_after
    
    # Fase 3
    from ota_sign import gen_keys, create_image, sign_image
    from ota_device import verify_and_apply

except ImportError as e:
    st.error(f"Error de importación: {e}. Asegúrate de que todos los archivos .py del ZIP están en la misma carpeta que app.py")
    st.stop()


# --- Configuración de la App ---
st.set_page_config(layout="wide", page_title="Laboratorio IoT")
st.title("🔬 Laboratorio: Firmware Vulnerable y Remediación")
st.caption("Adaptación a Streamlit de la actividad del profesor.")

# Usamos session_state para mantener el estado del dispositivo entre clics
if 'device_state' not in st.session_state:
    st.session_state.device_state = {}
if 'log' not in st.session_state:
    st.session_state.log = []

# --- Archivos de estado (igual que en los scripts) ---
STATE_FILE = pathlib.Path("device_state.json")

# Función helper para capturar 'print' de los scripts
def capture_script_output(func, *args, **kwargs):
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        func(*args, **kwargs)
    output = f.getvalue()
    st.session_state.log.append(output) # Guardar log
    return output

# --- Definición de las Pestañas ---
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏠 Introducción",
    "💥 Fase 1: Explotación (admin/admin)",
    "🔒 Fase 2: Remediación (Hashing)",
    "✍️ Fase 3: Remediación (OTA Firmado)",
    "✅ Entregables"
])


# --- Pestaña 1: Introducción ---
with tab1:
    st.header("Concepto del Laboratorio")
    st.markdown("""
    Este laboratorio simula uno de los mayores riesgos en IoT: **las credenciales por defecto**[cite: 12].
    Muchos dispositivos se venden con 'admin/admin', y si no se cambian, son un punto de entrada fácil para atacantes[cite: 13].
    
    **Objetivo:**
    1.  Simular un dispositivo vulnerable (v1).
    2.  Simular un ataque exitoso usando 'admin/admin'.
    3.  Simular una remediación (v2) que fuerza el cambio de contraseña y usa *hashing*.
    4.  Verificar que el ataque 'admin/admin' falla contra la v2.
    5.  Simular una actualización de firmware segura (OTA) usando firmas criptográficas.
    
    Usa las pestañas en orden para seguir el flujo del laboratorio.
    """)
    st.warning("Nota: Esta app crea y modifica archivos locales (`device_state.json`, claves `.pem`, etc.) en la carpeta donde se ejecuta.", icon="📁")


# --- Pestaña 2: Fase 1 (Vulnerable) ---
with tab2:
    st.header("Fase 1: El Dispositivo Vulnerable")
    st.markdown("---")
    
    st.subheader("Paso 1: Simular Dispositivo v1 (Inseguro)")
    st.caption("Ejecuta `device_insecure.py`. Fíjate cómo muestra las credenciales en texto plano.")
    
    if st.button("1. Ejecutar Dispositivo v1 Inseguro", type="primary"):
        output = capture_script_output(run_device)
        st.code(output, language="bash")
        st.info("Observa las credenciales 'admin/admin' y la clave WiFi en texto claro. [cite: 58, 59]")

    st.markdown("---")
    st.subheader("Paso 2: Crear Estado Vulnerable")
    st.caption("Crea el archivo `device_state.json` simulando un dispositivo con 'admin/admin' guardado en texto plano.")

    if st.button("2. Crear device_state.json (vulnerable)"):
        vulnerable_state = {"firmware":"v1.0","credentials":{"user":"admin","pass":"admin"}}
        st.session_state.device_state = vulnerable_state
        STATE_FILE.write_text(json.dumps(vulnerable_state))
        st.success("`device_state.json` creado.")
        st.json(vulnerable_state)

    st.markdown("---")
    st.subheader("Paso 3: Simular Ataque (admin/admin)")
    st.caption("Ejecuta `attacker_sim.py` contra el estado vulnerable.")

    if st.button("3. Ejecutar Atacante (contra v1)", type="primary"):
        if not STATE_FILE.exists():
            st.error("Debes crear el 'device_state.json' (Paso 2) primero.")
        else:
            state_data = json.loads(STATE_FILE.read_text())
            output = capture_script_output(try_login, "admin", "admin", state_data['credentials'])
            st.code(output, language="bash")
            st.success("¡Ataque exitoso! El atacante obtuvo acceso. [cite: 15]")


# --- Pestaña 3: Fase 2 (Remediación Hashing) ---
with tab3:
    st.header("Fase 2: Remediación con Hashing y Primer Arranque")
    st.markdown("---")

    st.subheader("Paso 4: Firmware Seguro (Primer Arranque)")
    st.caption("Ejecuta `device_secure.py`. Esto simula un 'primer arranque' [cite: 62] que te obliga a cambiar la contraseña. La nueva contraseña se guardará como un *hash*.")
    
    st.warning("En el script original, esto sería interactivo. Aquí, lo simulamos con un campo de texto.", icon="⌨️")
    
    new_password = st.text_input("Introduce nueva contraseña (mín 8 chars):", type="password", key="new_pass")

    if st.button("4. Ejecutar Primer Arranque (device_secure.py)", type="primary"):
        if len(new_password) < 8:
            st.error("Contraseña demasiado corta. Introduce >=8 caracteres.")
        else:
            # Lógica adaptada de device_secure.py
            pwd_hash = device_secure.sha256_hex(new_password)
            secure_state = {
                "firmware": "v2.0-secure",
                "credentials": {"user": "admin", "pass_hash": pwd_hash},
                "ota_version": "1.0"
            }
            st.session_state.device_state = secure_state
            STATE_FILE.write_text(json.dumps(secure_state))
            
            st.success("¡Primer arranque completado! Contraseña cambiada y guardada como hash.")
            st.code(f"=== FIRST BOOT FLOW ===\nContraseña establecida y guardada como hash.", language="bash")
            st.write("Nuevo estado del dispositivo (`device_state.json`):")
            st.json(secure_state)
            st.info("Observa que ahora solo se guarda el 'pass_hash', no la contraseña real.")

    st.markdown("---")
    st.subheader("Paso 5: Verificar Fallo del Ataque")
    st.caption("Ejecuta `attacker_after.py`. El atacante intenta 'admin/admin' de nuevo, pero ahora contra el estado seguro (con hash).")

    if st.button("5. Ejecutar Atacante (contra v2)", type="primary"):
        if not STATE_FILE.exists() or "pass_hash" not in st.session_state.device_state.get('credentials', {}):
            st.error("Debes ejecutar el 'Primer Arranque' (Paso 4) primero.")
        else:
            state_data = json.loads(STATE_FILE.read_text())
            # Lógica adaptada de attacker_after.py
            ok = verify_login_after("admin", "admin", state_data)
            output = f"Attack with admin/admin --> {'SUCCESS' if ok else 'FAIL (expected)'}"
            
            st.code(output, language="bash")
            st.error("¡Ataque fallido! Las credenciales por defecto ya no funcionan. [cite: 49] Remedición exitosa.")


# --- Pestaña 4: Fase 3 (OTA Firmado) ---
with tab4:
    st.header("Fase 3: Remediación con Actualización Segura (OTA)")
    st.markdown("Una contraseña segura es buena, pero también necesitamos actualizar el firmware de forma segura (OTA)[cite: 11]. Esto evita que un atacante instale firmware malicioso. Usamos criptografía (claves RSA) para *firmar* el firmware. [cite: 65, 66]")
    st.markdown("---")
    
    st.subheader("Paso 6: Firmar el Firmware (Lado del Fabricante)")
    st.caption("Ejecuta `ota_sign.py`. Esto genera un par de claves (pública/privada), crea una imagen de firmware falsa y la firma con la clave privada.")

    if st.button("6. Generar Claves y Firmar Imagen (ota_sign.py)", type="primary"):
        log_ota_sign = io.StringIO()
        with contextlib.redirect_stdout(log_ota_sign):
            gen_keys()
            create_image()
            sign_image()
        output = log_ota_sign.getvalue()
        st.code(output, language="bash")
        st.success("¡Imagen firmada! Se han creado los siguientes archivos:")
        st.info("`ota_private.pem` (¡SECRETA!), `ota_public.pem`, `firmware_image.bin`, `firmware.sig` (la firma)")

    st.markdown("---")
    st.subheader("Paso 7: Verificar y Aplicar OTA (Lado del Dispositivo)")
    st.caption("Ejecuta `ota_device.py`. El dispositivo usa la clave pública (que tendría pre-cargada) para verificar la firma de la imagen. Si es válida, aplica la actualización.")

    if st.button("7. Verificar Firma y Aplicar OTA (ota_device.py)", type="primary"):
        output = capture_script_output(verify_and_apply)
        st.code(output, language="bash")
        if "VERIFICACION OK" in output:
            st.success("¡Verificación de firma exitosa! El dispositivo aplicó el OTA. [cite: 68]")
            st.write("Estado final del dispositivo (`device_state.json`):")
            st.json(json.loads(STATE_FILE.read_text()))
        else:
            st.error("Fallo en la verificación. Comprueba que ejecutaste el Paso 6.")


# --- Pestaña 5: Entregables ---
with tab5:
    st.header("Entregables")
    st.markdown("Según el PDF[cite: 51], debes entregar capturas de pantalla y un informe de mitigación.")
    
    st.subheader("1. Capturas de Pantalla")
    st.info("""
    Usa esta app para generar las salidas y toma capturas de pantalla de:
    1.  **Pestaña 2 (Fase 1):** La salida del **Paso 3** que muestra "LOGIN OK -> Acceso concedido". [cite: 53]
    2.  **Pestaña 3 (Fase 2):** La salida del **Paso 4** que muestra el nuevo JSON con el `pass_hash`. [cite: 54]
    3.  **Pestaña 3 (Fase 2):** La salida del **Paso 5** que muestra "Attack with admin/admin --> FAIL". [cite: 50]
    """)

    st.subheader("2. Informe de Mitigación (Máx 250 palabras)")
    st.markdown("El PDF te pide 6 pasos de mitigación[cite: 55, 78]. Usa el siguiente cuadro para redactar tu respuesta.")
    
    st.text_area("Escribe aquí tu plan técnico de mitigación:", height=300, placeholder=
"""Basado en el laboratorio, los 6 pasos clave de mitigación son:

1.  **Forzar cambio de credenciales en primer arranque:** Como vimos en 'device_secure.py'[cite: 60], el dispositivo no debe operar hasta que el usuario reemplace 'admin/admin' por una clave robusta.
2.  **Almacenamiento de secretos:** Nunca guardar contraseñas en texto plano[cite: 57]. Se deben almacenar como hashes (ej. SHA-256)[cite: 63]. Idealmente, usar un Secure Element (ej. ATECC608A) o NVS cifrado para proteger claves. [cite: 64, 71]
3.  **Mecanismo OTA Firmado:** Implementar un proceso de actualización (OTA) que verifique firmas criptográficas (ej. RSA)[cite: 65, 71], como en 'ota_device.py'. El dispositivo solo debe aceptar firmware firmado con la clave privada del fabricante. [cite: 66, 67]
4.  **Deshabilitar servicios de debug:** Desactivar interfaces como Telnet, SSH y consolas serie en el firmware de producción para reducir la superficie de ataque. [cite: 72]
5.  **Rotación/Revocación de credenciales:** Tener un mecanismo para cambiar claves de API o certificados de dispositivo si se sospecha un compromiso. [cite: 74]
6.  **Plan de respuesta:** Definir un proceso claro sobre qué hacer si se detecta un compromiso: cómo aislar dispositivos, revocar credenciales e informar a los usuarios. [cite: 75]
""")
