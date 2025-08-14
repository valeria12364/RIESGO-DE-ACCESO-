import subprocess

def get_system_users():
  """
  Obtiene una lista de todos los nombres de usuario del sistema
  leyendo el archivo /etc/passwd.
  """
  try:
    with open("/etc/passwd", "r") as f:
      # Divide cada línea por ':' y toma la primera parte (el nombre de usuario)
      return [line.split(":")[0] for line in f]
  except FileNotFoundError:
    print("Error: El archivo /etc/passwd no se encontró. ¿Es un sistema Linux?")
    return []
  except Exception as e:
    print(f"Error al leer /etc/passwd: {e}")
    return []

def get_duplicate_uids():
  """
  Detecta UIDs (User IDs) duplicados en el sistema.
  Los UIDs duplicados pueden indicar cuentas compartidas o configuraciones erróneas.
  """
  try:
    # Usa comandos de shell para cortar el campo UID, ordenar y encontrar duplicados
    uids = subprocess.getoutput("cut -d: -f3 /etc/passwd | sort | uniq -d")
    return uids.splitlines()
  except Exception as e:
    print(f"Error al verificar UIDs duplicados: {e}")
    return []

def check_ssh_failed_attempts():
  """
  Revisa los logs del servicio SSH en busca de intentos de acceso fallidos.
  Un gran número de intentos fallidos puede indicar ataques de fuerza bruta.
  """
  try:
    # Filtra los logs de SSH para líneas que indican "Failed password"
    result = subprocess.getoutput("journalctl -u ssh | grep 'Failed password'")
    return result.splitlines()
  except Exception as e:
    print(f"Error al verificar intentos fallidos de SSH: {e}")
    return []

def check_mfa():
  """
  Verifica si la Autenticación de Múltiples Factores (MFA) está configurada
  en el archivo de configuración de SSH (/etc/ssh/sshd_config).
  """
  try:
    # Busca la línea 'AuthenticationMethods' en la configuración de SSH
    config = subprocess.getoutput("cat /etc/ssh/sshd_config | grep -i 'AuthenticationMethods'")
    return config.strip()
  except Exception as e:
    print(f"Error al verificar la configuración de MFA en SSH: {e}")
    return "Error al verificar."

def main():
  """
  Función principal que ejecuta todas las comprobaciones de seguridad
  y muestra los resultados en la consola.
  """
  print("--- Iniciando Auditoría Básica de Seguridad ---")

  # 1. Listar usuarios del sistema
  print("\n🧑‍💻 **Usuarios del sistema:**")
  users = get_system_users()
  if users:
    for user in users:
      print(f" - {user}")
  else:
    print("No se pudieron obtener los usuarios del sistema.")

  # 2. Detectar UIDs duplicados (cuentas compartidas)
  print("\n⚠️ **UIDs duplicados (posibles cuentas compartidas):**")
  duplicates = get_duplicate_uids()
  if duplicates:
    print("\n".join(duplicates))
  else:
    print("No se encontraron UIDs duplicados.")

  # 3. Revisar intentos fallidos de acceso SSH
  print("\n🚨 **Intentos fallidos de acceso SSH (últimos 10):**")
  failed_attempts = check_ssh_failed_attempts()
  if failed_attempts:
    # Muestra solo los últimos 10 para una mejor lectura
    for line in failed_attempts[-10:]:
      print(f" {line}")
    if len(failed_attempts) > 10:
        print(f"(... y {len(failed_attempts) - 10} intentos fallidos más no mostrados)")
  else:
    print("No se encontraron intentos fallidos de acceso SSH en los logs recientes.")

  # 4. Verificar configuración de MFA en SSH
  print("\n🔐 **MFA configurado en SSH (línea 'AuthenticationMethods'):**")
  mfa = check_mfa()
  if mfa:
    print(mfa)
  else:
    print("La línea 'AuthenticationMethods' no se encontró o no está configurada explícitamente.")
    print("Esto no significa necesariamente que MFA no esté activo, pero es un indicador a revisar.")

  print("\n--- Auditoría Finalizada ---")

if __name__ == "__main__":
  main()