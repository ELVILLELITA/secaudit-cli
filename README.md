# SecAudit CLI

Herramienta local y de solo lectura para detectar patrones básicos de
fuerza bruta en logs de autenticación y archivos con exposición insegura.
No imprime el contenido de ningún archivo.

## Estructura del proyecto

```text
scrip ciberseguridad/
├── README.md
├── secaudit/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── file_auditor.py
│   └── log_analyzer.py
└── tests/
    ├── test_file_auditor.py
    └── test_log_analyzer.py
```

- `secaudit/__main__.py`: permite ejecutar el paquete con `python -m secaudit`.
- `secaudit/cli.py`: define los subcomandos, argumentos, salida y errores de CLI.
- `secaudit/log_analyzer.py`: lee el log línea por línea, aplica expresiones
  regulares y agrupa intentos fallidos por dirección IP.
- `secaudit/file_auditor.py`: recorre un directorio sin seguir enlaces
  simbólicos y revisa nombres sensibles y permisos.
- `tests/`: pruebas unitarias para ambos auditores.

## Requisitos

- Python 3.10 o superior.
- No requiere paquetes externos para ejecutarse.
- Ejecutar los comandos desde la carpeta raíz del proyecto.

## Uso en Windows

```powershell
cd "C:\ruta\scrip ciberseguridad"
py -m secaudit --help
py -m secaudit logs "C:\ruta\auth.log"
py -m secaudit logs "C:\ruta\auth.log" --threshold 3
py -m secaudit files "C:\ruta\a\revisar"
```

## Uso en Linux

```bash
cd "/ruta/scrip ciberseguridad"
python3 -m secaudit logs /var/log/auth.log
python3 -m secaudit logs /var/log/auth.log --threshold 3
python3 -m secaudit files /etc
```

## Subcomando `logs`

```text
python -m secaudit logs <archivo> [--threshold N]
```

Busca las frases `Failed password`, `authentication failure`, `invalid user`
y `failed login`. Cuando una misma IP alcanza el umbral, muestra la cantidad
de intentos y los números de línea. El umbral predeterminado es `5`.

Ejemplo de salida:

```text
[HIGH] 192.0.2.10: 5 failed logins (lines: 10, 11, 12, 14, 15)
```

## Subcomando `files`

```text
python -m secaudit files <directorio>
```

Recorre archivos regulares y reporta:

- archivos con permiso de escritura para cualquier usuario (`world-writable`);
- archivos sensibles legibles por otros usuarios (`exposed-sensitive-file`).

Nombres revisados incluyen `.env`, `credentials.json`, `secrets.json`,
`config.php`, `settings.py`, `web.config`, `id_rsa` y extensiones
`.pem`, `.key`, `.p12`, `.pfx` y `.kdbx`.

En Windows, la revisión de bits de permisos POSIX se omite porque no representa
de forma fiable los permisos ACL de Windows. La exploración de nombres y rutas
sí está disponible.

## Códigos de salida

- `0`: auditoría completada.
- `2`: ruta inválida, error de lectura, permiso insuficiente o argumento inválido.

## Modelo interno

La CLI crea un `LogAnalyzer` o `FileAuditor`, ejecuta su método principal
(`analyze()` o `audit()`) y convierte los resultados en salida legible.
Los resultados se representan con `BruteForceFinding` y `FileFinding`.
Los errores de I/O se encapsulan en `LogAnalyzerError` o `FileAuditorError`
para que la CLI los muestre sin ocultarlos.

## Pruebas

Si `pytest` está instalado:

```text
python -m pytest -q
```
