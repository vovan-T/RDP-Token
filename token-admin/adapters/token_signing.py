"""Application-level proof of possession for administrator login."""

import base64
import os
import subprocess
from pathlib import Path

from adapters.rutoken_requests import sign_rutoken_challenge


def _powershell_path() -> Path:
    system = Path(os.environ.get("WINDIR", r"C:\Windows"))
    path = system / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not path.is_file():
        raise RuntimeError("Не найден штатный Windows PowerShell")
    return path


def _sign_windows_provider(fingerprint: str, challenge: bytes) -> bytes:
    script = r'''
$ErrorActionPreference = 'Stop'
$thumb = $args[0].Replace(' ', '').ToUpperInvariant()
$data = [Convert]::FromBase64String($args[1])
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -eq $thumb
} | Select-Object -First 1
if ($null -eq $cert) { throw 'Сертификат токена не найден в CurrentUser\\My' }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($null -ne $rsa) {
    $signature = $rsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
} else {
    $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($null -eq $ecdsa) { throw 'Windows-провайдер не предоставил RSA/ECDSA закрытый ключ' }
    $signature = $ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
}
[Convert]::ToBase64String($signature)
'''
    result = subprocess.run(
        [str(_powershell_path()), "-NoLogo", "-NoProfile", "-NonInteractive",
         "-Command", script, fingerprint, base64.b64encode(challenge).decode("ascii")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        timeout=45, check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or "Windows-провайдер не подписал запрос")
    try:
        return base64.b64decode(result.stdout.strip(), validate=True)
    except ValueError as exc:
        raise RuntimeError("Windows-провайдер вернул некорректную подпись") from exc


def sign_token_challenge(token, certificate: dict, pin: str, challenge: bytes) -> bytes:
    key_type = str(certificate.get("key_type", "")).upper()
    if (token.vendor == "Aktiv" and certificate.get("id_hex")
            and (not key_type or "RSA" in key_type)):
        return sign_rutoken_challenge(
            token.serial, token.model, certificate["id_hex"], pin, challenge)
    fingerprint = certificate.get("fingerprint", "")
    if fingerprint and certificate.get("provider"):
        return _sign_windows_provider(fingerprint, challenge)
    raise RuntimeError(
        "Для этого токена нет доступного PKCS#11 или Windows-провайдера подписи")
