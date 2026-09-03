import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path


def _certreq() -> Path:
    if platform.system() != "Windows":
        raise RuntimeError("Создание запроса сейчас поддерживается только в Windows")
    path = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "certreq.exe"
    if not path.is_file():
        raise RuntimeError(f"Не найден certreq.exe: {path}")
    return path


def _work_dir(serial: str) -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "RDP-Token" / "work"
    safe = "".join(char for char in (serial or "unknown") if char.isalnum() or char in "-_")
    directory = base / (safe or "unknown")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _run(*arguments: str) -> str:
    result = subprocess.run(
        [str(_certreq()), *arguments], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False, timeout=300,
    )
    try:
        output = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        ansi = result.stdout.decode("cp1251", errors="replace")
        oem = result.stdout.decode("cp866", errors="replace")
        ansi_noise = sum(ansi.count(char) for char in "ҐЇ¤¬®")
        oem_noise = sum(1 for char in oem if "\u2500" <= char <= "\u257f")
        output = ansi if ansi_noise <= oem_noise else oem
    if result.returncode != 0:
        raise RuntimeError(output.strip() or f"certreq: код {result.returncode}")
    return output


_CERTENROLL_SCRIPT = r'''
param(
    [Parameter(Mandatory=$true)][string]$Reader,
    [Parameter(Mandatory=$true)][string]$SubjectDn,
    [Parameter(Mandatory=$false)][string]$Upn = "",
    [Parameter(Mandatory=$true)][int]$KeyLength,
    [Parameter(Mandatory=$true)][string]$OutputPath
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
trap {
    Write-Output $_.Exception.Message
    exit 1
}
$privateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
$privateKey.ProviderName = "Microsoft Smart Card Key Storage Provider"
$privateKey.ReaderName = $Reader
$privateKey.Length = $KeyLength
$privateKey.KeySpec = 0
$privateKey.MachineContext = $false
$privateKey.ExportPolicy = 0
$privateKey.Create()

$request = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
$request.InitializeFromPrivateKey(1, $privateKey, "")

$subject = New-Object -ComObject X509Enrollment.CX500DistinguishedName
$subject.Encode($SubjectDn, 0)
$request.Subject = $subject

$keyUsage = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
$keyUsage.InitializeEncode(0xA0)
$request.X509Extensions.Add($keyUsage)

$ekuOids = New-Object -ComObject X509Enrollment.CObjectIds
foreach ($value in @("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2")) {
    $oid = New-Object -ComObject X509Enrollment.CObjectId
    $oid.InitializeFromValue($value)
    $ekuOids.Add($oid)
}
$eku = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
$eku.InitializeEncode($ekuOids)
$request.X509Extensions.Add($eku)

if ($Upn) {
    $names = New-Object -ComObject X509Enrollment.CAlternativeNames
    $name = New-Object -ComObject X509Enrollment.CAlternativeName
    $name.InitializeFromString(11, $Upn)
    $names.Add($name)
    $san = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $san.InitializeEncode($names)
    $request.X509Extensions.Add($san)
}

$request.Encode()
$enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
$enrollment.InitializeFromRequest($request)
$encoded = $enrollment.CreateRequest(3)
[System.IO.File]::WriteAllText($OutputPath, $encoded, [System.Text.Encoding]::ASCII)
'''


def _run_certenroll(reader: str, subject_dn: str, upn: str,
                    key_length: int, output_path: Path, script_path: Path) -> str:
    powershell = Path(os.environ.get("WINDIR", r"C:\Windows")) / \
        "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file():
        raise RuntimeError(f"Не найден Windows PowerShell: {powershell}")
    script_path.write_text(_CERTENROLL_SCRIPT, encoding="utf-8-sig")
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass",
         "-File", str(script_path), "-Reader", reader,
         "-SubjectDn", subject_dn, "-Upn", upn, "-KeyLength", str(key_length),
         "-OutputPath", str(output_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=300,
    )
    output = result.stdout.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(output.strip() or f"CertEnroll: код {result.returncode}")
    return output


def create_smartcard_request(serial: str, token_label: str, common_name: str,
                             upn: str, key_length: int = 2048,
                             request_path: Path | None = None,
                             reader_name: str = "",
                             subject_fields: dict[str, str] | None = None) -> Path:
    if key_length not in (2048, 3072, 4096):
        raise ValueError("Поддерживаются ключи RSA 2048, 3072 и 4096")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = _work_dir(serial)
    base_name = "".join(char if char.isalnum() or char in "-_" else "-" for char in common_name)
    request_path = request_path or directory / f"{base_name}-{stamp}.req"
    request_path.parent.mkdir(parents=True, exist_ok=True)
    if not reader_name:
        raise RuntimeError("Для Rutoken не определён физический считыватель")
    subject_fields = dict(subject_fields or {})
    subject_fields["CN"] = common_name
    subject_names = (("CN", "CN"), ("O", "O"), ("OU", "OU"),
                     ("C", "C"), ("serialNumber", "2.5.4.5"))
    subject_dn = ",".join(f"{name}={_escape_dn(subject_fields.get(field, ''))}"
                          for field, name in subject_names
                          if subject_fields.get(field, "").strip())
    script_path = directory / f"{base_name}-{stamp}.ps1"
    _run_certenroll(reader_name, subject_dn, upn, key_length,
                    request_path, script_path)
    if not request_path.is_file():
        raise RuntimeError("certreq завершился без создания CSR")
    return request_path


def _escape_dn(value: str) -> str:
    value = value.strip()
    escaped = "".join("\\" + char if char in '\\,+\"<>;' else char for char in value)
    if escaped.startswith("#"):
        escaped = "\\" + escaped
    return escaped


def install_smartcard_certificate(certificate_path: Path) -> str:
    if not certificate_path.is_file():
        raise RuntimeError("Файл сертификата не найден")
    return _run("-accept", str(certificate_path))
