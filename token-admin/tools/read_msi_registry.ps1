param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [string]$Pattern = 'ISBC|pkcs11|esmart'
)

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($MsiPath, 0)
$sql = 'SELECT `Registry`,`Root`,`Key`,`Name`,`Value`,`Component_` FROM `Registry`'
$view = $database.OpenView($sql)
$view.Execute()

while ($record = $view.Fetch()) {
    $values = for ($index = 1; $index -le 6; $index++) {
        $record.StringData($index)
    }
    $line = $values -join '|'
    if ($line -match $Pattern) {
        $line
    }
}

$view.Close()
