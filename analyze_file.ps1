param(
    [Parameter(Mandatory=$true)]
    [string]$LogFile
)

if ($LogFile -eq '%1' -or -not (Test-Path $LogFile)) {
    Write-Host "`nERROR: Invalid file path passed to analyzer." -ForegroundColor Red
    Write-Host "If testing manually, run:" -ForegroundColor Yellow
    Write-Host "powershell.exe -ExecutionPolicy Bypass -File `"D:\SOC_Project\analyze_file.ps1`" `"C:\full\path\to\your\log.json`"" -ForegroundColor Cyan
    Pause
    exit 1
}

Write-Host "`nAnalyzing file: $LogFile" -ForegroundColor Cyan
cd "D:\SOC_Project"

# activate venv
.\venv\Scripts\Activate.ps1

# copy selected log into project folder
Copy-Item $LogFile .\input_log.json -Force

# run analyzer pipeline
python parser_normalize.py .\input_log.json
python correlator.py
python ip_reputation.py
python report_generator.py
python telegram_alert.py

Write-Host "`n✅ Analysis complete." -ForegroundColor Green
Pause
