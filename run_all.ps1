Write-Host "Activating environment..." -ForegroundColor Yellow
.\venv\Scripts\Activate.ps1

Write-Host "Running parser..." -ForegroundColor Cyan
python parser_normalize.py

Write-Host "Running correlator..." -ForegroundColor Cyan
python correlator.py

Write-Host "Generating report..." -ForegroundColor Cyan
python report_generator.py

Write-Host "Running IP reputation enrichment..." -ForegroundColor Cyan
python ip_reputation.py

Write-Host "Sending Telegram alerts..." -ForegroundColor Cyan
python telegram_alert.py

Write-Host "All tasks completed ✅" -ForegroundColor Green
Read-Host "Press Enter to close"
