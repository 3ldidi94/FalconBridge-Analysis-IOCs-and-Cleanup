<#
    guest_prep.ps1 - prepares the guest VM BEFORE detonation and starts the captures.
    Run as Administrator INSIDE THE VM (never on the host).

    Prerequisites installed in the VM: Sysinternals (Procmon, Autorunsc), Wireshark/npcap (dumpcap),
    Frida (pip install frida-tools).

    Steps:
      1) powershell -ExecutionPolicy Bypass -File guest_prep.ps1 -Phase pre   # before detonation
      2) (detonate the sample through run_frida.py)
      3) powershell -ExecutionPolicy Bypass -File guest_prep.ps1 -Phase post  # after
#>
[CmdletBinding()]
param(
    [ValidateSet('pre','post')]
    [string]$Phase = 'pre',
    [string]$WorkDir = 'C:\sandbox',
    [string]$Tools   = 'C:\tools'   # where procmon.exe, dumpcap.exe, autorunsc.exe... live
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$cap = Join-Path $WorkDir 'capture'
New-Item -ItemType Directory -Force -Path $cap | Out-Null

function Have($exe) { return (Test-Path (Join-Path $Tools $exe)) -or (Get-Command $exe -ErrorAction SilentlyContinue) }
function Bin($exe) { $p = Join-Path $Tools $exe; if (Test-Path $p) { return $p } else { return $exe } }

if ($Phase -eq 'pre') {
    Write-Host "=== PHASE PRE - setting up captures ===" -ForegroundColor Cyan

    # 1) Persistence baseline BEFORE (autorunsc export)
    Write-Host "[*] Persistence baseline (autorunsc)..."
    if (Have 'autorunsc.exe') {
        & (Bin 'autorunsc.exe') -accepteula -a * -c -h -s '*' 2>$null | Out-File (Join-Path $cap 'autoruns_pre.csv') -Encoding UTF8
    } else { Write-Host "    (autorunsc not found - install Sysinternals)" -ForegroundColor DarkYellow }

    # 2) Procmon in the background (backing file)
    if (Have 'procmon.exe') {
        Write-Host "[*] Starting Procmon..."
        Start-Process (Bin 'procmon.exe') -ArgumentList "/AcceptEula","/Quiet","/Minimized","/BackingFile",(Join-Path $cap 'procmon.pml')
    } else { Write-Host "    (procmon not found)" -ForegroundColor DarkYellow }

    # 3) Network capture (dumpcap) on interface 1 (adjust -i for your lab)
    if (Have 'dumpcap.exe') {
        Write-Host "[*] Starting dumpcap (network capture)..."
        Start-Process (Bin 'dumpcap.exe') -ArgumentList "-i","1","-w",(Join-Path $cap 'traffic.pcapng'),"-n"
    } else { Write-Host "    (dumpcap not found - install Wireshark/npcap)" -ForegroundColor DarkYellow }

    # 4) Reminders
    Write-Host ""
    Write-Host ">>> Start FakeNet-NG in another window:" -ForegroundColor Yellow
    Write-Host "    fakenet.exe -c $PSScriptRoot\fakenet_FalconBridge.ini" -ForegroundColor Yellow
    Write-Host ">>> Then detonate:" -ForegroundColor Yellow
    Write-Host "    python $PSScriptRoot\run_frida.py $WorkDir\payload.exe" -ForegroundColor Yellow
    Write-Host ">>> CHECK that the VM SNAPSHOT is taken and the network is host-only / isolated." -ForegroundColor Red
}
elseif ($Phase -eq 'post') {
    Write-Host "=== PHASE POST - collection and diff ===" -ForegroundColor Cyan

    # 1) Autoruns AFTER + diff
    if (Have 'autorunsc.exe') {
        Write-Host "[*] Persistence snapshot (autorunsc) AFTER..."
        & (Bin 'autorunsc.exe') -accepteula -a * -c -h -s '*' 2>$null | Out-File (Join-Path $cap 'autoruns_post.csv') -Encoding UTF8
        if (Test-Path (Join-Path $cap 'autoruns_pre.csv')) {
            Write-Host "[*] Persistence diff (new entries):" -ForegroundColor Green
            $pre  = Get-Content (Join-Path $cap 'autoruns_pre.csv')
            $post = Get-Content (Join-Path $cap 'autoruns_post.csv')
            Compare-Object $pre $post | Where-Object SideIndicator -eq '=>' |
                Select-Object -ExpandProperty InputObject | Tee-Object (Join-Path $cap 'autoruns_NEW.txt')
        }
    }

    # 2) Stop Procmon and export
    if (Have 'procmon.exe') {
        Write-Host "[*] Stopping Procmon + CSV export..."
        Start-Process (Bin 'procmon.exe') -ArgumentList "/Terminate" -Wait
        if (Test-Path (Join-Path $cap 'procmon.pml')) {
            Start-Process (Bin 'procmon.exe') -ArgumentList "/OpenLog",(Join-Path $cap 'procmon.pml'),"/SaveApplyFilter","/SaveAs",(Join-Path $cap 'procmon.csv') -Wait
        }
    }

    # 3) Stop dumpcap
    Get-Process dumpcap -ErrorAction SilentlyContinue | Stop-Process -Force

    # 4) Non-Microsoft scheduled tasks
    Write-Host "[*] Scheduled tasks (non-Microsoft):" -ForegroundColor Green
    Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object TaskPath, TaskName, State | Format-Table -AutoSize |
        Out-String -Width 4096 | Tee-Object (Join-Path $cap 'tasks_nonMS.txt')

    Write-Host ""
    Write-Host ">>> Collection finished in $cap" -ForegroundColor Cyan
    Write-Host ">>> To review: frida.log, dumps\*.bin, traffic.pcapng, fakenet_*.pcap," -ForegroundColor Cyan
    Write-Host "    procmon.csv, autoruns_NEW.txt, tasks_nonMS.txt" -ForegroundColor Cyan
    Write-Host ">>> THEN: RESTORE THE VM SNAPSHOT." -ForegroundColor Red
}
