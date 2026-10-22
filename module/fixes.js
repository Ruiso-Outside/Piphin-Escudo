// Piphin Escudo · correções: cada uma guarda o que havia antes (para Desfazer) e as que precisam de administrador
// rodam juntas, com UM pedido do Windows (UAC). O script vai num .ps1 temporário (grande demais para a linha de comando).
// Em teste (job.test), o registro vai para HKCU\Software\PiphinEscudoTest e o hosts para uma cópia; o que não dá para
// redirecionar (firewall, antivírus, serviços, tarefas, contas) é pulado e marcado como "test-skip".
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");

const PS = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
const MPCMD = path.join(process.env.ProgramFiles || "C:\\Program Files", "Windows Defender", "MpCmdRun.exe");

// o que cada correção faz, em palavras simples, se precisa de administrador e se dá para desfazer
const FIXES = {
  run_disable: { label: "Tirar da inicialização", admin: (p) => /^HKLM/i.test(p.key), undo: true },
  startup_disable: { label: "Tirar da pasta Inicializar", admin: (p) => /\\ProgramData\\/i.test(p.file), undo: true },
  task_disable: { label: "Desativar a tarefa", admin: () => true, undo: true },
  service_disable: { label: "Desativar o serviço", admin: () => true, undo: true },
  ifeo_remove: { label: "Desfazer o desvio", admin: () => true, undo: true },
  winlogon_fix: { label: "Voltar o login ao padrão", admin: () => true, undo: true },
  hosts_fix: { label: "Limpar o arquivo hosts", admin: () => true, undo: true },
  proxy_off: { label: "Desligar o proxy", admin: () => false, undo: true },
  exclusions_remove: { label: "Retirar as exceções", admin: () => true, undo: true },
  guest_off: { label: "Desligar a conta Convidado", admin: () => true, undo: true },
  rdp_off: { label: "Desligar a Área de Trabalho Remota", admin: () => true, undo: true },
  assist_off: { label: "Desligar a Assistência Remota", admin: () => true, undo: true },
  uac_on: { label: "Ligar o UAC", admin: () => true, undo: true, restart: true },
  smb1_off: { label: "Desligar o SMBv1", admin: () => true, undo: false, restart: true },
  fw_on: { label: "Ligar o firewall", admin: () => true, undo: true },
  rt_on: { label: "Ligar o antivírus", admin: () => true, undo: false },
  autologon_off: { label: "Apagar a senha guardada", admin: () => true, undo: false },
};

const RUNNER = String.raw`
$ErrorActionPreference = 'Stop'
$job = Get-Content -LiteralPath '__JOB__' -Raw -Encoding UTF8 | ConvertFrom-Json
$TEST = [bool]$job.test
$ROOT = if ($TEST) { 'HKCU:\Software\PiphinEscudoTest' } else { '' }
$HOSTS = if ($TEST) { $job.hosts } else { Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' }
$QUAR = $job.quarantine
# chave de verdade -> chave de teste (em teste); cria a chave de teste se precisar
function K([string]$k) { if (-not $TEST) { return $k }; $t = $ROOT + '\' + ($k -replace '^(HKLM|HKCU):\\?', '$1\'); if (-not (Test-Path $t)) { New-Item -Path $t -Force | Out-Null }; return $t }
function GetV($k, $n) { $p = Get-ItemProperty -LiteralPath (K $k) -Name $n -ErrorAction SilentlyContinue; if ($p) { return $p.$n } else { return $null } }
function KindOf($k, $n) { try { return (Get-Item -LiteralPath (K $k)).GetValueKind($n).ToString() } catch { return 'String' } }
function SetV($k, $n, $v, $kind) { if ($null -eq $v) { Remove-ItemProperty -LiteralPath (K $k) -Name $n -ErrorAction SilentlyContinue } else { New-ItemProperty -LiteralPath (K $k) -Name $n -Value $v -PropertyType $kind -Force | Out-Null } }
function Skip { if ($TEST) { throw 'test-skip' } }
$WL = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$TS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$RA = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
$POL = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$IS = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$IFEO = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

$out = @()
foreach ($it in $job.items) {
  $p = $it.params; $b = $it.backup; $r = [ordered]@{ fix = $it.fix; undo = [bool]$it.undo; ok = $true; backup = $null; message = '' }
  try {
    if (-not $it.undo) {
      switch ($it.fix) {
        'run_disable' { $r.backup = @{ key = $p.key; name = $p.name; value = (GetV $p.key $p.name); kind = (KindOf $p.key $p.name) }; if ($null -eq $r.backup.value) { throw 'O item já não existe' }; SetV $p.key $p.name $null $null }
        'startup_disable' { if (-not (Test-Path -LiteralPath $p.file)) { throw 'O atalho já não existe' }; New-Item -ItemType Directory -Force $QUAR | Out-Null; $to = Join-Path $QUAR ([IO.Path]::GetFileName($p.file) + '.' + [DateTime]::Now.Ticks + '.desativado'); Move-Item -LiteralPath $p.file -Destination $to; $r.backup = @{ from = $p.file; to = $to } }
        'task_disable' { Skip; Disable-ScheduledTask -TaskPath $p.path -TaskName $p.name | Out-Null; $r.backup = @{ path = $p.path; name = $p.name } }
        'service_disable' { Skip; $s = Get-CimInstance Win32_Service -Filter "Name='$($p.name -replace "'", "''")'"; if (-not $s) { throw 'Serviço não encontrado' }; $r.backup = @{ name = $p.name; start = $s.StartMode; running = ($s.State -eq 'Running') }; Stop-Service -Name $p.name -Force -ErrorAction SilentlyContinue; Set-Service -Name $p.name -StartupType Disabled }
        'ifeo_remove' { $k = "$IFEO\$($p.exe)"; $r.backup = @{ key = $k; value = (GetV $k 'Debugger') }; SetV $k 'Debugger' $null $null }
        'winlogon_fix' { $r.backup = @{ shell = (GetV $WL 'Shell'); userinit = (GetV $WL 'Userinit'); userShell = (GetV 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell') }; SetV $WL 'Shell' 'explorer.exe' 'String'; SetV $WL 'Userinit' 'C:\Windows\system32\userinit.exe,' 'String'; SetV 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' $null $null }
        'hosts_fix' { $all = [IO.File]::ReadAllText($HOSTS); New-Item -ItemType Directory -Force $QUAR | Out-Null; $bk = Join-Path $QUAR ('hosts.' + [DateTime]::Now.Ticks + '.bak'); [IO.File]::WriteAllText($bk, $all); $lines = $all -split "\r?\n"; $kept = $lines | Where-Object { $_.Trim() -ne $p.line.Trim() }; [IO.File]::WriteAllText($HOSTS, ($kept -join [Environment]::NewLine)); $r.backup = @{ file = $bk }; if ($lines.Count -eq @($kept).Count) { $r.message = 'a linha já não estava lá' } }
        'proxy_off' { $r.backup = @{ enable = (GetV $IS 'ProxyEnable'); server = (GetV $IS 'ProxyServer'); pac = (GetV $IS 'AutoConfigURL') }; SetV $IS 'ProxyEnable' 0 'DWord'; SetV $IS 'AutoConfigURL' $null $null }
        'exclusions_remove' { Skip; $r.backup = @{ items = $p.items }; foreach ($e in $p.items) { switch ($e[0]) { 'path' { Remove-MpPreference -ExclusionPath $e[1] } 'process' { Remove-MpPreference -ExclusionProcess $e[1] } 'extension' { Remove-MpPreference -ExclusionExtension $e[1] } } } }
        'guest_off' { Skip; $g = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }; $r.backup = @{ name = $g.Name; enabled = $g.Enabled }; Disable-LocalUser -SID $g.SID }
        'rdp_off' { $r.backup = @{ value = (GetV $TS 'fDenyTSConnections') }; SetV $TS 'fDenyTSConnections' 1 'DWord' }
        'assist_off' { $r.backup = @{ value = (GetV $RA 'fAllowToGetHelp') }; SetV $RA 'fAllowToGetHelp' 0 'DWord' }
        'uac_on' { $r.backup = @{ lua = (GetV $POL 'EnableLUA'); prompt = (GetV $POL 'ConsentPromptBehaviorAdmin') }; SetV $POL 'EnableLUA' 1 'DWord'; if ((GetV $POL 'ConsentPromptBehaviorAdmin') -eq 0) { SetV $POL 'ConsentPromptBehaviorAdmin' 5 'DWord' }; $r.message = 'vale depois de reiniciar o PC' }
        'smb1_off' { SetV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 'DWord'; Skip; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null; $r.message = 'vale depois de reiniciar o PC' }
        'fw_on' { Skip; $r.backup = @{ profiles = @(Get-NetFirewallProfile | ForEach-Object { @{ name = "$($_.Name)"; enabled = [bool]$_.Enabled } }) }; Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True }
        'rt_on' { Skip; Set-MpPreference -DisableRealtimeMonitoring $false; if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) { throw 'O Windows não deixou ligar (talvez uma política de empresa ou outro antivírus)' } }
        'autologon_off' { SetV $WL 'DefaultPassword' $null $null; SetV $WL 'AutoAdminLogon' '0' 'String' }
        default { throw "Correção desconhecida: $($it.fix)" }
      }
    } else {
      # desfazer: volta o que estava guardado
      switch ($it.fix) {
        'run_disable' { SetV $b.key $b.name $b.value $b.kind }
        'startup_disable' { Move-Item -LiteralPath $b.to -Destination $b.from }
        'task_disable' { Skip; Enable-ScheduledTask -TaskPath $b.path -TaskName $b.name | Out-Null }
        'service_disable' { Skip; $m = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }[$b.start]; if (-not $m) { $m = 'Manual' }; Set-Service -Name $b.name -StartupType $m; if ($b.running) { Start-Service -Name $b.name -ErrorAction SilentlyContinue } }
        'ifeo_remove' { SetV $b.key 'Debugger' $b.value 'String' }
        'winlogon_fix' { SetV $WL 'Shell' $b.shell 'String'; SetV $WL 'Userinit' $b.userinit 'String'; if ($b.userShell) { SetV 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' $b.userShell 'String' } }
        'hosts_fix' { [IO.File]::WriteAllText($HOSTS, [IO.File]::ReadAllText($b.file)) }
        'proxy_off' { SetV $IS 'ProxyEnable' $b.enable 'DWord'; if ($b.pac) { SetV $IS 'AutoConfigURL' $b.pac 'String' } }
        'exclusions_remove' { Skip; foreach ($e in $b.items) { switch ($e[0]) { 'path' { Add-MpPreference -ExclusionPath $e[1] } 'process' { Add-MpPreference -ExclusionProcess $e[1] } 'extension' { Add-MpPreference -ExclusionExtension $e[1] } } } }
        'guest_off' { Skip; if ($b.enabled) { Enable-LocalUser -Name $b.name } }
        'rdp_off' { SetV $TS 'fDenyTSConnections' $b.value 'DWord' }
        'assist_off' { SetV $RA 'fAllowToGetHelp' $b.value 'DWord' }
        'uac_on' { SetV $POL 'EnableLUA' $b.lua 'DWord'; if ($null -ne $b.prompt) { SetV $POL 'ConsentPromptBehaviorAdmin' $b.prompt 'DWord' } }
        'fw_on' { Skip; foreach ($x in $b.profiles) { Set-NetFirewallProfile -Profile $x.name -Enabled ([bool]$x.enabled) } }
        default { throw 'Não dá para desfazer esta correção' }
      }
    }
  } catch { $r.ok = $false; $r.message = $_.Exception.Message }
  $out += [pscustomobject]$r
}
[IO.File]::WriteAllText('__OUT__', (ConvertTo-Json -InputObject @($out) -Depth 8), (New-Object Text.UTF8Encoding $false))
`;

function run(file, args, timeout = 30 * 60 * 1000) {
  return new Promise((resolve) => execFile(file, args, { windowsHide: true, timeout, maxBuffer: 32 * 1024 * 1024 }, (err, stdout, stderr) =>
    resolve({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, out: String(stdout || ""), err: String(stderr || "") })));
}
// roda uma lista de correções (ou desfazeres); elevated: com o pedido de administrador
async function runJob(items, { elevated = false, test = null, quarantine }) {
  if (!items.length) return [];
  const dir = path.join(os.tmpdir(), "piphin-escudo");
  fs.mkdirSync(dir, { recursive: true });
  const id = crypto.randomBytes(6).toString("hex");
  const job = path.join(dir, `job-${id}.json`), out = path.join(dir, `res-${id}.json`), ps1 = path.join(dir, `fix-${id}.ps1`);
  fs.writeFileSync(job, JSON.stringify({ items, test: !!test, hosts: test && test.hosts, quarantine }), "utf8");
  const q = (s) => String(s).split("'").join("''");
  // UTF-8 com BOM: o PowerShell 5 lê os acentos certo
  fs.writeFileSync(ps1, "\uFEFF" + RUNNER.split("__JOB__").join(q(job)).split("__OUT__").join(q(out)), "utf8");
  try {
    if (elevated && !test) {
      const launcher = `try { $p = Start-Process -FilePath '${q(PS)}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','"${q(ps1)}"'; exit $p.ExitCode } catch { exit 1223 }`;
      const r = await run(PS, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", launcher]);
      if (!fs.existsSync(out)) { if (r.code === 1223) throw Object.assign(new Error("O pedido de administrador foi recusado"), { declined: true }); throw new Error("O ajudante de administrador não respondeu (código " + r.code + ")"); }
    } else {
      const r = await run(PS, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ps1]);
      if (!fs.existsSync(out)) throw new Error("A correção não respondeu: " + (r.err || r.out).slice(0, 300));
    }
    const res = JSON.parse(fs.readFileSync(out, "utf8").replace(/^\uFEFF/, ""));
    return Array.isArray(res) ? res : [res];
  } finally { for (const x of [job, out, ps1]) fs.rmSync(x, { force: true }); }
}

// aplica: separa o que precisa de administrador (um UAC só para tudo) do que não precisa
async function apply(list, opts) {
  const need = list.map((x) => ({ ...x, admin: FIXES[x.fix] ? !!FIXES[x.fix].admin(x.params || {}) : true }));
  const user = need.filter((x) => !x.admin), adm = need.filter((x) => x.admin);
  const results = [];
  results.push(...(await runJob(user.map((x) => ({ fix: x.fix, params: x.params, undo: !!x.undo, backup: x.backup })), { ...opts, elevated: false })));
  results.push(...(await runJob(adm.map((x) => ({ fix: x.fix, params: x.params, undo: !!x.undo, backup: x.backup })), { ...opts, elevated: true })));
  return results;
}

// antivírus (Microsoft Defender) pela ferramenta de linha de comando dele; não precisa de administrador
function defender(args, timeout = 6 * 3600 * 1000) { return run(MPCMD, args, timeout); }
async function scanFile(p) {
  const r = await defender(["-Scan", "-ScanType", "3", "-File", p, "-DisableRemediation"], 10 * 60 * 1000);
  // 0 = limpo; 2 = ameaça encontrada (o Defender cuida dela pela proteção em tempo real)
  return { clean: r.code === 0, threat: r.code === 2, code: r.code, output: (r.out || r.err).trim().slice(-600) };
}

module.exports = { FIXES, apply, defender, scanFile, MPCMD, PS };
