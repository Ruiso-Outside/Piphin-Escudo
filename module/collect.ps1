# Piphin Escudo · coleta (SÓ LEITURA): configurações de segurança, o que abre sozinho com o Windows, processos,
# rede e registros do Windows. Não muda nada no PC. Sai em JSON (-Out arquivo, ou na tela).
#   -Admin  também o que só o administrador vê (exclusões do antivírus, log de Segurança, BitLocker, TPM)
#   -Light  só o que o Vigia compara (inicialização, tarefas, serviços, contas, hosts, proxy, acesso remoto)
param([string]$Out = '', [switch]$Admin, [switch]$Light)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$R = [ordered]@{ at = (Get-Date).ToString('o'); admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); light = [bool]$Light }
function Try-Get([scriptblock]$b) { try { & $b } catch { $null } }
function RegVal($path, $name) { Try-Get { (Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop).$name } }

# caminho do programa de uma linha de comando ("C:\x\a.exe" -arg / C:\x\a.exe -arg / rundll32 x.dll,y)
function ExePath([string]$cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($c.StartsWith('"')) { $p = $c.Substring(1, [Math]::Max(0, $c.IndexOf('"', 1) - 1)) }
  else { $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|hta|scr|dll|lnk|msi))(\s|,|$)', 'IgnoreCase'); $p = if ($m.Success) { $m.Groups[1].Value } else { ($c -split '\s')[0] } }
  if ($p -and -not ($p -match '\\') ) { $w = Join-Path $env:SystemRoot "System32\$p"; if (Test-Path -LiteralPath $w) { $p = $w } elseif (Test-Path -LiteralPath "$w.exe") { $p = "$w.exe" } }
  return $p
}
# assinatura digital de um arquivo (com cache): quem assinou e se é válida
$sigCache = @{}
function SigOf([string]$p) {
  if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ exists = $false } }
  if ($sigCache.ContainsKey($p)) { return $sigCache[$p] }
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $who = if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { '' }
  $vi = (Get-Item -LiteralPath $p).VersionInfo
  $r = @{ exists = $true; status = "$($s.Status)"; signer = $who; company = $vi.CompanyName; product = $vi.ProductName; original = ("$($vi.OriginalFilename)" -replace '\.mui$', ''); created = (Get-Item -LiteralPath $p).CreationTime.ToString('o') }
  $sigCache[$p] = $r; return $r
}
function Item($o) { $p = ExePath $o.command; $o.path = $p; $o.sig = SigOf $p; [pscustomobject]$o }

# ---------------------------------------------------------------- o que abre sozinho (persistência)
$run = @()
foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')) {
  $props = Get-ItemProperty -LiteralPath $k
  if (-not $props) { continue }
  foreach ($pr in $props.PSObject.Properties) { if ($pr.Name -like 'PS*') { continue }; $run += Item @{ key = $k; name = $pr.Name; command = "$($pr.Value)" } }
}
$R.run = $run
$startup = @()
foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
  foreach ($f in Get-ChildItem -LiteralPath $d -File -Force) {
    if ($f.Name -eq 'desktop.ini') { continue }
    $target = $f.FullName
    if ($f.Extension -eq '.lnk') { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).TargetPath + ' ' + (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).Arguments }
    $startup += Item @{ file = $f.FullName; command = $target; created = $f.CreationTime.ToString('o'); common = ($d -eq [Environment]::GetFolderPath('CommonStartup')) }
  }
}
$R.startup = $startup
$tasks = @()
foreach ($t in Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) {
  foreach ($a in @($t.Actions)) {
    if (-not $a.Execute) { continue }
    $tasks += Item @{ name = $t.TaskName; taskPath = $t.TaskPath; state = "$($t.State)"; author = $t.Author; user = $t.Principal.UserId; runLevel = "$($t.Principal.RunLevel)"; command = ('"' + $a.Execute + '" ' + $a.Arguments).Trim(); hidden = [bool]$t.Settings.Hidden; triggers = (@($t.Triggers) | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task|Trigger$', '' }) -join ',' }
  }
}
$R.tasks = $tasks
$svc = @()
foreach ($s in Get-CimInstance Win32_Service) {
  $p = ExePath $s.PathName
  if (-not $p) { continue } # sem permissão para ver o caminho
  if ($p -like "$env:SystemRoot\*" -and $p -notmatch '\\Temp\\') { continue } # serviços do próprio Windows (conferidos à parte, se forem estranhos)
  $svc += [pscustomobject]@{ name = $s.Name; display = $s.DisplayName; command = $s.PathName; path = $p; start = $s.StartMode; state = $s.State; account = $s.StartName; sig = (SigOf $p) }
}
$R.services = $svc
# truques conhecidos: shell do logon trocado, "Debugger" (programa trocado), DLL injetada em tudo, teclas de acessibilidade trocadas
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$R.winlogon = @{ shell = (RegVal $wl 'Shell'); userinit = (RegVal $wl 'Userinit'); userShell = (RegVal 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell') }
$R.ifeo = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object { $d = (Get-ItemProperty -LiteralPath $_.PSPath).Debugger; if ($d) { [pscustomobject]@{ exe = $_.PSChildName; debugger = $d } } })
$R.appinit = @{ dlls = (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs'); load = (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'LoadAppInit_DLLs') }
$R.accessibility = @(foreach ($n in 'sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe') { $p = Join-Path $env:SystemRoot "System32\$n"; $s = SigOf $p; [pscustomobject]@{ exe = $n; original = $s.original; status = $s.status; signer = $s.signer } })
$R.wmi = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | ForEach-Object { [pscustomobject]@{ name = $_.Name; kind = $_.CimClass.CimClassName; command = "$($_.CommandLineTemplate)$($_.ScriptText)".Substring(0, [Math]::Min(400, "$($_.CommandLineTemplate)$($_.ScriptText)".Length)) } })

# contas
$R.users = @(Get-LocalUser | ForEach-Object { [pscustomobject]@{ name = $_.Name; enabled = $_.Enabled; rid = ($_.SID.Value -split '-')[-1]; passwordRequired = $_.PasswordRequired; passwordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('o') }; lastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('o') }; description = $_.Description } })
$R.admins = @(Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { [pscustomobject]@{ name = "$($_.Name)"; source = "$($_.PrincipalSource)"; kind = "$($_.ObjectClass)" } })
$R.me = "$env:USERDOMAIN\$env:USERNAME"

# rede: hosts, proxy, DNS, acesso remoto
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$R.hosts = @(Get-Content -LiteralPath $hosts | Where-Object { $_ -match '^\s*[0-9a-fA-F:.]+\s+\S' } | ForEach-Object { $_.Trim() })
$is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$R.proxy = @{ enabled = (RegVal $is 'ProxyEnable'); server = (RegVal $is 'ProxyServer'); pac = (RegVal $is 'AutoConfigURL'); winhttp = ((netsh winhttp show proxy) -join ' ') -replace '\s+', ' ' }
$remoteNames = 'anydesk|teamviewer|rustdesk|ultraviewer|screenconnect|connectwise|netsupport|client32|ammyy|aeroadmin|supremo|splashtop|remoteutilities|rutserv|rfusclient|dwagent|dwservice|zoho.?assist|logmein|gotoassist|vnc|radmin|ateraagent|level.?agent|meshagent|tightvnc|ultravnc|chrome.?remote.?desktop|remotepc|ninja.?rmm|syncro|action1|getscreen'
$R.remote = @{
  running = @(Get-Process | Where-Object { $_.ProcessName -match $remoteNames } | ForEach-Object { [pscustomobject]@{ name = $_.ProcessName; path = $_.Path } } | Sort-Object name -Unique)
  installed = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -match $remoteNames } | ForEach-Object { [pscustomobject]@{ name = $_.DisplayName; publisher = $_.Publisher; installed = $_.InstallDate } } | Sort-Object name -Unique)
  services = @($svc | Where-Object { $_.name -match $remoteNames -or $_.path -match $remoteNames } | ForEach-Object { [pscustomobject]@{ name = $_.display; start = $_.start; state = $_.state } })
}
if ($Light) { if ($Out) { $R | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $Out -Encoding UTF8 } else { $R | ConvertTo-Json -Depth 6 -Compress }; return }

# ---------------------------------------------------------------- proteção do Windows
$os = Get-CimInstance Win32_OperatingSystem
$R.os = @{ caption = $os.Caption; build = [int]$os.BuildNumber; display = (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'); installed = $os.InstallDate.ToString('o'); boot = $os.LastBootUpTime.ToString('o') }
$mp = Get-MpComputerStatus
$R.defender = if ($mp) { @{ service = $mp.AMServiceEnabled; av = $mp.AntivirusEnabled; realtime = $mp.RealTimeProtectionEnabled; tamper = $mp.IsTamperProtected; sigAge = $mp.AntivirusSignatureAge; quickAge = $mp.QuickScanAge; fullAge = $mp.FullScanAge; behavior = $mp.BehaviorMonitorEnabled; ioav = $mp.IoavProtectionEnabled; mode = "$($mp.AMRunningMode)" } } else { $null }
$R.avProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [pscustomobject]@{ name = $_.displayName; state = $_.productState } })
$R.threats = @(Get-MpThreatDetection | Select-Object -First 30 | ForEach-Object { $t = Get-MpThreat -ThreatID $_.ThreatID; [pscustomobject]@{ name = $t.ThreatName; severity = $t.SeverityID; when = $_.InitialDetectionTime.ToString('o'); resources = @($_.Resources | Select-Object -First 3); action = $_.ActionSuccess; status = $_.ThreatStatusID } })
$R.firewall = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ name = "$($_.Name)"; enabled = [bool]$_.Enabled; inbound = "$($_.DefaultInboundAction)" } })
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$R.updates = @{ lastHotfix = if ($hf) { $hf.InstalledOn.ToString('o') }; lastKb = $hf.HotFixID; uso = "$((Get-Service wuauserv).StartType)" }
$pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$R.uac = @{ lua = (RegVal $pol 'EnableLUA'); prompt = (RegVal $pol 'ConsentPromptBehaviorAdmin'); secureDesktop = (RegVal $pol 'PromptOnSecureDesktop') }
$R.smartscreen = @{ explorer = (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'); policy = (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen') }
$R.hardening = @{ secureBoot = (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'); hvci = (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled')
  lsaPpl = (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'); smb1 = (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'); smb1Client = "$((Get-Service mrxsmb10).Status)"
  autorun = (RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') }
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$R.remoteAccess = @{ rdpDeny = (RegVal $ts 'fDenyTSConnections'); nla = (RegVal "$ts\WinStations\RDP-Tcp" 'UserAuthentication'); assistance = (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'); winrm = "$((Get-Service WinRM).Status)"; ssh = "$((Get-Service sshd).Status)" }
$R.autologon = @{ enabled = (RegVal $wl 'AutoAdminLogon'); user = (RegVal $wl 'DefaultUserName'); hasPassword = [bool](RegVal $wl 'DefaultPassword') } # a senha em si nunca é lida para fora

# portas abertas para a rede (escutando em todas as interfaces) e conexões para fora
$procPath = @{}; foreach ($p in Get-Process) { $procPath[$p.Id] = @{ name = $p.ProcessName; path = $p.Path } }
$R.listening = @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' } | Sort-Object LocalPort -Unique | ForEach-Object { $pp = $procPath[[int]$_.OwningProcess]; [pscustomobject]@{ port = $_.LocalPort; pid = $_.OwningProcess; name = $pp.name; path = $pp.path } })
$R.connections = @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80|::$)' } | Group-Object OwningProcess | ForEach-Object { $pp = $procPath[[int]$_.Name]; [pscustomobject]@{ pid = [int]$_.Name; name = $pp.name; path = $pp.path; count = $_.Count; remotes = @($_.Group | Select-Object -First 4 | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" }) } })
$R.shares = @(Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object { [pscustomobject]@{ name = $_.Name; path = $_.Path } })
# DNS colocado à mão (o que vem do provedor/roteador automaticamente fica em DhcpNameServer, não em NameServer)
$R.dnsManual = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' | ForEach-Object { $ns = (Get-ItemProperty -LiteralPath $_.PSPath).NameServer; if ($ns) { $ns -split '[ ,]' | Where-Object { $_ } } } | Sort-Object -Unique)
$R.dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { [pscustomobject]@{ iface = $_.InterfaceAlias; servers = @($_.ServerAddresses) } })
$wl2 = netsh wlan show interfaces 2>$null
$R.wifi = @{ ssid = (($wl2 | Where-Object { $_ -match '^\s*SSID\s*:' } | Select-Object -First 1) -replace '^.*?:\s*', ''); auth = (($wl2 | Where-Object { $_ -match '^\s*(Autentica|Authentication)' } | Select-Object -First 1) -replace '^.*?:\s*', '') }

# processos que fingem ser do Windows ou rodam de pastas estranhas
$sysNames = 'svchost|lsass|csrss|winlogon|services|smss|wininit|explorer|spoolsv|taskhostw|dllhost|conhost|rundll32|regsvr32|lsm|dwm|ctfmon|sihost|runtimebroker|searchindexer'
$R.processes = @(Get-Process | Where-Object { $_.Path } | ForEach-Object {
  $p = $_.Path; $odd = $p -match '\\(Temp|AppData\\Local\\Temp|Downloads|\$Recycle\.Bin|Users\\Public|PerfLogs)\\' -or $p -match '^[A-Z]:\\ProgramData\\[^\\]+\.exe$'
  $fake = ($_.ProcessName -match "^($sysNames)$") -and ($p -notlike "$env:SystemRoot\*")
  if ($odd -or $fake) { [pscustomobject]@{ pid = $_.Id; name = $_.ProcessName; path = $p; fake = $fake; sig = (SigOf $p); cpu = [int]$_.CPU } }
})
# executáveis e scripts novos (30 dias) em pastas onde programas normais não instalam
$since = (Get-Date).AddDays(-30)
$spots = @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA", "$env:PUBLIC", "$env:ProgramData", "$env:SystemDrive\Users\Public\Documents")
$exts = '\.(exe|scr|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|pif|com)$'
# na Temp só executáveis (ferramentas deixam scripts .js temporários lá o tempo todo)
$R.newFiles = @(@(foreach ($d in $spots) { Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Name -match $(if ($d -eq $env:TEMP) { '\.(exe|scr|dll|com|pif)$' } else { $exts }) -and $_.CreationTime -gt $since -and $_.Length -lt 200MB } | Select-Object -First 30 | ForEach-Object { $s = if ($_.Extension -match 'exe|scr|dll|com|pif') { SigOf $_.FullName } else { @{ status = 'Script' } }; [pscustomobject]@{ path = $_.FullName; created = $_.CreationTime.ToString('o'); size = $_.Length; sig = $s } } }) | Where-Object { $_.sig.status -ne 'Valid' })

# extensões dos navegadores (só nome e permissões)
$R.extensions = @(foreach ($b in @(@('Chrome', "$env:LOCALAPPDATA\Google\Chrome\User Data"), @('Edge', "$env:LOCALAPPDATA\Microsoft\Edge\User Data"), @('Brave', "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"), @('Opera', "$env:APPDATA\Opera Software\Opera Stable"))) {
  foreach ($prof in Get-ChildItem -LiteralPath $b[1] -Directory | Where-Object { $_.Name -match '^(Default|Profile \d+)$' -or $b[0] -eq 'Opera' }) {
    $ext = if ($b[0] -eq 'Opera') { Join-Path $b[1] 'Extensions' } else { Join-Path $prof.FullName 'Extensions' }
    foreach ($e in Get-ChildItem -LiteralPath $ext -Directory) {
      $mf = Get-ChildItem -LiteralPath $e.FullName -Directory | Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object { Join-Path $_.FullName 'manifest.json' }
      $j = Try-Get { Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json }
      if (-not $j) { continue }
      $name = "$($j.name)"
      if ($name -like '__MSG_*') { $key = $name -replace '^__MSG_|__$', ''; $loc = Join-Path (Split-Path $mf) "_locales\$($j.default_locale)\messages.json"; $m = Try-Get { Get-Content -LiteralPath $loc -Raw -Encoding UTF8 | ConvertFrom-Json }; if ($m) { $hit = $m.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1; if ($hit) { $name = $hit.Value.message } } }
      [pscustomobject]@{ browser = $b[0]; id = $e.Name; name = $name; perms = @($j.permissions) + @($j.host_permissions) | Where-Object { $_ -is [string] } | Select-Object -First 15; update = "$($j.update_url)" }
    }
    if ($b[0] -eq 'Opera') { break }
  }
} ) | Sort-Object browser, id -Unique

# registros do Windows (os que um usuário comum consegue ler)
$d30 = (Get-Date).AddDays(-30)
$R.events = @{
  logCleared = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104; StartTime = $d30 } -MaxEvents 5 | ForEach-Object { $_.TimeCreated.ToString('o') })
  newServices = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $d30 } -MaxEvents 40 | ForEach-Object { $x = [xml]$_.ToXml(); $dd = @{}; foreach ($n in $x.Event.EventData.Data) { $dd[$n.Name] = $n.'#text' }; [pscustomobject]@{ when = $_.TimeCreated.ToString('o'); name = $dd.ServiceName; file = $dd.ImagePath; account = $dd.AccountName } })
  defenderOff = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001, 5010, 5012; StartTime = $d30 } -MaxEvents 10 | ForEach-Object { [pscustomobject]@{ when = $_.TimeCreated.ToString('o'); id = $_.Id } })
}

# ---------------------------------------------------------------- só como administrador
if ($Admin -and $R.admin) {
  $pref = Get-MpPreference
  $R.exclusions = @{ paths = @($pref.ExclusionPath | Where-Object { $_ -and $_ -notlike 'N/A*' }); processes = @($pref.ExclusionProcess | Where-Object { $_ -and $_ -notlike 'N/A*' }); extensions = @($pref.ExclusionExtension | Where-Object { $_ -and $_ -notlike 'N/A*' }) }
  $d7 = (Get-Date).AddDays(-7)
  $R.security = @{
    cleared = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $d30 } -MaxEvents 5 | ForEach-Object { $_.TimeCreated.ToString('o') })
    usersCreated = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = $d30 } -MaxEvents 20 | ForEach-Object { $x = [xml]$_.ToXml(); $dd = @{}; foreach ($n in $x.Event.EventData.Data) { $dd[$n.Name] = $n.'#text' }; [pscustomobject]@{ when = $_.TimeCreated.ToString('o'); user = $dd.TargetUserName; by = $dd.SubjectUserName } })
    addedToAdmins = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4732; StartTime = $d30 } -MaxEvents 20 | ForEach-Object { $x = [xml]$_.ToXml(); $dd = @{}; foreach ($n in $x.Event.EventData.Data) { $dd[$n.Name] = $n.'#text' }; [pscustomobject]@{ when = $_.TimeCreated.ToString('o'); member = $dd.MemberName; sid = $dd.MemberSid; group = $dd.TargetUserName; by = $dd.SubjectUserName } })
    failedLogons = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $d7 } -MaxEvents 2000 | ForEach-Object { $x = [xml]$_.ToXml(); $dd = @{}; foreach ($n in $x.Event.EventData.Data) { $dd[$n.Name] = $n.'#text' }; [pscustomobject]@{ type = $dd.LogonType; ip = $dd.IpAddress; user = $dd.TargetUserName } } | Group-Object type, ip | ForEach-Object { [pscustomobject]@{ key = $_.Name; count = $_.Count; users = @($_.Group | Select-Object -ExpandProperty user -Unique | Select-Object -First 5) } })
  }
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
  $R.bitlocker = if ($bl) { @{ status = "$($bl.ProtectionStatus)"; percent = $bl.EncryptionPercentage; method = "$($bl.EncryptionMethod)" } } else { $null }
  $tpm = Get-Tpm
  $R.tpm = if ($tpm) { @{ present = $tpm.TpmPresent; ready = $tpm.TpmReady } } else { $null }
  $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
  $R.smb1Feature = if ($f) { "$($f.State)" } else { $null }
}

$json = $R | ConvertTo-Json -Depth 7 -Compress
if ($Out) { [IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding $false)) } else { $json }
