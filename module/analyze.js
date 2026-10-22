// Piphin Escudo · análise: transforma a coleta (collect.ps1) em achados em linguagem simples, com gravidade e correção.
// Gravidade: critical (provável invasão ou porta aberta grave), high, medium, low, info (só para saber).
// Categoria: "invasao" (sinais de que alguém mexeu no PC), "brecha" (por onde alguém poderia entrar), "protecao" (defesas do Windows).
const SEV = { critical: 30, high: 14, medium: 6, low: 2, info: 0 };
const low = (s) => String(s || "").toLowerCase();
const writable = (p) => /\\users\\[^\\]+\\(appdata|downloads|desktop|documents|music|pictures|videos)\\|\\temp\\|\\windows\\temp\\|^[a-z]:\\programdata\\|\\users\\public\\|\$recycle\.bin|^[a-z]:\\perflogs\\/i.test(p || "");
const signed = (s) => s && s.status === "Valid";
const signer = (s) => (s && s.signer) || (s && s.company) || "";
// comandos que vírus usam para baixar e rodar coisas escondido
const SHADY = /-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{20,}|frombase64string|\biex\b|invoke-expression|downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|bitsadmin\s+\/transfer|certutil.*-urlcache|\bmshta\b|\bwscript\b|\bcscript\b|regsvr32.*\/i:\s*https?|rundll32.*(javascript|url\.dll)|-w(indowstyle)?\s+h(idden)?/i;
const ACCESS = { "sethc.exe": "sethc.exe", "utilman.exe": "utilman2.exe", "osk.exe": "osk.exe", "magnify.exe": "screenmagnifier.exe", "narrator.exe": "sr.exe", "displayswitch.exe": "displayswitch.exe" };
const WMI_OK = /^(scm event log consumer|bvtconsumer)$/i;
const DNS_OK = /^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.112\.112|208\.67\.222\.222|208\.67\.220\.220|94\.140\.14\.14|94\.140\.15\.15|76\.76\.2\.\d+|185\.228\.168\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|127\.0\.0\.1|100\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+)$/;
const BIG_SITES = /(google|gmail|youtube|microsoft|windowsupdate|live\.com|outlook|office|bing|facebook|instagram|whatsapp|twitter|x\.com|paypal|mercadopago|mercadolivre|nubank|itau|bradesco|santander|caixa|bb\.com|inter\.co|c6bank|picpay|banco|steam|epicgames|discord|roblox|riotgames|apple|icloud|amazon)/i;
const AV_SITES = /(avast|avg\.com|kaspersky|eset|malwarebytes|norton|mcafee|bitdefender|avira|sophos|trendmicro|virustotal|defender|wdcp\.microsoft|update\.microsoft)/i;
const RISKY_PORTS = { 21: "FTP", 22: "SSH", 23: "Telnet", 3389: "Área de Trabalho Remota", 5900: "VNC", 5901: "VNC", 5938: "TeamViewer", 5985: "WinRM", 5986: "WinRM", 1433: "SQL Server", 3306: "MySQL", 27017: "MongoDB", 4444: "porta comum de vírus", 6667: "IRC (vírus antigos)", 31337: "porta comum de vírus" };
const age = (iso) => (iso ? (Date.now() - Date.parse(iso)) / 86400000 : Infinity);
const short = (p) => String(p || "").replace(/^C:\\Users\\[^\\]+/i, "%PERFIL%");

// opts.trusted: pastas que nunca são suspeitas (o próprio Piphin Hub, que roda o Escudo)
function analyze(d, opts = {}) {
  const trusted = (opts.trusted || []).map(low);
  const isTrusted = (p) => trusted.some((t) => low(p).startsWith(t));
  const F = [], good = [];
  const add = (f) => F.push({ details: [], fix: null, ...f });
  const yes = (t) => good.push(t);

  // ---------------------------------------------------------------- sinais de invasão
  for (const a of d.accessibility || []) {
    const want = ACCESS[low(a.exe)], orig = low(a.original);
    if ((orig && want && orig !== want) || (a.status && a.status !== "Valid")) add({ id: "access:" + a.exe, cat: "invasao", sev: "critical", title: `A tecla de acessibilidade "${a.exe}" foi trocada`,
      text: "Esse é um truque clássico de invasores: trocam um programa de acessibilidade (como as Teclas de Aderência, ao apertar Shift 5 vezes) por outro, para abrir um terminal na tela de login sem senha.",
      details: [`Esperado: ${want} · encontrado: ${a.original || "?"} (${a.status})`], fix: { id: "defender_scan_file", params: { path: `%SystemRoot%\\System32\\${a.exe}` } } });
  }
  for (const i of d.ifeo || []) add({ id: "ifeo:" + i.exe, cat: "invasao", sev: /^(sethc|utilman|osk|magnify|narrator|taskmgr|msconfig|regedit|msmpeng|mrt|cmd|powershell)\.exe$/i.test(i.exe) ? "critical" : "high",
    title: `O programa "${i.exe}" foi desviado para outro`, text: "Uma configuração escondida do Windows (Debugger) faz outro programa abrir no lugar desse. Vírus usam isso para impedir que você abra o Gerenciador de Tarefas ou o antivírus, ou para criar uma porta dos fundos.",
    details: [`Abre no lugar: ${i.debugger}`], fix: { id: "ifeo_remove", params: { exe: i.exe } } });
  const w = d.winlogon || {};
  if ((w.shell && low(w.shell).replace(/\s/g, "") !== "explorer.exe") || (w.userinit && !/^c:\\windows\\system32\\userinit\.exe,?$/i.test(String(w.userinit).trim())) || w.userShell)
    add({ id: "winlogon", cat: "invasao", sev: "critical", title: "O que abre no login do Windows foi alterado", text: "O Windows sempre abre o explorer.exe e o userinit.exe quando você entra. Outro programa nessa lista é uma forma de um vírus abrir junto com tudo, antes de qualquer coisa.",
      details: [`Shell: ${w.shell || "-"}`, `Userinit: ${w.userinit || "-"}`, ...(w.userShell ? [`Shell do usuário: ${w.userShell}`] : [])], fix: { id: "winlogon_fix", params: {} } });
  if (d.appinit && d.appinit.dlls && String(d.appinit.dlls).trim() && d.appinit.load) add({ id: "appinit", cat: "invasao", sev: "high", title: "Uma DLL é carregada dentro de todos os programas", text: "AppInit_DLLs injeta um arquivo em todo programa que abre. É raro hoje em dia e muito usado por programas maliciosos.", details: [d.appinit.dlls] });
  for (const c of (d.wmi || []).filter((x) => !WMI_OK.test(x.name))) add({ id: "wmi:" + c.name, cat: "invasao", sev: SHADY.test(c.command) ? "critical" : "high", title: `Gatilho escondido do Windows: "${c.name}"`,
    text: "Uma assinatura WMI roda um comando sozinha quando algo acontece no PC. Quase nenhum programa normal usa isso; é uma forma de invasores ficarem no PC sem aparecer na inicialização.", details: [c.kind, c.command || "(sem comando visível)"] });

  // o que abre sozinho com o Windows
  const auto = [
    ...(d.run || []).map((r) => ({ ...r, kind: "run", label: r.name, where: r.key.replace(/^HK(LM|CU):\\(SOFTWARE|Software)\\/, "HK$1\\…\\") })),
    ...(d.startup || []).map((r) => ({ ...r, kind: "startup", label: r.file.split("\\").pop(), where: "Pasta Inicializar" })),
    ...(d.tasks || []).map((r) => ({ ...r, kind: "task", label: r.name, where: "Tarefa agendada " + r.taskPath })),
  ];
  let autoOk = 0;
  for (const a of auto) {
    const key = `${a.kind}:${a.key || a.taskPath || ""}${a.label}`;
    const fix = a.kind === "run" ? { id: "run_disable", params: { key: a.key, name: a.name } } : a.kind === "startup" ? { id: "startup_disable", params: { file: a.file } } : { id: "task_disable", params: { path: a.taskPath, name: a.name } };
    const det = [`Comando: ${a.command}`, `Onde: ${a.where}`, signed(a.sig) ? `Assinado por: ${signer(a.sig)}` : a.sig && a.sig.exists ? "Sem assinatura digital válida" : "O programa não existe mais"];
    if (isTrusted(a.path)) { autoOk++; continue; }
    if (SHADY.test(a.command)) add({ id: key, cat: "invasao", sev: "critical", title: `"${a.label}" abre com o Windows e roda um comando escondido`, text: "Esse item baixa ou executa código escondido (PowerShell codificado, mshta, scripts). É o jeito mais comum de um vírus voltar toda vez que o PC liga.", details: det, fix });
    else if (a.sig && a.sig.exists && !signed(a.sig) && writable(a.path)) add({ id: key, cat: "invasao", sev: a.hidden ? "high" : "medium", title: `"${a.label}" abre com o Windows sem assinatura, de uma pasta comum`, text: "Programas de verdade normalmente são assinados pela empresa que fez. Este não é, e fica numa pasta onde qualquer programa consegue gravar. Pode ser legítimo (programa pequeno ou feito em casa), mas vale conferir.", details: det, fix });
    else if (a.sig && !a.sig.exists && a.path) add({ id: key, cat: "invasao", sev: "low", title: `"${a.label}" aponta para um programa que não foi encontrado`, text: "O programa foi desinstalado ou fica num disco que não está conectado agora. Não é perigoso; se o programa não existe mais, dá para retirar.", details: det, fix });
    else autoOk++;
  }
  if (autoOk) yes(`${autoOk} ${autoOk === 1 ? "programa abre" : "programas abrem"} com o Windows e ${autoOk === 1 ? "está assinado" : "estão assinados"} ou no lugar certo`);
  for (const s of d.services || []) {
    if (!s.path) continue;
    const det = [`Arquivo: ${s.path}`, `Início: ${s.start} · ${s.state} · conta ${s.account || "-"}`, signed(s.sig) ? `Assinado por: ${signer(s.sig)}` : "Sem assinatura digital válida"];
    if (/\\temp\\/i.test(s.path) || SHADY.test(s.command)) add({ id: "svc:" + s.name, cat: "invasao", sev: "critical", title: `Serviço "${s.display || s.name}" roda de uma pasta temporária`, text: "Serviços rodam com poder total no PC. Um serviço rodando da pasta Temp ou com comando escondido é um sinal forte de invasão.", details: det, fix: { id: "service_disable", params: { name: s.name } } });
    else if (s.sig && s.sig.exists && !signed(s.sig) && writable(s.path)) add({ id: "svc:" + s.name, cat: "invasao", sev: "high", title: `Serviço sem assinatura: "${s.display || s.name}"`, text: "Um serviço (roda com poder total, até sem ninguém logado) sem assinatura e numa pasta comum. Confira se você sabe de onde ele veio.", details: det, fix: { id: "service_disable", params: { name: s.name } } });
  }
  for (const e of (d.events && d.events.newServices) || []) {
    const f = String(e.file || "");
    if (writable(f) || /\\temp\\|powershell|cmd\.exe \/c|%comspec%/i.test(f)) add({ id: "newsvc:" + e.name + e.when, cat: "invasao", sev: "high", title: `Serviço novo instalado: "${e.name}"`, text: "Nos últimos 30 dias foi instalado um serviço que roda de uma pasta comum ou executa comandos. Ferramentas de invasão costumam se instalar assim.", details: [`Quando: ${new Date(e.when).toLocaleString("pt-BR")}`, `Arquivo: ${f}`, `Conta: ${e.account || "-"}`] });
  }
  const seenProc = new Set();
  for (const p of d.processes || []) {
    if (isTrusted(p.path) || seenProc.has(low(p.path))) continue; // um achado por programa (não por processo)
    seenProc.add(low(p.path));
    const det = [`Arquivo: ${p.path}`, signed(p.sig) ? `Assinado por: ${signer(p.sig)}` : "Sem assinatura digital válida"];
    const dl = /\\downloads\\/i.test(p.path) && !p.fake;
    if (p.fake) add({ id: "fake:" + p.path, cat: "invasao", sev: "critical", title: `"${p.name}" está fingindo ser do Windows`, text: `O verdadeiro ${p.name}.exe fica só dentro da pasta do Windows. Este está em outro lugar, um disfarce comum de vírus.`, details: det, fix: { id: "defender_scan_file", params: { path: p.path, pid: p.pid } } });
    else if (!signed(p.sig) && dl) add({ id: "proc:" + p.path, cat: "invasao", sev: "low", title: `"${p.name}" roda da pasta Downloads sem assinatura`, text: "Programas portáteis (que não precisam instalar) costumam rodar de onde foram baixados. Se você reconhece, tudo bem; se não, mande o antivírus verificar.", details: det, fix: { id: "defender_scan_file", params: { path: p.path, pid: p.pid } } });
    else if (!signed(p.sig)) add({ id: "proc:" + p.path, cat: "invasao", sev: "medium", title: `"${p.name}" está rodando de uma pasta estranha`, text: "Um programa sem assinatura rodando agora de uma pasta temporária, da Lixeira ou da pasta Pública. Pode ser um instalador, mas também é o lugar preferido de vírus.", details: det, fix: { id: "defender_scan_file", params: { path: p.path, pid: p.pid } } });
  }
  const loose = (d.newFiles || []).filter((f) => !signed(f.sig));
  if (loose.length) add({ id: "newfiles", cat: "invasao", sev: loose.some((f) => /\.(vbs|vbe|js|jse|hta|scr|pif)$/i.test(f.path)) ? "medium" : "low", title: `${loose.length} ${loose.length === 1 ? "arquivo executável novo e solto" : "arquivos executáveis novos e soltos"} em pastas do usuário`,
    text: "Programas e scripts sem assinatura que apareceram nos últimos 30 dias direto nas pastas AppData, Temp ou ProgramData (fora da pasta de um programa). Instaladores deixam isso às vezes; vírus também.",
    details: loose.slice(0, 12).map((f) => `${short(f.path)} · ${new Date(f.created).toLocaleDateString("pt-BR")}`), fix: { id: "defender_scan_files", params: { paths: loose.map((f) => f.path).slice(0, 30) } } });
  // rede sequestrada
  for (const h of d.hosts || []) {
    const [ip, ...names] = h.split(/\s+/), host = names.join(" ");
    const sink = /^(0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(ip);
    if (!sink && BIG_SITES.test(host)) add({ id: "hosts:" + h, cat: "invasao", sev: "critical", title: `Site importante desviado no arquivo hosts: ${host}`, text: "O arquivo hosts manda o seu PC para outro endereço quando você digita esse site. É usado para golpes: você vê a página do banco ou do e-mail, mas é uma cópia falsa.", details: [h], fix: { id: "hosts_fix", params: { line: h } } });
    else if (sink && AV_SITES.test(host)) add({ id: "hosts:" + h, cat: "invasao", sev: "high", title: `Site de antivírus bloqueado no arquivo hosts: ${host}`, text: "Bloquear sites de antivírus e de atualização é o que vírus fazem para não serem removidos.", details: [h], fix: { id: "hosts_fix", params: { line: h } } });
  }
  const px = d.proxy || {};
  if ((px.enabled && px.server) || px.pac) {
    const local = /^(127\.0\.0\.1|localhost)/i.test(String(px.server || ""));
    add({ id: "proxy", cat: "invasao", sev: local && !px.pac ? "medium" : "high", title: px.pac ? "A internet passa por um script de proxy" : `A internet passa por um proxy: ${px.server}`, text: "Todo o tráfego dos navegadores passa por outro computador antes de chegar aos sites. Programas de VPN e de empresa fazem isso; vírus que roubam senhas também.", details: [px.server ? `Servidor: ${px.server}` : "", px.pac ? `Script: ${px.pac}` : ""].filter(Boolean), fix: { id: "proxy_off", params: {} } });
  }
  if (/proxy\s*server|servidor\s*proxy/i.test(px.winhttp || "") && !/direto|direct/i.test(px.winhttp || "")) add({ id: "winhttp", cat: "invasao", sev: "medium", title: "O Windows usa um proxy para as atualizações", text: "O proxy do sistema (WinHTTP) está configurado. Se você não usa rede de empresa, pode ser obra de um programa malicioso.", details: [px.winhttp] });
  // só o DNS colocado à mão (o do provedor vem automático e é normal)
  for (const s of (d.dnsManual || []).filter((x) => !DNS_OK.test(x))) add({ id: "dns:" + s, cat: "invasao", sev: "medium", title: `DNS colocado à mão e desconhecido: ${s}`, text: "O DNS traduz nomes de sites em endereços. Alguém configurou esse servidor manualmente no Windows, e ele não é de nenhum serviço conhecido (Google, Cloudflare, Quad9, OpenDNS...). Um DNS trocado por um vírus pode mandar você para sites falsos.", details: [`Todos os DNS colocados à mão: ${d.dnsManual.join(", ")}`] });
  if (d.dnsManual && !(d.dnsManual || []).some((x) => !DNS_OK.test(x))) yes((d.dnsManual || []).length ? "DNS conhecido" : "DNS automático (do provedor)");
  // acesso remoto
  const rem = d.remote || {}, remNames = [...new Set([...(rem.running || []).map((x) => x.name), ...(rem.installed || []).map((x) => x.name), ...(rem.services || []).map((x) => x.name)])];
  if (remNames.length) add({ id: "remote:" + remNames.sort().join(","), cat: "invasao", sev: (rem.running || []).length ? "high" : "medium", title: (rem.running || []).length ? "Programa de acesso remoto aberto agora" : "Programa de acesso remoto instalado",
    text: "Esses programas deixam outra pessoa ver e controlar o seu PC. São úteis, mas golpistas sempre pedem para instalar um deles (\"suporte do banco\", \"técnico da Microsoft\"). Se você não usa, desinstale.",
    details: [...(rem.running || []).map((x) => `Aberto: ${x.name} (${x.path || "?"})`), ...(rem.installed || []).map((x) => `Instalado: ${x.name}${x.publisher ? " · " + x.publisher : ""}`), ...(rem.services || []).map((x) => `Serviço: ${x.name} (${x.start}, ${x.state})`)] });
  else yes("Nenhum programa de acesso remoto (AnyDesk, TeamViewer...)");
  // antivírus e registros
  const th = d.threats || [];
  if (th.length) add({ id: "threats", cat: "invasao", sev: th.some((t) => t.status !== 3 && t.status !== 4 && !t.action) ? "high" : "medium", title: `O antivírus encontrou ${th.length} ${th.length === 1 ? "ameaça" : "ameaças"}`, text: "O Microsoft Defender detectou e (em geral) removeu essas ameaças. Vale saber de onde vieram: um arquivo baixado, um pendrive, um site.", details: th.slice(0, 10).map((t) => { const r = t.resources && t.resources[0] ? short(String(t.resources[0]).replace(/^(file|CmdLine):_/i, "")) : ""; return `${t.name} · ${new Date(t.when).toLocaleDateString("pt-BR")}${r ? " · " + (r.length > 110 ? r.slice(0, 110) + "…" : r) : ""}`; }) });
  else if (d.defender) yes("Nenhuma ameaça encontrada pelo antivírus");
  const ev = d.events || {};
  if ((ev.logCleared || []).length || ((d.security && d.security.cleared) || []).length) add({ id: "logcleared", cat: "invasao", sev: "high", title: "Os registros do Windows foram apagados", text: "Apagar o registro de eventos é o que invasores fazem para esconder o que fizeram. Se não foi você (ou um programa de limpeza), é um sinal sério.", details: [...(ev.logCleared || []).map((x) => "Sistema: " + new Date(x).toLocaleString("pt-BR")), ...((d.security && d.security.cleared) || []).map((x) => "Segurança: " + new Date(x).toLocaleString("pt-BR"))] });
  if ((ev.defenderOff || []).length) add({ id: "defoff", cat: "invasao", sev: "medium", title: "A proteção do antivírus foi desligada recentemente", text: "O registro do Defender mostra que a proteção em tempo real ou partes dela foram desligadas nos últimos 30 dias. Se não foi você, algo pode ter desligado de propósito.", details: ev.defenderOff.map((x) => new Date(x.when).toLocaleString("pt-BR") + " (evento " + x.id + ")") });
  if (d.exclusions) {
    const ex = [...d.exclusions.paths.map((x) => ["path", x]), ...d.exclusions.processes.map((x) => ["process", x]), ...d.exclusions.extensions.map((x) => ["extension", x])];
    if (ex.length) add({ id: "exclusions", cat: "invasao", sev: ex.some(([k, x]) => k === "extension" || /^[a-z]:\\?$|\\users\\[^\\]+\\?$|appdata|\\temp/i.test(x)) ? "critical" : "high", title: `O antivírus ignora ${ex.length} ${ex.length === 1 ? "item" : "itens"} (exceções)`,
      text: "Exceções fazem o antivírus não olhar para pastas ou programas. Vírus adoram se colocar ali. Se você não criou (alguns jogos e programas pedem), retire.", details: ex.map(([k, x]) => `${{ path: "Pasta", process: "Programa", extension: "Tipo de arquivo" }[k]}: ${x}`), fix: { id: "exclusions_remove", params: { items: ex } } });
    else yes("O antivírus não tem exceções");
  }
  if (d.security) {
    for (const u of d.security.usersCreated || []) add({ id: "newuser:" + u.user + u.when, cat: "invasao", sev: "medium", title: `Conta nova criada: ${u.user}`, text: "Uma conta de usuário foi criada nos últimos 30 dias. Se não foi você, alguém pode ter criado um acesso próprio ao PC.", details: [`Quando: ${new Date(u.when).toLocaleString("pt-BR")}`, `Por: ${u.by}`] });
    for (const u of d.security.addedToAdmins || []) add({ id: "newadmin:" + u.sid + u.when, cat: "invasao", sev: "high", title: "Uma conta virou administradora", text: "Nos últimos 30 dias uma conta foi colocada no grupo de administradores (poder total no PC).", details: [`Quando: ${new Date(u.when).toLocaleString("pt-BR")}`, `Conta: ${u.member || u.sid}`, `Por: ${u.by}`] });
    const net = (d.security.failedLogons || []).filter((g) => /^(3|10),/.test(g.key) && !/^(3|10),\s*(-|127\.0\.0\.1|::1)?$/.test(g.key));
    const total = net.reduce((a, g) => a + g.count, 0);
    if (total >= 20) add({ id: "bruteforce", cat: "invasao", sev: "high", title: `${total} tentativas de senha erradas pela rede (7 dias)`, text: "Alguém está tentando adivinhar a senha do PC pela rede (Área de Trabalho Remota ou compartilhamento). Desligue o acesso remoto se não usa e use uma senha forte.", details: net.slice(0, 8).map((g) => `${g.key.replace(/^3,/, "Rede, ").replace(/^10,/, "Área de Trabalho Remota, ")}: ${g.count} vezes · contas ${g.users.join(", ")}`), fix: { id: "rdp_off", params: {} } });
  }
  // contas
  for (const u of (d.users || []).filter((x) => x.enabled)) {
    if (/\$$/.test(u.name)) add({ id: "hidden:" + u.name, cat: "invasao", sev: "critical", title: `Conta escondida: ${u.name}`, text: "Contas que terminam com $ não aparecem na tela de login. É um truque para criar um acesso secreto ao PC.", details: [`Último acesso: ${u.lastLogon ? new Date(u.lastLogon).toLocaleString("pt-BR") : "nunca"}`] });
    if (u.rid === "501") add({ id: "guest", cat: "brecha", sev: "high", title: "A conta Convidado está ligada", text: "Qualquer pessoa pode entrar no PC sem senha pela conta Convidado.", details: [u.name], fix: { id: "guest_off", params: {} } });
  }
  const meName = low(String(d.me || "").split("\\").pop());
  const otherAdmins = (d.admins || []).filter((a) => a.kind === "User" && low(a.name.split("\\").pop()) !== meName && !(d.users || []).some((u) => low(u.name) === low(a.name.split("\\").pop()) && (!u.enabled || u.rid === "500")));
  for (const a of otherAdmins) add({ id: "admin:" + a.name, cat: "invasao", sev: "medium", title: `Outra conta com poder de administrador: ${a.name}`, text: "Além da sua, esta conta pode instalar programas e mudar tudo no PC. Se é de outra pessoa da casa, tudo bem; se você não reconhece, desconfie.", details: [`Tipo: ${a.source}`] });
  if (!otherAdmins.length && d.admins) yes("Só a sua conta é administradora");

  // ---------------------------------------------------------------- defesas do Windows
  const df = d.defender, others = (d.avProducts || []).filter((a) => !/defender/i.test(a.name) && ((a.state >> 12) & 0xf) === 1);
  if (df) {
    if (!df.av || !df.realtime) {
      if (others.length) yes(`Antivírus ativo: ${others.map((a) => a.name).join(", ")}`);
      else add({ id: "rt", cat: "protecao", sev: "critical", title: "O antivírus está desligado", text: "A proteção em tempo real do Microsoft Defender está desligada e não há outro antivírus ativo. O PC fica aberto para qualquer arquivo malicioso.", details: [`Antivírus: ${df.av ? "ligado" : "desligado"} · Tempo real: ${df.realtime ? "ligado" : "desligado"}`], fix: { id: "rt_on", params: {} } });
    } else yes("Antivírus ligado, com proteção em tempo real");
    if (df.av && df.sigAge > 7) add({ id: "sig", cat: "protecao", sev: df.sigAge > 30 ? "high" : "medium", title: `O antivírus está desatualizado (${df.sigAge} dias)`, text: "As definições de vírus não são atualizadas há dias: ameaças novas passam despercebidas.", fix: { id: "sig_update", params: {} } });
    if (df.av && !df.tamper) add({ id: "tamper", cat: "protecao", sev: "medium", title: "A proteção contra adulteração está desligada", text: "Ela impede que programas maliciosos desliguem o antivírus. Ligue em Segurança do Windows › Proteção contra vírus e ameaças › Gerenciar configurações › Proteção contra adulterações." });
    else if (df.tamper) yes("Proteção contra adulteração ligada");
    if (df.av && df.fullAge > 3650 && df.quickAge > 14) add({ id: "noscan", cat: "protecao", sev: "low", title: "Faz tempo que o antivírus não verifica o PC", text: "Uma verificação de vez em quando pega coisas que entraram antes das definições de vírus serem atualizadas.", fix: { id: "quick_scan", params: {} } });
  } else if (!others.length) add({ id: "noav", cat: "protecao", sev: "high", title: "Não deu para confirmar nenhum antivírus", text: "O Windows não informou nenhum antivírus funcionando." });
  else yes(`Antivírus ativo: ${others.map((a) => a.name).join(", ")}`);
  const fwOff = (d.firewall || []).filter((p) => !p.enabled);
  if (fwOff.length) add({ id: "fw", cat: "protecao", sev: fwOff.some((p) => /public|p[úu]blic/i.test(p.name)) ? "high" : "medium", title: `Firewall desligado (${fwOff.map((p) => ({ Domain: "domínio", Private: "rede privada", Public: "rede pública" }[p.name] || p.name)).join(", ")})`, text: "O firewall bloqueia conexões de fora que você não pediu. Sem ele, qualquer serviço aberto no PC fica exposto na rede.", fix: { id: "fw_on", params: {} } });
  else if ((d.firewall || []).length) yes("Firewall ligado em todas as redes");
  const up = d.updates || {}, upAge = age(up.lastHotfix);
  if (d.os && d.os.build && d.os.build < 22000) add({ id: "win10", cat: "protecao", sev: "high", title: "Windows 10 sem atualizações de segurança", text: "O Windows 10 parou de receber correções de segurança em outubro de 2025 (fora quem pagou o ESU). Falhas descobertas depois disso ficam abertas para sempre.", details: [d.os.caption] });
  if (upAge > 60) add({ id: "updates", cat: "protecao", sev: "high", title: `O Windows não recebe atualizações há ${Math.round(upAge)} dias`, text: "As atualizações mensais fecham falhas que já estão sendo usadas por invasores. Abra Configurações › Windows Update e instale tudo.", details: [`Última: ${up.lastKb || "?"} em ${up.lastHotfix ? new Date(up.lastHotfix).toLocaleDateString("pt-BR") : "?"}`] });
  else if (upAge > 40) add({ id: "updates", cat: "protecao", sev: "medium", title: `Última atualização do Windows há ${Math.round(upAge)} dias`, text: "Vale abrir o Windows Update e instalar o que estiver pendente.", details: [`Última: ${up.lastKb}`] });
  else if (up.lastHotfix) yes("Windows atualizado");
  const uac = d.uac || {};
  if (uac.lua === 0) add({ id: "uac", cat: "brecha", sev: "critical", title: "O Controle de Conta de Usuário (UAC) está desligado", text: "Sem o UAC, qualquer programa ganha poder total no PC sem perguntar. É a principal barreira contra vírus que tentam se instalar.", fix: { id: "uac_on", params: {} } });
  else if (uac.prompt === 0) add({ id: "uacprompt", cat: "brecha", sev: "high", title: "O UAC está configurado para nunca avisar", text: "Programas ganham poder de administrador sem a janela de confirmação.", fix: { id: "uac_on", params: {} } });
  else if (uac.lua === 1) yes("Controle de Conta de Usuário (UAC) ligado");
  const ss = d.smartscreen || {};
  if (low(ss.explorer) === "off" || ss.policy === 0) add({ id: "smartscreen", cat: "protecao", sev: "medium", title: "O SmartScreen está desligado", text: "O SmartScreen avisa antes de abrir programas baixados desconhecidos. Ligue em Segurança do Windows › Controle de aplicativos e do navegador." });
  const hd = d.hardening || {};
  if (hd.smb1 === 1 || d.smb1Feature === "Enabled") add({ id: "smb1", cat: "brecha", sev: "high", title: "O protocolo antigo SMBv1 está ligado", text: "O SMBv1 é o compartilhamento de arquivos de 30 anos atrás, usado pelo WannaCry para se espalhar. Nenhum PC moderno precisa dele.", fix: { id: "smb1_off", params: {} } });
  if (hd.secureBoot === 0) add({ id: "secureboot", cat: "protecao", sev: "low", title: "Inicialização Segura (Secure Boot) desligada", text: "Ela impede que vírus se instalem antes do Windows ligar (rootkits). Liga-se na BIOS/UEFI da placa-mãe." });
  else if (hd.secureBoot === 1) yes("Inicialização Segura (Secure Boot) ligada");
  if (hd.hvci === 1) yes("Integridade de Memória ligada");
  else add({ id: "hvci", cat: "protecao", sev: "low", title: "Integridade de Memória desligada", text: "Ela protege o coração do Windows contra drivers maliciosos. Ligue em Segurança do Windows › Segurança do dispositivo › Isolamento de núcleo (alguns drivers antigos podem não ser compatíveis)." });
  const ra = d.remoteAccess || {};
  if (ra.rdpDeny === 0) add({ id: "rdp", cat: "brecha", sev: ra.nla === 0 ? "high" : "medium", title: "Área de Trabalho Remota ligada", text: "Outras pessoas podem tentar entrar no seu PC pela rede. Se você não usa, desligue: é uma das portas mais atacadas da internet.", details: [ra.nla === 0 ? "Sem autenticação no nível da rede (mais perigoso)" : "Com autenticação no nível da rede"], fix: { id: "rdp_off", params: {} } });
  if (ra.assistance === 1) add({ id: "assist", cat: "brecha", sev: "low", title: "Assistência Remota ligada", text: "Permite que alguém, com um convite seu, controle o PC. Pouca gente usa; golpistas às vezes pedem.", fix: { id: "assist_off", params: {} } });
  if (low(ra.ssh) === "running") add({ id: "ssh", cat: "brecha", sev: "medium", title: "Servidor SSH ligado", text: "O PC aceita acesso por terminal pela rede. Se não foi você que configurou, desligue." });
  const al = d.autologon || {};
  if (String(al.enabled) === "1" && al.hasPassword) add({ id: "autologon", cat: "brecha", sev: "high", title: "Login automático com a senha guardada sem proteção", text: "O Windows está entrando sozinho e a senha da conta fica gravada em texto puro no registro. Qualquer programa consegue ler.", details: [`Conta: ${al.user || "?"}`], fix: { id: "autologon_off", params: {} } });
  for (const l of d.listening || []) {
    const risky = RISKY_PORTS[l.port];
    if (risky && !(l.port === 3389 && ra.rdpDeny === 0)) add({ id: "port:" + l.port, cat: "brecha", sev: l.port === 4444 || l.port === 31337 || l.port === 6667 ? "high" : "medium", title: `Porta ${l.port} (${risky}) aberta para a rede`, text: "Um programa está esperando conexões de outros computadores nessa porta. Se você não instalou um servidor desse tipo, investigue.", details: [`Programa: ${l.name || "?"} ${l.path ? "(" + l.path + ")" : ""}`] });
    else if (l.path && writable(l.path)) add({ id: "port:" + l.port, cat: "brecha", sev: "medium", title: `Programa de pasta comum aceitando conexões: ${l.name} (porta ${l.port})`, text: "Programas que recebem conexões de fora normalmente ficam em Arquivos de Programas. Jogos e apps de comunicação fazem isso às vezes; vírus de controle remoto também.", details: [l.path] });
  }
  for (const s of d.shares || []) add({ id: "share:" + s.name, cat: "brecha", sev: "low", title: `Pasta compartilhada na rede: ${s.name}`, text: "Outras pessoas da rede podem ver (ou mudar) essa pasta. Se não precisa mais, pare de compartilhar.", details: [s.path] });
  const wf = d.wifi || {};
  if (wf.ssid && /open|aberta|wep/i.test(wf.auth || "")) add({ id: "wifi", cat: "brecha", sev: "high", title: `Wi-Fi sem senha (ou senha fraca de 1999): ${wf.ssid}`, text: "Numa rede aberta ou WEP, qualquer pessoa por perto pode ver o que passa pela rede. Use uma rede com WPA2/WPA3 e, em lugares públicos, prefira os dados do celular.", details: [`Segurança: ${wf.auth}`] });
  else if (wf.ssid) yes(`Wi-Fi protegido (${wf.auth || "com senha"})`);
  if (d.bitlocker) {
    if (/off|0/i.test(d.bitlocker.status)) add({ id: "bitlocker", cat: "protecao", sev: "low", title: "O disco do Windows não está criptografado", text: "Se o PC (ou o disco) for roubado, dá para ler todos os arquivos ligando o disco em outro computador. O BitLocker resolve isso (em notebooks, vale muito a pena)." });
    else yes("Disco criptografado (BitLocker)");
  }
  for (const e of (d.extensions || []).filter((x) => x.update && !/clients2\.google\.com|edge\.microsoft\.com|microsoftedge\.microsoft\.com|opera\.com/i.test(x.update)))
    add({ id: "ext:" + e.browser + e.id, cat: "invasao", sev: "medium", title: `Extensão de fora da loja no ${e.browser}: ${e.name}`, text: "Ela se atualiza de um site que não é a loja oficial do navegador. Extensões assim podem ler tudo o que você vê e digita nos sites.", details: [`Atualiza de: ${e.update}`, `Permissões: ${(e.perms || []).join(", ") || "-"}`] });

  // ---------------------------------------------------------------- nota
  const order = ["critical", "high", "medium", "low", "info"];
  F.sort((a, b) => order.indexOf(a.sev) - order.indexOf(b.sev));
  return { findings: F, good };
}

// nota de 0 a 100 e o veredito de invasão (sem os achados ignorados)
function score(findings) {
  const s = Math.max(0, 100 - findings.reduce((a, f) => a + (SEV[f.sev] || 0), 0));
  const inv = findings.filter((f) => f.cat === "invasao");
  const verdict = inv.some((f) => f.sev === "critical") ? "danger" : inv.some((f) => f.sev === "high") ? "warn" : inv.some((f) => f.sev === "medium") ? "check" : "clean";
  return { score: s, verdict };
}

module.exports = { analyze, score, SEV };
