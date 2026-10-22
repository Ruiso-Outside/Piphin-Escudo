// Piphin Escudo como módulo do Piphin Hub: verifica se o PC tem brechas de segurança ou sinais de invasão,
// corrige (com Desfazer), vigia mudanças perigosas enquanto o Hub está aberto e reúne as ferramentas de defesa.
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { analyze, score } = require("./analyze");
const fixes = require("./fixes");

const WATCH_MS = 15 * 60000;
exports.activate = (ctx) => {
  const D = (f) => path.join(ctx.dataDir, f);
  const readJson = (f, d) => { try { return JSON.parse(fs.readFileSync(D(f), "utf8").replace(/^﻿/, "")); } catch { return d; } };
  const writeJson = (f, v) => { try { fs.writeFileSync(D(f), JSON.stringify(v)); } catch (e) { ctx.log("salvar", f, e.message); } };
  let prefs = { watch: true, notify: true, ...readJson("prefs.json", {}) };
  let last = readJson("ultima.json", null); // { at, mode, raw, findings, good }
  let history = readJson("historico.json", []); // [{ at, mode, score, verdict, counts }]
  let ignored = new Set(readJson("ignorados.json", []));
  let done = readJson("correcoes.json", []); // correções feitas (para desfazer)
  let alerts = readJson("alertas.json", []);
  // o próprio Piphin Hub (que roda o Escudo) nunca é suspeito
  const trusted = [path.dirname(process.execPath) + path.sep];
  const COLLECT = path.join(ctx.dir, "collect.ps1");
  // para a tela: só texto (funções não passam pela ponte do Hub)
  const FIX_INFO = Object.fromEntries(Object.entries(fixes.FIXES).map(([k, v]) => [k, { label: v.label, undo: v.undo, restart: !!v.restart }]));

  function runPs(args, timeout = 10 * 60000) {
    return new Promise((resolve) => execFile(fixes.PS, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", ...args], { windowsHide: true, timeout, maxBuffer: 64 * 1024 * 1024 },
      (err, out, se) => resolve({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, out: String(out || ""), err: String(se || "") })));
  }
  // coleta: comum, rápida (Vigia) ou completa como administrador (um pedido do Windows)
  async function collect({ admin = false, light = false } = {}) {
    const out = path.join(os.tmpdir(), `piphin-escudo-${crypto.randomBytes(5).toString("hex")}.json`);
    try {
      if (admin) {
        const q = (s) => String(s).split("'").join("''");
        const launcher = `try { $p = Start-Process -FilePath '${q(fixes.PS)}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','"${q(COLLECT)}"','-Admin','-Out','"${q(out)}"'; exit $p.ExitCode } catch { exit 1223 }`;
        const r = await runPs(["-Command", launcher], 15 * 60000);
        if (!fs.existsSync(out)) throw Object.assign(new Error(r.code === 1223 ? "O pedido de administrador foi recusado" : "A verificação completa não respondeu"), { declined: r.code === 1223 });
      } else {
        const r = await runPs(["-File", COLLECT, ...(light ? ["-Light"] : []), "-Out", out]);
        if (!fs.existsSync(out)) throw new Error("A verificação não respondeu: " + (r.err || r.out).slice(0, 300));
      }
      return JSON.parse(fs.readFileSync(out, "utf8").replace(/^﻿/, ""));
    } finally { fs.rmSync(out, { force: true }); }
  }

  // ---------------------------------------------------------------- verificação
  let scanning = null;
  const publicState = () => {
    const f = last ? last.findings.map((x) => ({ ...x, ignored: ignored.has(x.id) })) : [];
    const active = f.filter((x) => !x.ignored);
    return { last: last && { at: last.at, mode: last.mode, findings: f, good: last.good, ...score(active), admin: !!(last.raw && last.raw.admin) }, history: history.slice(0, 30),
      done: done.slice(0, 50), alerts: alerts.slice(0, 50), prefs, scanning: !!scanning, fixes: FIX_INFO };
  };
  async function scan(mode = "quick") {
    if (scanning) return scanning;
    scanning = (async () => {
      ctx.emit("scanning", { mode });
      try {
        const raw = await collect({ admin: mode === "full" });
        const r = analyze(raw, { trusted });
        last = { at: new Date().toISOString(), mode, raw, findings: r.findings, good: r.good };
        writeJson("ultima.json", last);
        const sc = score(r.findings.filter((x) => !ignored.has(x.id)));
        const counts = {}; for (const x of r.findings) if (!ignored.has(x.id)) counts[x.sev] = (counts[x.sev] || 0) + 1;
        history.unshift({ at: last.at, mode, ...sc, counts }); history = history.slice(0, 100); writeJson("historico.json", history);
        // a coleta completa também vira a base do Vigia
        updateBaseline(raw);
        return publicState();
      } finally { scanning = null; ctx.emit("state", publicState()); }
    })();
    return scanning;
  }

  // ---------------------------------------------------------------- correções e desfazer
  async function fix(ids) {
    const todo = (last ? last.findings : []).filter((f) => ids.includes(f.id) && f.fix && fixes.FIXES[f.fix.id]);
    if (!todo.length) throw new Error("Nada para corrigir");
    const res = await fixes.apply(todo.map((f) => ({ fix: f.fix.id, params: f.fix.params })), { quarantine: D("quarentena") });
    // os resultados voltam na ordem: primeiro os sem administrador, depois os com
    const order = [...todo.filter((f) => !fixes.FIXES[f.fix.id].admin(f.fix.params || {})), ...todo.filter((f) => fixes.FIXES[f.fix.id].admin(f.fix.params || {}))];
    const out = [];
    res.forEach((r, i) => {
      const f = order[i];
      if (r.ok) { done.unshift({ id: crypto.randomBytes(5).toString("hex"), at: new Date().toISOString(), finding: f.id, title: f.title, fix: f.fix.id, label: fixes.FIXES[f.fix.id].label, backup: r.backup, undoable: fixes.FIXES[f.fix.id].undo, message: r.message }); }
      out.push({ title: f.title, ok: r.ok, message: r.message, restart: !!fixes.FIXES[f.fix.id].restart });
    });
    writeJson("correcoes.json", done.slice(0, 200));
    scan("quick").catch(() => {});
    return out;
  }
  async function undo(id) {
    const e = done.find((x) => x.id === id);
    if (!e || !e.undoable || e.undone) throw new Error("Essa correção não pode ser desfeita");
    const [r] = await fixes.apply([{ fix: e.fix, undo: true, backup: e.backup, params: {} }], { quarantine: D("quarentena") });
    if (!r.ok) throw new Error(r.message || "Não deu para desfazer");
    e.undone = new Date().toISOString(); writeJson("correcoes.json", done);
    scan("quick").catch(() => {});
    return true;
  }

  // ---------------------------------------------------------------- antivírus (Microsoft Defender)
  let defBusy = null;
  async function defenderJob(kind, arg) {
    if (defBusy) throw new Error("O antivírus já está trabalhando: " + defBusy);
    const names = { quick: "verificação rápida", full: "verificação completa", update: "atualização do antivírus", file: "verificação do arquivo", files: "verificação dos arquivos" };
    defBusy = names[kind]; ctx.emit("defender", { busy: defBusy });
    try {
      if (kind === "update") { const r = await fixes.defender(["-SignatureUpdate"], 20 * 60000); return { ok: r.code === 0, text: r.code === 0 ? "Antivírus atualizado" : "Não deu para atualizar (sem internet?)" }; }
      if (kind === "quick" || kind === "full") {
        const r = await fixes.defender(["-Scan", "-ScanType", kind === "quick" ? "1" : "2"]);
        const text = r.code === 0 ? "Nenhuma ameaça encontrada" : r.code === 2 ? "Ameaças encontradas: o Defender cuidou delas (veja em Segurança do Windows › Histórico de proteção)" : "A verificação não terminou (código " + r.code + ")";
        ctx.host.notify("Piphin Escudo · " + names[kind], text).catch(() => {});
        return { ok: r.code === 0 || r.code === 2, threat: r.code === 2, text };
      }
      const list = kind === "file" ? [arg] : arg;
      const res = [];
      for (const p of list.slice(0, 30)) { const r = await fixes.scanFile(p); res.push({ path: p, clean: r.clean, threat: r.threat }); }
      const bad = res.filter((x) => x.threat);
      return { ok: true, threat: bad.length > 0, files: res, text: bad.length ? `${bad.length} ${bad.length === 1 ? "arquivo é ameaça" : "arquivos são ameaças"}: o Defender vai remover` : `Nenhuma ameaça em ${res.length} ${res.length === 1 ? "arquivo" : "arquivos"}` };
    } finally { defBusy = null; ctx.emit("defender", { busy: null }); }
  }

  // ---------------------------------------------------------------- Vigia: compara o que abre sozinho, contas, hosts... a cada 15 min
  // A base é a última verificação; o que aparecer de novo vira alerta (uma vez só) e entra na base.
  const sig = (raw) => ({
    auto: [...(raw.run || []).map((x) => `run|${x.key}|${x.name}|${x.command}`), ...(raw.startup || []).map((x) => `startup|${x.file}`), ...(raw.tasks || []).map((x) => `task|${x.taskPath}${x.name}|${x.command}`)],
    services: (raw.services || []).map((x) => `${x.name}|${x.path}`), admins: (raw.admins || []).map((x) => x.name), users: (raw.users || []).filter((u) => u.enabled).map((u) => u.name),
    hosts: raw.hosts || [], proxy: [`${(raw.proxy || {}).enabled}|${(raw.proxy || {}).server}|${(raw.proxy || {}).pac}`], remote: [...((raw.remote || {}).installed || []).map((x) => x.name), ...((raw.remote || {}).services || []).map((x) => x.name)],
    wmi: (raw.wmi || []).map((x) => x.name), ifeo: (raw.ifeo || []).map((x) => `${x.exe}|${x.debugger}`), winlogon: [JSON.stringify(raw.winlogon || {})],
  });
  let baseline = readJson("vigia-base.json", null);
  function updateBaseline(raw) { baseline = sig(raw); writeJson("vigia-base.json", baseline); }
  const WHAT = { auto: "Algo novo vai abrir com o Windows", services: "Serviço novo instalado", admins: "Nova conta de administrador", users: "Nova conta de usuário", hosts: "O arquivo hosts mudou", proxy: "O proxy da internet mudou",
    remote: "Programa de acesso remoto instalado", wmi: "Gatilho escondido do Windows (WMI) criado", ifeo: "Um programa foi desviado para outro", winlogon: "O login do Windows foi alterado" };
  async function watchTick() {
    if (!prefs.watch || scanning) return;
    let raw; try { raw = await collect({ light: true }); } catch (e) { return ctx.log("vigia", e.message); }
    const now = sig(raw);
    if (!baseline) { baseline = now; writeJson("vigia-base.json", baseline); return; }
    const found = [];
    for (const k of Object.keys(now)) for (const v of now[k]) if (!(baseline[k] || []).includes(v)) found.push({ k, v });
    if (!found.length) return;
    // a análise diz quão grave é o que apareceu
    const a = analyze(raw, { trusted }).findings;
    for (const { k, v } of found) {
      const label = v.split("|").slice(1, 3).filter(Boolean).join(" · ") || v;
      const related = a.find((f) => (f.details || []).some((d) => v.split("|").some((part) => part.length > 3 && d.includes(part))) || f.title.includes(v.split("|")[1] || "\u0000"));
      const sev = related ? related.sev : ["auto", "services", "admins", "remote"].includes(k) ? "medium" : "low";
      const al = { id: crypto.randomBytes(5).toString("hex"), at: new Date().toISOString(), kind: k, title: WHAT[k], item: label.slice(0, 300), sev, finding: related && related.title };
      alerts.unshift(al);
      if (prefs.notify && sev !== "low") ctx.host.notify("Piphin Escudo · " + WHAT[k], `${al.item.slice(0, 120)}${related ? "\n" + related.title : ""}\nClique para ver.`).catch(() => {});
    }
    alerts = alerts.slice(0, 200); writeJson("alertas.json", alerts);
    baseline = now; writeJson("vigia-base.json", baseline);
    ctx.emit("state", publicState());
  }
  const watchTimer = setInterval(() => watchTick().catch(() => {}), WATCH_MS);
  const firstWatch = setTimeout(() => watchTick().catch(() => {}), 2 * 60000);
  ctx.onStop(() => { clearInterval(watchTimer); clearTimeout(firstWatch); });

  // ---------------------------------------------------------------- senha vazada (Have I Been Pwned, anonimato k)
  // A tela calcula o SHA-1 da senha e manda só os 5 primeiros caracteres; o site devolve todos os que começam igual
  // e a comparação acontece no PC. A senha nunca sai do computador.
  function pwnedRange(prefix) {
    if (!/^[0-9A-F]{5}$/.test(prefix)) throw new Error("Prefixo inválido");
    return new Promise((resolve, reject) => {
      const req = https.get(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "User-Agent": "PiphinEscudo", "Add-Padding": "true" }, timeout: 15000 }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return reject(new Error("O serviço de senhas vazadas não respondeu (" + res.statusCode + ")")); }
        let t = ""; res.setEncoding("utf8"); res.on("data", (d) => (t += d)); res.on("end", () => resolve(t));
      });
      req.on("timeout", () => req.destroy(new Error("Sem resposta do serviço de senhas vazadas")));
      req.on("error", (e) => reject(new Error("Sem internet: " + e.message)));
    });
  }

  // ---------------------------------------------------------------- chamadas da tela
  ctx.handle("state", () => publicState());
  ctx.handle("scan", (mode) => scan(mode === "full" ? "full" : "quick"));
  ctx.handle("fix", (ids) => fix(ids));
  ctx.handle("undo", (id) => undo(id));
  ctx.handle("ignore", (id, on) => { if (on) ignored.add(id); else ignored.delete(id); writeJson("ignorados.json", [...ignored]); ctx.emit("state", publicState()); return true; });
  ctx.handle("defender", (kind, arg) => defenderJob(kind, arg));
  ctx.handle("offline-scan", async () => {
    const r = await ctx.host.messageBox({ type: "warning", message: "Reiniciar o PC para a verificação offline?", detail: "O Microsoft Defender reinicia o computador e verifica tudo antes do Windows abrir (pega vírus que se escondem com o Windows ligado). Leva uns 15 minutos.\n\nSalve o que estiver aberto antes.", buttons: ["Reiniciar e verificar", "Cancelar"], cancelId: 1 });
    if (r !== 0) return false;
    const q = (s) => String(s).split("'").join("''");
    await runPs(["-Command", `Start-Process -FilePath '${q(fixes.PS)}' -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','Start-MpWDOScan'`]);
    return true;
  });
  ctx.handle("pwned", (prefix) => pwnedRange(String(prefix).toUpperCase()));
  ctx.handle("prefs", (patch) => { prefs = { ...prefs, ...(patch || {}) }; writeJson("prefs.json", prefs); return prefs; });
  ctx.handle("clear-alerts", () => { alerts = []; writeJson("alertas.json", alerts); ctx.emit("state", publicState()); return true; });
  ctx.handle("show-path", (p) => ctx.host.showItem(p));
  ctx.handle("open-security", () => execFile("explorer.exe", ["windowsdefender:"], () => {}));

  // ---------------------------------------------------------------- ferramentas para a IA
  const forAi = () => {
    const s = publicState(); if (!s.last) return null;
    const act = s.last.findings.filter((f) => !f.ignored);
    return { checked_at: s.last.at, mode: s.last.mode === "full" ? "completa (administrador)" : "rápida", score_0_100: s.last.score,
      intrusion_verdict: { clean: "nenhum sinal de invasão", check: "itens para revisar", warn: "sinais suspeitos", danger: "sinais graves de invasão" }[s.last.verdict],
      findings: act.map((f) => ({ severity: f.sev, category: { invasao: "sinal de invasão", brecha: "brecha", protecao: "proteção do Windows" }[f.cat], title: f.title, explanation: f.text, details: (f.details || []).slice(0, 6), can_fix_in_app: !!(f.fix && fixes.FIXES[f.fix.id]) })),
      good: s.last.good, recent_watch_alerts: s.alerts.slice(0, 5).map((a) => ({ when: a.at, what: a.title, item: a.item })) };
  };
  ctx.handle("tool:security_status", async () => {
    if (!last || Date.now() - Date.parse(last.at) > 24 * 3600000) await scan("quick");
    return { ...forAi(), note: "As correções são feitas pela pessoa na tela do Piphin Escudo (com confirmação)." };
  });
  ctx.handle("tool:run_security_scan", async () => { await scan("quick"); return forAi(); });
};
