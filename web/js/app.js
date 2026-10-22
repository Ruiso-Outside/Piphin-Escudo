// Piphin Escudo · telas: início (nota e veredito), resultados com correções, vigia, ferramentas e histórico.
"use strict";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const call = async (ch, ...a) => { const r = await piphin.invoke(ch, ...a); if (!r.ok) throw new Error(r.error); return r.data; };
const when = (iso) => { const d = new Date(iso), m = Math.round((Date.now() - d) / 60000); return m < 1 ? "agora" : m < 60 ? `há ${m} min` : m < 1440 ? `hoje, ${d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}` : d.toLocaleString("pt-BR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }); };
const SEV = { critical: ["Grave", "skull"], high: ["Alto", "siren"], medium: ["Médio", "triangle-alert"], low: ["Baixo", "info"], info: ["Info", "info"] };
const CAT = { invasao: ["Sinais de invasão", "fingerprint", "Coisas que um invasor ou vírus costuma deixar no PC"], brecha: ["Brechas", "lock-open", "Portas por onde alguém poderia entrar"], protecao: ["Proteção do Windows", "shield-check", "As defesas que já vêm no Windows"] };
const VERDICT = {
  clean: ["Nenhum sinal de invasão", "Não encontramos nada que indique que o PC foi invadido.", "#22c55e"],
  check: ["Alguns itens para conferir", "Nada grave, mas há coisas que vale olhar com calma.", "#38bdf8"],
  warn: ["Sinais suspeitos", "Há coisas que costumam aparecer em PCs invadidos. Confira os itens de risco alto.", "#f59e0b"],
  danger: ["Sinais graves de invasão", "Encontramos marcas típicas de invasão. Veja os itens graves e use o Modo emergência.", "#ef4444"],
};
const S = { tab: "home", st: null, filter: "all", openIds: new Set(), defBusy: null };

// ---------------------------------------------------------------- avisos e janelas
function toast(text, kind = "") { const el = document.createElement("div"); el.className = "toast " + kind; el.textContent = text; $("#toasts").appendChild(el); setTimeout(() => el.remove(), 5000); }
const modal = $("#modal"), box = $("#modalBox");
const openModal = (html, cls = "") => { box.className = "modal-box " + cls; box.innerHTML = html; modal.hidden = false; };
const closeModal = () => { modal.hidden = true; box.innerHTML = ""; };
modal.addEventListener("mousedown", (e) => { if (e.target === modal) closeModal(); });
const confirmBox = (title, html, yes = "Continuar", danger = false) => new Promise((resolve) => {
  openModal(`<h3>${esc(title)}</h3><div class="mtext">${html}</div><div class="modal-actions"><button class="btn" data-n>Cancelar</button><button class="btn ${danger ? "danger solid" : "primary"}" data-y>${esc(yes)}</button></div>`);
  box.querySelector("[data-y]").onclick = () => { closeModal(); resolve(true); };
  box.querySelector("[data-n]").onclick = () => { closeModal(); resolve(false); };
});
const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { busy(null); toast(e.message, "err"); } };
const HINTS = ["Olhando o que abre com o Windows...", "Conferindo as tarefas agendadas e os serviços...", "Procurando programas disfarçados de Windows...", "Verificando antivírus, firewall e atualizações...", "Conferindo o arquivo hosts, o proxy e o DNS...", "Olhando as contas de usuário...", "Procurando programas de acesso remoto..."];
let hintT = 0;
function busy(title, text) {
  $("#busy").hidden = !title; clearInterval(hintT);
  if (!title) return;
  $("#busyTitle").textContent = title;
  if (text) { $("#busyText").textContent = text; return; }
  let i = 0; $("#busyText").textContent = HINTS[0]; hintT = setInterval(() => ($("#busyText").textContent = HINTS[++i % HINTS.length]), 1600);
}

// ---------------------------------------------------------------- dados
piphin.on("scanning", () => busy("Verificando o PC..."));
piphin.on("defender", (d) => { S.defBusy = d.busy; if (S.tab === "tools") render(); });
const findings = () => (S.st && S.st.last ? S.st.last.findings : []);
const active = () => findings().filter((f) => !f.ignored);

// ---------------------------------------------------------------- navegação
$$("#nav [data-tab]").forEach((b) => (b.onclick = () => go(b.dataset.tab)));
function go(tab, filter) { S.tab = tab; if (filter) S.filter = filter; render(); $("#content").scrollTop = 0; }
function render() {
  $$("#nav [data-tab]").forEach((b) => b.classList.toggle("active", b.dataset.tab === S.tab));
  const n = active().filter((f) => f.sev !== "info").length; $("#nRes").textContent = n || "";
  const na = S.st ? S.st.alerts.filter((a) => Date.now() - Date.parse(a.at) < 7 * 86400000 && a.sev !== "low").length : 0; $("#nAl").textContent = na || "";
  if (!S.st) { $("#content").innerHTML = `<div class="loading"><span class="spin"></span></div>`; return; }
  $("#content").innerHTML = { home, results, watch, tools, history }[S.tab]();
  bind();
}

// ---------------------------------------------------------------- início
function ring(score, color) {
  const r = 80, c = 2 * Math.PI * r, p = score / 100;
  return `<svg viewBox="0 0 200 220" class="shield-svg"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".25"/><stop offset="1" stop-color="${color}" stop-opacity=".05"/></linearGradient></defs>
    <path d="M100 8 L182 40 V108 C182 160 146 196 100 212 C54 196 18 160 18 108 V40 Z" fill="url(#g)" stroke="${color}" stroke-opacity=".5" stroke-width="2"/>
    <circle cx="100" cy="108" r="${r - 22}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="10"/>
    <circle cx="100" cy="108" r="${r - 22}" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(2 * Math.PI * (r - 22)) * p} 999" transform="rotate(-90 100 108)" style="filter:drop-shadow(0 0 6px ${color})"/>
    <text x="100" y="118" text-anchor="middle" class="sc">${score}</text><text x="100" y="140" text-anchor="middle" class="sl">de 100</text></svg>`;
}
function home() {
  const L = S.st.last;
  if (!L) return `<div class="wrap"><section class="hero first"><div class="hero-ic"><i class="i i-shield"></i></div><h1>Vamos ver se o seu PC está seguro</h1>
    <p>O Piphin Escudo procura sinais de invasão (vírus escondidos, programas que abrem sozinhos, contas estranhas, sites desviados) e brechas de segurança. Ele só olha: nada muda sem você mandar.</p>
    <div class="row center"><button class="btn primary big" data-act="scan"><i class="i i-scan-search"></i>Verificar agora</button><button class="btn big" data-act="scan-full"><i class="i i-shield-check"></i>Verificação completa</button></div>
    <p class="faint">A completa também vê as exceções do antivírus e o registro de segurança (o Windows pede permissão de administrador).</p></section></div>`;
  const v = VERDICT[L.verdict], act = active();
  const cats = Object.entries(CAT).map(([k, [n, ic, d]]) => { const list = act.filter((f) => f.cat === k && f.sev !== "info"), worst = ["critical", "high", "medium", "low"].find((s) => list.some((f) => f.sev === s));
    return `<button class="cat ${worst || "ok"}" data-go="${k}"><i class="i i-${ic}"></i><b>${n}</b><span>${list.length ? `${list.length} ${list.length === 1 ? "item" : "itens"} para ver` : "Tudo certo"}</span><em>${d}</em></button>`; }).join("");
  const top = act.filter((f) => f.sev === "critical" || f.sev === "high").slice(0, 3);
  return `<div class="wrap">
    <section class="hero"><div class="shield">${ring(L.score, v[2])}</div>
      <div class="hero-txt"><span class="kicker" style="color:${v[2]}">${L.verdict === "clean" ? `<i class="i i-shield-check"></i>` : `<i class="i i-shield-alert"></i>`}${esc(v[0])}</span>
        <h1>${L.score >= 90 ? "Seu PC está bem protegido" : L.score >= 70 ? "Seu PC está razoavelmente protegido" : L.score >= 40 ? "Seu PC precisa de atenção" : "Seu PC está em risco"}</h1>
        <p>${esc(v[1])}</p>
        <div class="row"><button class="btn primary" data-act="scan"><i class="i i-refresh-cw"></i>Verificar de novo</button><button class="btn" data-act="scan-full"><i class="i i-shield-check"></i>Verificação completa</button>
          ${act.some((f) => f.fix && S.st.fixes[f.fix.id]) ? `<button class="btn" data-act="fix-all"><i class="i i-wrench"></i>Corrigir o que dá</button>` : ""}</div>
        <span class="faint">${L.mode === "full" ? "Verificação completa" : "Verificação rápida"} · ${when(L.at)}${L.mode !== "full" ? " · a completa também vê as exceções do antivírus e o log de segurança" : ""}</span></div></section>
    ${top.length ? `<section class="panel urgent"><h3><i class="i i-siren"></i>Mais importante agora</h3>${top.map((f) => `<button class="mini-f ${f.sev}" data-open="${esc(f.id)}"><span class="sev ${f.sev}">${SEV[f.sev][0]}</span>${esc(f.title)}<i class="i i-chevron-right"></i></button>`).join("")}</section>` : ""}
    <section class="cats">${cats}</section>
    ${L.good.length ? `<section class="panel"><h3><i class="i i-circle-check"></i>Pontos fortes</h3><div class="good">${L.good.map((g) => `<span><i class="i i-check"></i>${esc(g)}</span>`).join("")}</div></section>` : ""}
    <section class="panel watchcard"><div><h3><i class="i i-radar"></i>Vigia ${S.st.prefs.watch ? `<span class="on">ligado</span>` : `<span class="off">desligado</span>`}</h3>
      <p class="faint">${S.st.prefs.watch ? "A cada 15 minutos o Escudo confere se algo novo passou a abrir com o Windows, se apareceu conta nova, se o hosts ou o proxy mudaram, e avisa." : "Ligue para ser avisado quando algo perigoso mudar no PC."}</p></div>
      <button class="btn sm" data-tab-go="watch">${S.st.alerts.length ? `${S.st.alerts.length} ${S.st.alerts.length === 1 ? "alerta" : "alertas"}` : "Abrir"}<i class="i i-chevron-right"></i></button></section>
  </div>`;
}

// ---------------------------------------------------------------- resultados
function fCard(f) {
  const fx = f.fix && S.st.fixes[f.fix.id], def = f.fix && /^defender_|^quick_scan$|^sig_update$/.test(f.fix.id), open = S.openIds.has(f.id);
  return `<article class="fc ${f.sev} ${f.ignored ? "ign" : ""} ${open ? "open" : ""}" data-id="${esc(f.id)}">
    <header data-toggle><span class="sev ${f.sev}"><i class="i i-${SEV[f.sev][1]}"></i>${SEV[f.sev][0]}</span><b>${esc(f.title)}</b><span class="cat-t">${CAT[f.cat][0]}</span><i class="i i-chevron-down chev"></i></header>
    <div class="fb"><p>${esc(f.text)}</p>${(f.details || []).length ? `<ul class="det">${f.details.map((d) => `<li>${esc(d)}</li>`).join("")}</ul>` : ""}
      <div class="row">${fx && !f.ignored ? `<button class="btn sm primary" data-fix="${esc(f.id)}"><i class="i i-wrench"></i>${esc(fx.label)}${fx.admin(f.fix.params || {}) ? "" : ""}</button>` : ""}
        ${def && !f.ignored ? `<button class="btn sm primary" data-def="${esc(f.id)}"><i class="i i-bug"></i>${f.fix.id === "quick_scan" ? "Verificar o PC com o antivírus" : f.fix.id === "sig_update" ? "Atualizar o antivírus" : "Verificar com o antivírus"}</button>` : ""}
        <button class="btn sm ghost" data-ign="${esc(f.id)}"><i class="i i-${f.ignored ? "eye" : "eye-off"}"></i>${f.ignored ? "Voltar a mostrar" : "Ignorar (sei o que é)"}</button></div></div></article>`;
}
function results() {
  const L = S.st.last;
  if (!L) return `<div class="wrap"><div class="empty-box"><i class="i i-scan-search"></i><b>Nenhuma verificação ainda</b><button class="btn primary" data-act="scan">Verificar agora</button></div></div>`;
  const all = findings(), list = all.filter((f) => (S.filter === "all" ? !f.ignored : S.filter === "ignored" ? f.ignored : f.cat === S.filter && !f.ignored));
  const n = (k) => all.filter((f) => !f.ignored && (k === "all" || f.cat === k)).length;
  return `<div class="wrap"><div class="rhead"><div class="seg">${[["all", "Tudo"], ["invasao", "Sinais de invasão"], ["brecha", "Brechas"], ["protecao", "Proteção"], ["ignored", "Ignorados"]].map(([k, l]) => `<button class="${S.filter === k ? "active" : ""}" data-filter="${k}">${l} <em>${k === "ignored" ? all.filter((f) => f.ignored).length : n(k)}</em></button>`).join("")}</div>
    <div class="grow"></div>${list.some((f) => f.fix && S.st.fixes[f.fix.id] && !f.ignored) ? `<button class="btn sm primary" data-act="fix-all"><i class="i i-wrench"></i>Corrigir o que dá</button>` : ""}</div>
    ${list.length ? list.map(fCard).join("") : `<div class="empty-box"><i class="i i-shield-check"></i><b>${S.filter === "ignored" ? "Nada ignorado" : "Nada por aqui"}</b><span>${S.filter === "ignored" ? "" : "Nenhum problema nesta parte."}</span></div>`}
    ${S.filter === "all" && L.good.length ? `<section class="panel"><h3><i class="i i-circle-check"></i>O que está certo</h3><div class="good">${L.good.map((g) => `<span><i class="i i-check"></i>${esc(g)}</span>`).join("")}</div></section>` : ""}</div>`;
}

// ---------------------------------------------------------------- vigia
function watch() {
  const p = S.st.prefs, al = S.st.alerts;
  return `<div class="wrap narrow"><h2>Vigia</h2>
    <div class="p-settings">
      <div class="set"><div><h4>Vigiar o PC</h4><p>A cada 15 minutos, com o Hub aberto, confere o que abre com o Windows, serviços, contas, administradores, hosts, proxy, programas de acesso remoto e truques conhecidos de invasores.</p></div><label class="switch"><input type="checkbox" id="pWatch" ${p.watch ? "checked" : ""}><span></span></label></div>
      <div class="set"><div><h4>Avisar com notificação</h4><p>Uma notificação do Windows quando aparecer algo de risco médio para cima.</p></div><label class="switch"><input type="checkbox" id="pNotify" ${p.notify ? "checked" : ""}><span></span></label></div>
    </div>
    <div class="rhead"><h3>Alertas</h3><div class="grow"></div>${al.length ? `<button class="btn sm ghost" data-act="clear-alerts"><i class="i i-trash-2"></i>Limpar</button>` : ""}</div>
    ${al.length ? `<div class="timeline">${al.map((a) => `<div class="al ${a.sev}"><span class="dot"></span><div><b>${esc(a.title)}</b><span class="faint">${when(a.at)}</span><p>${esc(a.item)}</p>${a.finding ? `<p class="why"><i class="i i-${SEV[a.sev][1]}"></i>${esc(a.finding)}</p>` : ""}</div></div>`).join("")}</div>
      <p class="faint">Instalou um programa agora? É normal ele aparecer aqui. Se você não reconhece o item, rode uma verificação.</p>`
      : `<div class="empty-box"><i class="i i-radar"></i><b>Nenhuma mudança suspeita</b><span>Quando algo novo passar a abrir com o Windows (ou outra mudança perigosa), aparece aqui.</span></div>`}</div>`;
}

// ---------------------------------------------------------------- ferramentas
let pass = { len: 16, symbols: true, words: false, value: "" };
function genPass() {
  const r = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;
  if (pass.words) {
    const w = []; for (let i = 0; i < Math.max(4, Math.round(pass.len / 4)); i++) { const x = WORDS[r(WORDS.length)]; w.push(x[0].toUpperCase() + x.slice(1)); }
    pass.value = w.join("-") + "-" + (10 + r(90));
  } else {
    const sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", ...(pass.symbols ? ["!@#$%&*?-_+="] : [])];
    let v = sets.map((s) => s[r(s.length)]).join(""); const all = sets.join("");
    while (v.length < pass.len) v += all[r(all.length)];
    pass.value = [...v].sort(() => r(3) - 1).join("");
  }
}
function tools() {
  if (!pass.value) genPass();
  const L = S.st.last, df = L && L.findings ? null : null;
  return `<div class="wrap"><div class="tgrid">
    <section class="panel tool"><h3><i class="i i-bug"></i>Antivírus (Microsoft Defender)</h3>
      <p class="faint">${S.defBusy ? `<span class="spin sm"></span> ${esc(S.defBusy)} em andamento... pode continuar usando o PC.` : "Use quando desconfiar de algo. A completa pode levar mais de uma hora."}</p>
      <div class="btns"><button class="btn" data-def-act="quick" ${S.defBusy ? "disabled" : ""}><i class="i i-scan-search"></i>Verificação rápida</button><button class="btn" data-def-act="full" ${S.defBusy ? "disabled" : ""}><i class="i i-hard-drive"></i>Verificação completa</button>
        <button class="btn" data-def-act="update" ${S.defBusy ? "disabled" : ""}><i class="i i-refresh-cw"></i>Atualizar o antivírus</button><button class="btn" data-act="offline"><i class="i i-power"></i>Verificação offline</button>
        <button class="btn ghost" data-act="open-security"><i class="i i-external-link"></i>Segurança do Windows</button></div></section>
    <section class="panel tool"><h3><i class="i i-key-round"></i>Minha senha vazou?</h3>
      <p class="faint">Confere se a senha aparece em vazamentos conhecidos (mais de 900 milhões de senhas). <b>A senha não sai do PC:</b> só 5 letras de um código dela são enviadas.</p>
      <form class="pw" id="pwForm"><input type="password" id="pwIn" placeholder="Digite uma senha" autocomplete="off"><button type="button" class="btn icon ghost" id="pwEye" title="Mostrar"><i class="i i-eye"></i></button><button class="btn primary">Conferir</button></form>
      <div id="pwOut"></div></section>
    <section class="panel tool"><h3><i class="i i-sparkles"></i>Gerador de senhas</h3>
      <div class="genval"><code id="genV">${esc(pass.value)}</code><button class="btn icon" data-act="copy-pass" title="Copiar"><i class="i i-copy"></i></button><button class="btn icon" data-act="regen" title="Outra"><i class="i i-refresh-cw"></i></button></div>
      <div class="genopts"><label class="swl"><span class="switch"><input type="checkbox" id="gWords" ${pass.words ? "checked" : ""}><span></span></span>Fácil de lembrar (palavras)</label>
        ${pass.words ? "" : `<label class="swl"><span class="switch"><input type="checkbox" id="gSym" ${pass.symbols ? "checked" : ""}><span></span></span>Símbolos</label>`}
        <label class="slen">Tamanho <input type="range" id="gLen" min="12" max="32" value="${pass.len}"><b>${pass.len}</b></label></div>
      <p class="faint">Use uma senha diferente em cada site. Um gerenciador de senhas (do navegador, Bitwarden, Proton Pass) guarda todas.</p></section>
    <section class="panel tool emergency"><h3><i class="i i-siren"></i>Modo emergência</h3>
      <p class="faint">Acha que foi invadido ou caiu num golpe? Siga na ordem:</p>
      <ol class="steps">
        <li><b>Desconecte o PC da internet</b> (tire o cabo ou desligue o Wi-Fi). Isso corta o acesso de quem estiver controlando.</li>
        <li><b>Feche e desinstale programas de acesso remoto</b> que você não usa (AnyDesk, TeamViewer...).</li>
        <li><b>Faça a verificação offline do antivírus</b> <button class="btn sm" data-act="offline"><i class="i i-power"></i>Reiniciar e verificar</button></li>
        <li><b>Rode a verificação completa do Escudo</b> <button class="btn sm" data-act="scan-full"><i class="i i-shield-check"></i>Verificar</button> e corrija o que aparecer.</li>
        <li><b>Troque as senhas usando o celular</b> (não este PC): primeiro o e-mail, depois banco, redes sociais e jogos. Ligue a verificação em duas etapas.</li>
        <li><b>Avise o seu banco</b> se você digitou dados bancários ou viu movimentações estranhas.</li>
        <li>Se os sinais continuarem, <b>salve seus arquivos e reinstale o Windows</b> (Configurações › Sistema › Recuperação › Restaurar o PC).</li>
      </ol></section>
  </div></div>`;
}

// ---------------------------------------------------------------- histórico
function history() {
  const h = S.st.history, d = S.st.done;
  return `<div class="wrap narrow"><h2>Histórico</h2>
    <h3 class="sub">Correções</h3>
    ${d.length ? `<div class="hlist">${d.map((x) => `<div class="hi"><i class="i i-${x.undone ? "undo-2" : "wrench"}"></i><div><b>${esc(x.label)}</b><span>${esc(x.title)}</span><span class="faint">${when(x.at)}${x.undone ? " · desfeito " + when(x.undone) : ""}${x.message ? " · " + esc(x.message) : ""}</span></div>
      ${x.undoable && !x.undone ? `<button class="btn sm" data-undo="${esc(x.id)}"><i class="i i-undo-2"></i>Desfazer</button>` : ""}</div>`).join("")}</div>` : `<p class="faint">Nenhuma correção feita ainda.</p>`}
    <h3 class="sub">Verificações</h3>
    ${h.length ? `<div class="hlist">${h.map((x) => `<div class="hi"><span class="hs" style="--c:${VERDICT[x.verdict][2]}">${x.score}</span><div><b>${esc(VERDICT[x.verdict][0])}</b><span class="faint">${x.mode === "full" ? "Completa" : "Rápida"} · ${when(x.at)} · ${["critical", "high", "medium", "low"].filter((k) => x.counts[k]).map((k) => `${x.counts[k]} ${SEV[k][0].toLowerCase()}`).join(", ") || "nenhum problema"}</span></div></div>`).join("")}</div>` : `<p class="faint">Nenhuma verificação ainda.</p>`}</div>`;
}

// ---------------------------------------------------------------- ações
async function scan(mode) {
  if (mode === "full" && !(await confirmBox("Verificação completa", "O Windows vai pedir permissão de administrador para o Escudo ver também:<ul><li>as exceções do antivírus (onde vírus gostam de se esconder)</li><li>o registro de segurança (contas criadas, senhas erradas pela rede, registros apagados)</li><li>a criptografia do disco e o chip de segurança (TPM)</li></ul>Nada é alterado.", "Verificar"))) return;
  busy(mode === "full" ? "Verificação completa..." : "Verificando o PC...");
  try { setState(await call("scan", mode)); S.tab = "home"; render(); } finally { busy(null); }
}
async function doFix(ids) {
  const fs = findings().filter((f) => ids.includes(f.id) && f.fix && S.st.fixes[f.fix.id]);
  if (!fs.length) return;
  const admin = fs.some((f) => S.st.fixes[f.fix.id].admin(f.fix.params || {}));
  const ok = await confirmBox(fs.length === 1 ? fs[0].title : `Corrigir ${fs.length} itens?`,
    `<ul class="fixlist">${fs.map((f) => `<li><b>${esc(S.st.fixes[f.fix.id].label)}</b> · ${esc(f.title)}${S.st.fixes[f.fix.id].undo ? "" : ` <span class="faint">(não dá para desfazer)</span>`}</li>`).join("")}</ul>
    ${admin ? `<p class="faint"><i class="i i-shield"></i> O Windows vai pedir permissão de administrador uma vez.</p>` : ""}<p class="faint">Tudo fica no Histórico, de onde dá para desfazer.</p>`, "Corrigir");
  if (!ok) return;
  busy("Corrigindo...", admin ? "Se o Windows pedir permissão, clique em Sim." : "Só um instante.");
  try {
    const res = await call("fix", ids);
    busy(null);
    const bad = res.filter((r) => !r.ok), restart = res.some((r) => r.ok && r.restart);
    if (bad.length) toast(`${res.length - bad.length} de ${res.length} corrigidos. Não deu: ${bad.map((b) => b.title + " (" + b.message + ")").join("; ")}`, "err");
    else toast(`${res.length === 1 ? "Corrigido" : res.length + " itens corrigidos"}${restart ? ". Reinicie o PC para valer." : ""}`, "ok");
  } finally { busy(null); }
}
async function defend(kind, arg) {
  if (kind !== "update") toast(kind === "full" ? "Verificação completa começou: pode levar mais de uma hora, avisamos quando terminar" : "O antivírus está verificando...");
  const r = await call("defender", kind, arg);
  toast(r.text, r.threat ? "err" : "ok");
}
async function checkPwned(pw) {
  const out = $("#pwOut");
  if (!pw) return;
  out.innerHTML = `<p class="faint"><span class="spin sm"></span> Conferindo...</p>`;
  const h = [...new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(pw)))].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const body = await call("pwned", h.slice(0, 5));
  const line = body.split(/\r?\n/).find((l) => l.split(":")[0] === h.slice(5));
  const n = line ? Number(line.split(":")[1]) : 0;
  out.innerHTML = n > 0 ? `<div class="pwres bad"><i class="i i-shield-x"></i><div><b>Essa senha vazou ${n.toLocaleString("pt-BR")} ${n === 1 ? "vez" : "vezes"}</b><span>Invasores testam essas senhas primeiro. Troque em todo lugar que você usa e não use mais.</span></div></div>`
    : `<div class="pwres ok"><i class="i i-shield-check"></i><div><b>Não aparece em nenhum vazamento conhecido</b><span>Ótimo! Mesmo assim, não use a mesma senha em mais de um site.</span></div></div>`;
}
function bind() {
  const w = $("#pWatch"); if (w) w.onchange = guard(async () => { S.st.prefs = await call("prefs", { watch: w.checked }); toast(w.checked ? "Vigia ligado" : "Vigia desligado", "ok"); render(); });
  const n = $("#pNotify"); if (n) n.onchange = guard(async () => { S.st.prefs = await call("prefs", { notify: n.checked }); });
  const pf = $("#pwForm"); if (pf) { pf.onsubmit = guard(async (e) => { e.preventDefault(); await checkPwned($("#pwIn").value); $("#pwIn").value = ""; }); $("#pwEye").onclick = () => { const i = $("#pwIn"); i.type = i.type === "password" ? "text" : "password"; }; }
  const gw = $("#gWords"); if (gw) gw.onchange = () => { pass.words = gw.checked; genPass(); render(); };
  const gs = $("#gSym"); if (gs) gs.onchange = () => { pass.symbols = gs.checked; genPass(); render(); };
  const gl = $("#gLen"); if (gl) gl.oninput = () => { pass.len = +gl.value; gl.nextElementSibling.textContent = gl.value; genPass(); $("#genV").textContent = pass.value; };
}
$("#content").addEventListener("click", guard(async (e) => {
  const t = e.target.closest("[data-act],[data-go],[data-open],[data-toggle],[data-fix],[data-def],[data-ign],[data-filter],[data-undo],[data-def-act],[data-tab-go]"); if (!t) return;
  if (t.dataset.tabGo) return go(t.dataset.tabGo);
  if (t.dataset.go) return go("results", t.dataset.go);
  if (t.dataset.open) { S.openIds.add(t.dataset.open); S.filter = "all"; go("results"); setTimeout(() => { const el = $(`.fc[data-id="${CSS.escape(t.dataset.open)}"]`); if (el) el.scrollIntoView({ block: "center" }); }, 50); return; }
  if (t.dataset.toggle !== undefined) { const id = t.closest(".fc").dataset.id; S.openIds.has(id) ? S.openIds.delete(id) : S.openIds.add(id); t.closest(".fc").classList.toggle("open"); return; }
  if (t.dataset.filter) { S.filter = t.dataset.filter; return render(); }
  if (t.dataset.fix) return doFix([t.dataset.fix]);
  if (t.dataset.ign) { const f = findings().find((x) => x.id === t.dataset.ign); return call("ignore", f.id, !f.ignored); }
  if (t.dataset.undo) { if (await confirmBox("Desfazer a correção?", "O que foi mudado volta como estava antes.", "Desfazer")) { busy("Desfazendo...", "Se o Windows pedir permissão, clique em Sim."); try { await call("undo", t.dataset.undo); toast("Desfeito", "ok"); } finally { busy(null); } } return; }
  if (t.dataset.defAct) return defend(t.dataset.defAct);
  if (t.dataset.def) {
    const f = findings().find((x) => x.id === t.dataset.def), p = f.fix.params || {};
    return defend(f.fix.id === "quick_scan" ? "quick" : f.fix.id === "sig_update" ? "update" : f.fix.id === "defender_scan_files" ? "files" : "file", p.paths || p.path);
  }
  switch (t.dataset.act) {
    case "scan": return scan("quick");
    case "scan-full": return scan("full");
    case "fix-all": return doFix(active().filter((f) => f.fix && S.st.fixes[f.fix.id]).map((f) => f.id));
    case "clear-alerts": return call("clear-alerts");
    case "offline": return call("offline-scan");
    case "open-security": return call("open-security");
    case "regen": genPass(); $("#genV").textContent = pass.value; return;
    case "copy-pass": await navigator.clipboard.writeText(pass.value); return toast("Senha copiada", "ok");
  }
}));

// as funções de "precisa de administrador" vêm do motor como texto; aqui viram uma regra simples
function adminRule(id) { return (p) => !/^(proxy_off)$/.test(id) && !(id === "run_disable" && /^HKCU/i.test(p.key || "")) && !(id === "startup_disable" && !/\\ProgramData\\/i.test(p.file || "")); }
// todo estado que chega do motor passa por aqui (as correções ganham a regra de administrador)
function setState(st) { for (const k of Object.keys(st.fixes || {})) st.fixes[k] = { ...st.fixes[k], admin: adminRule(k) }; S.st = st; }
(async () => {
  setState(await call("state")); render();
  piphin.on("state", (st) => { setState(st); render(); });
})().catch((e) => { $("#content").innerHTML = `<div class="empty-box"><i class="i i-triangle-alert"></i><b>Não deu para abrir</b><span>${esc(e.message)}</span></div>`; });
