// Desenha o ícone do Piphin Escudo: icons/escudo.png (256). Uso: npm run icon (usa o Electron do Piphin Hub).
const { app, BrowserWindow } = require("electron");
const fs = require("fs");
const path = require("path");

app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false, webPreferences: { offscreen: true } });
  await win.loadURL("about:blank");
  const b64 = await win.webContents.executeJavaScript(`(() => {
    const s = 256, c = document.createElement("canvas"); c.width = c.height = s;
    const g = c.getContext("2d");
    g.beginPath(); g.roundRect(8, 8, 240, 240, 56);
    const bg = g.createLinearGradient(0, 0, s, s); bg.addColorStop(0, "#06301a"); bg.addColorStop(1, "#090d0b");
    g.fillStyle = bg; g.fill();
    g.lineWidth = 3; g.strokeStyle = "rgba(34,197,94,.6)"; g.stroke();
    const grad = g.createLinearGradient(60, 210, 196, 50); grad.addColorStop(0, "#15803d"); grad.addColorStop(.6, "#22c55e"); grad.addColorStop(1, "#86efac");
    // escudo
    g.save(); g.shadowColor = "#22c55e"; g.shadowBlur = 26; g.fillStyle = grad;
    g.beginPath(); g.moveTo(128, 40); g.lineTo(200, 66); g.lineTo(200, 124); g.bezierCurveTo(200, 170, 170, 202, 128, 218); g.bezierCurveTo(86, 202, 56, 170, 56, 124); g.lineTo(56, 66); g.closePath(); g.fill(); g.restore();
    // ondas do radar e o visto
    g.save(); g.strokeStyle = "rgba(255,255,255,.35)"; g.lineWidth = 3;
    for (const r of [26, 46]) { g.beginPath(); g.arc(128, 128, r, -Math.PI * 0.85, -Math.PI * 0.15); g.stroke(); }
    g.restore();
    g.strokeStyle = "#fff"; g.lineWidth = 16; g.lineCap = "round"; g.lineJoin = "round";
    g.beginPath(); g.moveTo(98, 134); g.lineTo(120, 156); g.lineTo(162, 108); g.stroke();
    return c.toDataURL("image/png").split(",")[1];
  })()`);
  fs.mkdirSync(path.join(__dirname, "..", "icons"), { recursive: true });
  fs.writeFileSync(path.join(__dirname, "..", "icons", "escudo.png"), Buffer.from(b64, "base64"));
  console.log("ícone: icons/escudo.png");
  app.quit();
});
