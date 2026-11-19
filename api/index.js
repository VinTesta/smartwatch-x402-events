// Handler compartilhado: usado como função serverless na Vercel e pelo server.js local.
const { handle } = require("../lib/aes-reference.cjs");

// Chaves da Fase 1 (AES). Em produção, defina AES_ENC_KEY / AES_MAC_KEY na Vercel.
// O fallback são as chaves de TESTE que já estão no código do relógio
// (prot-simple_sig/shared/config.js) — não servem para nada real.
const TEST_KEYS = {
  enc: "7c1a4f0e9b2d3c5a6e8f10213243546f",
  mac: "0f1e2d3c4b5a69788796a5b4c3d2e1f000112233445566778899aabbccddeeff",
};
const KEYS = {
  enc: process.env.AES_ENC_KEY || TEST_KEYS.enc,
  mac: process.env.AES_MAC_KEY || TEST_KEYS.mac,
};
const usingTestKeys = !process.env.AES_ENC_KEY || !process.env.AES_MAC_KEY;
// Só ligue se o KAT do relógio indicar layout "iv-prefixado".
const AES_OPTS = { ivPrefixed: process.env.AES_IV_PREFIXED === "1" };

function readBody(req) {
  // Na Vercel o body já vem parseado em req.body
  if (req.body !== undefined) return Promise.resolve(req.body);
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve(raw);
      }
    });
  });
}

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(obj));
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { ok: false, error: "Method not allowed" });
  }

  const body = await readBody(req);

  console.log("---- POST recebido", new Date().toISOString(), "----");
  console.log("Headers:", req.headers);
  console.log("Title:", req.headers["title"]);
  console.log("Body:", JSON.stringify(body));

  // Mensagens do relógio (via app-side) trazem { kind, payload }.
  if (body && typeof body === "object" && typeof body.kind === "string") {
    if (usingTestKeys) console.warn("Usando chaves de TESTE (AES_ENC_KEY/AES_MAC_KEY não definidas)");
    const result = handle(body, KEYS, AES_OPTS);
    console.log("Resultado:", JSON.stringify(result));
    return sendJson(res, 200, result);
  }

  sendJson(res, 200, { ok: true });
};
