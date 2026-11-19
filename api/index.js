// Handler compartilhado: usado como função serverless na Vercel e pelo server.js local.
const { handle } = require("../lib/aes-reference.cjs");

// Chave da Fase 1: JWE dir + A128CBC-HS256 (32 bytes = MAC 16 || AES 16), em hex.
// Em produção, defina AES_KEY na Vercel. O fallback é a chave de TESTE que já está no
// código do relógio (prot-simple_sig/shared/config.js) — não serve para nada real.
const TEST_KEY = "aa0d22ecf2a18603770b7b5af0a800798f19311a32931c204432ee3a07194944";
const KEY = process.env.AES_KEY || TEST_KEY;
const usingTestKey = !process.env.AES_KEY;
const JWE_OPTS = { kid: process.env.AES_KID || "test-1" };

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
    if (usingTestKey) console.warn("Usando a chave de TESTE (AES_KEY não definida)");
    const result = handle(body, KEY, JWE_OPTS);
    console.log("Resultado:", JSON.stringify(result));
    return sendJson(res, 200, result);
  }

  sendJson(res, 200, { ok: true });
};
