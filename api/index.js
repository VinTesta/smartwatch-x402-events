// Handler compartilhado: usado como função serverless na Vercel e pelo server.js local.
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

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify({ ok: false, error: "Method not allowed" }));
  }

  const body = await readBody(req);

  console.log("---- POST recebido", new Date().toISOString(), "----");
  console.log("Headers:", req.headers);
  console.log("Title:", req.headers["title"]);
  console.log("Body:", body);

  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ ok: true }));
};
