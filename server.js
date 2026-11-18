const http = require("http");

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url.split("?")[0] !== "/") {
    res.writeHead(404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: false, error: "Not found" }));
  }

  let raw = "";
  req.on("data", (chunk) => (raw += chunk));
  req.on("end", () => {
    let body = raw;
    try {
      body = JSON.parse(raw);
    } catch {
      // mantém como texto se não for JSON
    }

    console.log("---- POST recebido", new Date().toISOString(), "----");
    console.log("Headers:", req.headers);
    console.log("Title:", req.headers["title"]);
    console.log("Body:", body);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
});

server.listen(PORT, () => console.log(`Escutando em http://localhost:${PORT}`));
