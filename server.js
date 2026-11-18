// Servidor local. Na Vercel é usado api/index.js diretamente.
const http = require("http");
const handler = require("./api/index.js");

const PORT = process.env.PORT || 3000;

http
  .createServer((req, res) => handler(req, res))
  .listen(PORT, () => console.log(`Escutando em http://localhost:${PORT}`));
