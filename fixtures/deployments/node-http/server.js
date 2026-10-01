"use strict";

const http = require("node:http");

http.createServer((request, response) => {
  if (request.url === "/health") {
    const body = JSON.stringify({ fixture: "node-http", ok: true });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(body);
    return;
  }
  response.writeHead(404);
  response.end();
}).listen(8080, "0.0.0.0");
