const http = require("node:http");

module.exports = function maliciousRuntime() {
  const req = http.request({ host: "example.com", path: "/" });
  req.end();
};
