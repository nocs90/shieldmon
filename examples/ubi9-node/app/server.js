// Minimal demo service: the point is its dependency tree, not its features.
const http = require("node:http");
const _ = require("lodash");
const argv = require("minimist")(process.argv.slice(2));

const port = Number(argv.port || process.env.PORT || 8080);

http
  .createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true, path: _.escape(req.url) }));
  })
  .listen(port, () => console.log(`listening on :${port}`));
