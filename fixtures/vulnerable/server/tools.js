const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

async function preview(req, res) {
  const response = await fetch(req.query.url);
  res.send(await response.text());
}

function convert(req, res) {
  exec(`convert uploads/${req.query.file} -resize 200x200 thumbs/${req.query.file}`, (err) => {
    res.json({ ok: !err });
  });
}

function calc(req, res) {
  const result = eval(req.body.expression);
  res.json({ result });
}

function download(req, res) {
  const file = path.join(__dirname, '../uploads', req.query.name);
  res.send(fs.readFileSync(file));
}

function go(req, res) {
  res.redirect(req.query.next);
}

module.exports = { preview, convert, calc, download, go };
