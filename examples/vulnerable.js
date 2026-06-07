// Deliberately vulnerable JS sample, for testing XSEC.
// Run: xsec scan examples/vulnerable.js

const cp = require("child_process");
const crypto = require("crypto");

const API_KEY = "super_secret_value_123";  // fake value, just for testing

function calc(expr) {
  return eval(expr);  // arbitrary code execution
}

function run(userInput) {
  cp.exec(`ls ${userInput}`);  // command injection
}

function render(el, userInput) {
  el.innerHTML = userInput;  // DOM XSS
}

function fingerprint(data) {
  return crypto.createHash("md5").update(data).digest("hex");  // weak hash
}

const agent = { rejectUnauthorized: false };  // TLS verification off

module.exports = { calc, run, render, fingerprint, agent, API_KEY };
