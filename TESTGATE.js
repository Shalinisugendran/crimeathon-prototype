// IOC Gate logic tests. Run with: node test_gate.js  (Node 18 or later, no packages needed)
const fs = require("fs");
const html = fs.readFileSync(require("path").join(__dirname, "index.html"), "utf8");
const m = html.match(/<script id="gate-logic">([\s\S]*?)<\/script>/);
new Function(m[1])();
const G = globalThis.IOCGate;
let fails = 0;
const check = (name, got, want) => { const ok = JSON.stringify(got) === JSON.stringify(want); if (!ok) fails++; console.log(`${ok ? "ok  " : "FAIL"} ${name}: ${JSON.stringify(got)}${ok ? "" : "  (want " + JSON.stringify(want) + ")"}`); };

// 1. Self-test on the four samples
for (const r of G.selfTest()) check(`sample ${r.name}`, r.got, r.expected);

// 2. Per-indicator decisions
const gen = G.runGate(G.clone(G.SAMPLES.genuine), G.DEFAULT_CONFIG);
check("genuine decisions", gen.indicators.map(i => [i.value, i.decision]), [["203.0.113.77","block"],["198.51.100.23","watch"],["bad-cdn.example","watch"]]);
const poi = G.runGate(G.clone(G.SAMPLES.poisoned), G.DEFAULT_CONFIG);
check("poisoned hits", poi.stages.harm.hits.map(h => h.value), ["10.20.4.17","172.16.8.0/24"]);
check("poisoned defanged URL host", poi.indicators[3].host, "malware-drop.example");
const look = G.runGate(G.clone(G.SAMPLES.lookalike), G.DEFAULT_CONFIG);
check("look-alike sender status", look.stages.sender.status, "fail");

// 3. Look-alike detector edge cases
const sup = ["kestrel-it.example"];
const kind = (h) => G.compareToSupplier(G.hostFromAny(h), sup, 2).kind;
check("exact", kind("security@kestrel-it.example"), "match");
check("subdomain", kind("https://portal.kestrel-it.example/x"), "match");
check("typo (1 for l)", kind("kestre1-it.example"), "lookalike");
check("rn for m? (n/a) hyphen move", kind("kestrelit.example"), "lookalike");
check("other ending", kind("kestrel-it.co"), "lookalike");
check("brand + word", kind("kestrel-it-security.example"), "lookalike");
check("prefix trick", kind("kestrel-it.example.attacker.example"), "lookalike");
check("cyrillic e", kind("kеstrel-it.example"), "lookalike");
check("unrelated", kind("freemail.example"), "unrelated");
check("unrelated short", kind("abc.example"), "unrelated");

// 4. Harm check edge cases
const harm = (ind) => { const r = G.runGate({ ...G.emptyInput(), from: "security@kestrel-it.example", auth:{spf:"pass",dkim:"pass",dmarc:"pass"}, indicators: ind }, G.DEFAULT_CONFIG); return r.outcome; };
check("0.0.0.0/0 quarantined", harm("0.0.0.0/0"), "QUARANTINE");
check("our domain quarantined", harm("intranet.harborfinch.example"), "QUARANTINE");
check("supplier domain quarantined", harm("kestrel-it.example"), "QUARANTINE");
check("public IP watched", harm("203.0.113.9"), "ACCEPT_WATCH");
check("private 192.168 quarantined", harm("192.168.1.5"), "QUARANTINE");
check("ipv6 loopback quarantined", harm("::1"), "QUARANTINE");
check("hash watched", harm("44d88612fea8a8f36de82e1278abb02f"), "ACCEPT_WATCH");

// 5. Unknown sender can never enforce
const unk = G.runGate({ ...G.clone(G.SAMPLES.genuine), from: "intel@someone-else.example", replyTo: "", returnPath: "", links: "", reg: { created: "", registrant: "", privacy: false } }, G.DEFAULT_CONFIG);
check("unknown sender capped", [unk.outcome, unk.enforce.length], ["ACCEPT_WATCH", 0]);
// 6. Invalid lines ignored
const inv = G.runGate({ ...G.emptyInput(), from: "security@kestrel-it.example", indicators: "999.1.1.1\nnot an indicator\n# comment" }, G.DEFAULT_CONFIG);
check("invalid ignored", inv.indicators.map(i => i.decision), ["ignored", "ignored"]);
console.log(fails ? `\n${fails} FAILED` : "\nall passed");
process.exit(fails ? 1 : 0);