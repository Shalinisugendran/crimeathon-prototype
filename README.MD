# IOC Gate

IOC Gate checks outside threat intelligence before anyone acts on it. It was built for CRIMEATHON’26, Case File CR-26-047 (Harbor & Finch), on the Defense track.

When a notice and an indicator list arrive from an outside company, IOC Gate runs three checks in order and returns one of four decisions, with the reason and the evidence behind every finding.

| Check | Question | If it fails |
|---|---|---|
| 1. Sender check | Who sent it? | REJECT: nothing is acted on, and the indicators are kept as evidence |
| 2. Harm check | Would it hurt us? | QUARANTINE: the whole list is held for review |
| 3. Corroboration | Can anyone confirm it? | ACCEPT_WATCH until confirmed; ACCEPT_ENFORCE only for indicators seen in our logs and confirmed out-of-band |

## Run it

Open `index.html` in any modern browser. There is nothing to install, and it works with no internet connection.

## Use it

1. Open **Settings** and replace the sample values with the details from the case file: the supplier’s real domain, our domains and network ranges, and the evidence IDs.
2. On **Check a notice**, enter the sender details, links, registration data, indicator list and any log lines, then select **Run the gate**.
3. Download the report (JSON) or the blocklist. The blocklist only ever contains ACCEPT_ENFORCE indicators.
4. Every run is recorded in the **Audit log**, which you can download as CSV or JSON for the proof pack.

## Test it

- In the app, open **How it works** and select **Run the self-test**. It runs the four built-in examples and compares each decision with the expected one.
- From the command line, run `node test_gate.js` (Node 18 or later). It checks the four examples plus look-alike, harm and corroboration edge cases.

## What it never does

- It never connects to the internet. There are no live WHOIS lookups, and links are never opened.
- It never sends anything you enter anywhere. Settings and the audit log stay in your browser.
- It never puts an indicator on the blocklist without two confirmations: our own logs and the contract contact.

## Known limits

- Unicode look-alikes beyond the built-in character list can get past the sender check. The other two checks still apply.
- A hacked but genuine supplier mailbox passes the sender check, so the harm and corroboration checks have to catch it.
- Registration data entered by hand may be out of date. Confirm it with the contract contact.
- Watching first means a real, urgent threat waits for confirmation.

## About the example data

The four examples use reserved test domains (`.example`) and documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). They are not case evidence. The network ranges 172.16.0.0/16 and 10.20.4.0/24 come from the case file.

Built with AI assistance (Claude).