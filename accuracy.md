# Accuracy against the Cridex ground truth

This compares three real runs of the agent (gemini-3.5-flash-lite, 4 Volatility 3 plugins) on cridex.vmem with the published ground truth for that image. The image is 536,870,912 bytes with SHA-256 02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d. Run 1 is committed under examples/cridex-run/. Runs 2 and 3 were not kept, so their numbers below come from the checks I did at the time, not from files you can inspect.

## Ground truth

Cridex is a banking trojan. The malicious process is reader_sl.exe (PID 1640, child of explorer.exe PID 1484), and it talks to a command and control server on port 8080.

## Results

Process name and PID: reader_sl.exe with PID 1640 appeared as a confirmed finding in 3 of 3 runs, together with its command line (runs 1 to 3 cited windows.pslist and windows.cmdline). Parent explorer.exe (PID 1484) was reported in 1 of 3 runs. All 11 confirmed claims across the three runs were re-checked by hand against fresh Volatility output and none was contradicted, so the false-claim rate among confirmed findings was 0 of 11.

Flagged as anomalous or malicious: 0 of 3. The agent listed reader_sl.exe as a running process but never called it suspicious, and the words suspicious, malicious, malware and Cridex do not appear in any of the three reports or final answers. This is the main miss. The agent reports what the tables say and stops short of triage.

Port 8080 and the C2 connection: 0 of 3. windows.netscan crashes on this image with NotImplementedError: This version of Windows is not supported: 5.1 15.2600, because Volatility 3 has no netscan support for Windows XP. The agent handled the failure correctly in all three runs by reporting the failure as a confirmed fact and not inventing any connection. It did not try another route, because the allow list holds only the four plugins.

## What this means

The spec assumed windows.netscan would show the port 8080 connection. On Volatility 3 2.28.2 it cannot for this XP image, so the connection half of the evaluation cannot pass with the specified four plugins. Windows XP connection plugins such as windows.connscan exist in Volatility 3 but are outside the allow list, and widening the allow list is a scope change I have not made.

The guard rails held: no claim was confirmed without a real tool call id and a verbatim excerpt, and the failed plugin was reported as data. The triage step did not happen, so on this evaluation the honest headline is that the agent is a reliable but cautious reader of process tables and does not identify the malware by itself.

## Limits of these numbers

Three runs on one image with one model is a small sample. Cridex is a public sample with public write-ups, so any correct detail may partly reflect training data, although here the agent did not use that knowledge to name the malware.
