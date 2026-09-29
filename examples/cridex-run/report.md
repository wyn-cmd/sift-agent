# DFIR Investigation Report

## Findings
- Claim: The memory image corresponds to Windows XP Service Pack 3 (NtMajorVersion 5, NtMinorVersion 1, CSDVersion 3, NTBuildLab 2600.xpsp.080413-2111).
  Status: confirmed
  Tool Call IDs: 1918ebef-603b-4cd2-8e47-8656fbf99de9
  Excerpt: NTBuildLab	2600.xpsp.080413-2111
CSDVersion	3
NtMajorVersion	5
NtMinorVersion	1

- Claim: The windows.netscan plugin failed with a NotImplementedError because Windows version 5.1 is not supported by netscan.
  Status: confirmed
  Tool Call IDs: 3a244228-b833-48dc-b752-f06916ed9c94
  Excerpt: NotImplementedError: This version of Windows is not supported: 5.1 15.2600

- Claim: Process reader_sl.exe is running with PID 1640 and path C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe.
  Status: confirmed
  Tool Call IDs: f454c769-702a-4583-80ae-c2c2e62c1422, cc42b56c-0249-4c4d-b377-8969d8328597
  Excerpt: 1640	1484	reader_sl.exe	0x81e7bda0	5	39	0	False	2012-07-22 02:42:36.000000 UTC	N/A	Disabled
1640	reader_sl.exe	"C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe"

- Claim: Two instances of wuauclt.exe are running with PIDs 1136 and 1588.
  Status: confirmed
  Tool Call IDs: f454c769-702a-4583-80ae-c2c2e62c1422, cc42b56c-0249-4c4d-b377-8969d8328597
  Excerpt: 1136	1004	wuauclt.exe	0x821fcda0	8	173	0	False	2012-07-22 02:43:46.000000 UTC	N/A	Disabled
1588	1004	wuauclt.exe	0x8205bda0	5	132	0	False	2012-07-22 02:44:01.000000 UTC	N/A	Disabled

## Limitations
- Truncated plugins: None
- Calls used vs cap: 4 / 15
- Plugins never run: None
- Rate limit approached: No