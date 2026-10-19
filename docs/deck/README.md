# Supplied source deck

Privacy redaction (2026-10-19): personal usernames in historical local paths below are replaced with [redacted-user]. This does not claim those commands were rerun or change the original capture evidence.

This directory preserves the user's original `de_ppt.pdf`, supplied from the local Downloads
directory on 2026-09-06. Do not rewrite it to make proposed changes appear to be original slide text.

VERIFIED: this read-only command returned matching source and copy hashes:

```powershell
Get-FileHash -LiteralPath 'C:\Users\[redacted-user]\Downloads\de_ppt.pdf','docs/deck/de_ppt.pdf' -Algorithm SHA256 | Select-Object Path,Hash | ConvertTo-Json
```

```json
[
  {
    "Path": "C:\\Users\\[redacted-user]\\Downloads\\de_ppt.pdf",
    "Hash": "F4D2C012559D86B63F5228D6BC753DDC5C5C5D07DEE9FFD22202494A0A1F7C4E"
  },
  {
    "Path": "C:\\Users\\[redacted-user]\\Downloads\\fragmented\\docs\\deck\\de_ppt.pdf",
    "Hash": "F4D2C012559D86B63F5228D6BC753DDC5C5C5D07DEE9FFD22202494A0A1F7C4E"
  }
]
```

The hash records byte identity between the supplied file and the copy, not independent provenance,
signature verification, malware clearance or confirmation of the deck's research claims.

VERIFIED: `git diff --cached --stat -- docs/deck/de_ppt.pdf` returned at staging time:

```text
 docs/deck/de_ppt.pdf | Bin 0 -> 519896 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)
```

Staged does not mean committed. Check current Git state before stating otherwise.

VERIFIED: the following local inspection command reported `PDF pages: 16` and `Encrypted: False`
before printing the extracted text. Empty text on pages 7/14 was followed by local page rendering,
not treated as missing visual content:

```powershell
& python3.12 -c "from pathlib import Path; import pymupdf; path = Path(r'C:\Users\[redacted-user]\Downloads\de_ppt.pdf'); assert path.is_file(), f'MISSING: {path}'; document = pymupdf.open(path); print('PDF pages:', document.page_count); print('Encrypted:', bool(document.needs_pass)); pages = (7, 13, 14, 15); print('\n'.join('PAGE ' + str(number) + '\n' + document[number - 1].get_text() for number in pages if number <= document.page_count)); document.close()"
```

Inspected locations, not independently validated research claims:

- Page 7: gap radar, labelled literature coverage and research-need severity.
- Page 13: methodology stages 1-5 and claimed setup/duplicate/false-positive reductions.
- Page 14: module diagram; it includes two labels for Module 4.
- Page 15: stages 6-8, reporting and re-scan; the current source wording is "PDF or HTML".

NOT RUN: independent literature verification or measurement of the percentage claims. This task
inspects supplied source material only. "HTML report (printable)" is proposed design wording, not an
edit to this original PDF. Rendered preview images are temporary local inspection outputs, not lab
fixtures, feed evidence, model output or generated replacement slides.
