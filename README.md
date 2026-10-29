# engagement-quickstart

Per-engagement setup for internal/external tests: variables, folder layout and logged tool wrappers, so output lands where the report-prep parser can find it.

## Use

1. Edit the top block of `engagement.sh` (engagement name, domain, DC, interface).
2. Source it in every terminal or tmux pane:

   ```bash
   source ./engagement.sh
   ```

   It prompts for the test username, password and NT hash. These only live in that shell's memory and are never written to disk.
3. Use the variables, not the values:

   ```bash
   nx smb "$TARGETS" -u "$TUSER" -p "$TPASS" --gen-relay-list "$ENG_ROOT/nxc/relay_targets.txt"
   ```

   Double quotes matter. `'$TPASS'` sends the literal text `$TPASS`.
4. Run `engdone` when finished to clear credentials from the shell.

## Functions

| Function | Wraps | Output |
|---|---|---|
| `nx <proto> <args>` | nxc | `$ENG_ROOT/nxc/` |
| `relay <args>` | ntlmrelayx (sudo) | `$ENG_ROOT/relay/` |
| `tssl <host:port>` | testssl (JSON) | `$ENG_ROOT/testssl/` |
| `nscan <label> <args>` | nmap (sudo, `-oA`) | `$ENG_ROOT/nmap/` |
| `shot [--here\|-o DIR] <targets>` | headless Chromium | `$ENG_ROOT/screenshots/` |
| `prep` | reportprep.py | `$ENG_ROOT/report_prep_<date>.xlsx` |

### Screenshots (`shot`)

Headless Chromium, so no display is needed and it works over plain SSH. Needs `chromium` (`apt install chromium`) and `curl`.

```bash
shot https://10.0.0.5/login          # saves to $ENG_ROOT/screenshots/
shot --here 10.0.0.5:8443            # saves to the current directory
shot -o /some/dir urls.txt           # file with one URL/host per line (# comments ok)
shot clickjackpoc.html               # local HTML files, e.g. framing PoCs
```

- Bare hosts default to `https://`, except `:80`, `:8080` and `:8000`, which use `http://`.
- Unreachable targets are skipped instead of screenshotting Chrome's error page.
- Certificate errors are ignored, and Chrome's background calls to Google are switched off.
- To view shots from a remote box: `scp box:'~/engagements/<ENG>/screenshots/*' .`
| `engdone` | n/a | clears creds |

## Report prep (`prep`)

Drop `.nessus` exports into `$ENG_ROOT/nessus/` and run `prep`. It writes a spreadsheet with:

- **Summary**: 2.4 Information Provided line, findings by risk, suggested 1.4 area ratings, 3.3 priority order
- **Findings**: one row per library title, with risk, area, consolidated IP ranges, a verification command and evidence from a representative host
- **Affected**: one row per finding/host/port, each with its own verification command
- **Unmapped**: anything non-informational that didn't match a library title, with a Tenable link
- **Scope** and **Limitations**: from `targets.txt`/`scope.txt` and `notes/limitations.md`

Mapping lives in `mapping.toml`. Add a `[[finding]]` (or a plugin ID to an existing one) whenever something lands on Unmapped that belongs to a library title.

Needs Python 3.11+ and openpyxl (`apt install python3-openpyxl`). Runs entirely locally.

You can also run it directly: `python3 reportprep.py scan1.nessus scan2.nessus -o prep.xlsx`.

## Folder layout

```
$ENG_ROOT/
  scope.txt  targets.txt
  nessus/ nmap/ naabu/ nuclei/ burp/ testssl/ sslscan/ nxc/ relay/ screenshots/ notes/
```

## Notes

- nxc prints the password on successful logins. Set `audit_mode = *` in `~/.nxc/nxc.conf` to mask it, and check once before relying on it in screenshots.
- Test `relay` on a lab box before using it on an engagement.
- Never commit engagement output to this repo. `.gitignore` blocks the usual output types as a safety net.
