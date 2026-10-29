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
| `engdone` | n/a | clears creds |

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
