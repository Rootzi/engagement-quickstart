#!/usr/bin/env bash
# =====================================================================
#  Engagement setup
#
#  SOURCE this file, don't run it, or the variables vanish when it exits:
#      source ./engagement.sh
#
#  Run it again in every new terminal / tmux pane (secrets are prompted
#  each time and only ever live in that shell's memory, never on disk).
# =====================================================================

# Where this repo lives (so `prep` can find reportprep.py)
export QS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# --- Engagement details: edit these per job --------------------------
export ENG_NAME="CLIENT-2026-11"                  # used for folder names
export ENG_ROOT="$HOME/engagements/$ENG_NAME"
export DOMAIN="corp.local"
export DC_IP="10.0.0.10"
export IFACE="eth0"                               # interface facing the client network

# Your IP on that interface (for relays, listeners, coercion)
export LHOST="$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)"

# --- Credentials: prompted, never written to disk --------------------
printf 'Test username: ';                   read -r  TUSER
printf 'Test password (blank to skip): ';   read -rs TPASS;  echo
printf 'NT hash (blank to skip): ';         read -rs NTHASH; echo
export TUSER TPASS NTHASH

# --- Folder layout (matches what the report parser will read) --------
export SCOPE="$ENG_ROOT/scope.txt"
export TARGETS="$ENG_ROOT/targets.txt"
for d in nessus nmap naabu nuclei burp testssl sslscan nxc relay screenshots notes; do
    mkdir -p "$ENG_ROOT/$d"
done
touch "$SCOPE" "$TARGETS"
touch "$ENG_ROOT/notes/limitations.md"     # jot limitations as they happen (report 2.5)

# Non-secret engagement details for report section 2.4 (password/hash never saved)
if [ -n "$TUSER" ]; then
    printf 'engagement=%s\ndomain=%s\nusername=%s\n' "$ENG_NAME" "$DOMAIN" "$TUSER" \
        > "$ENG_ROOT/engagement.info"
fi

# --- Helpers ---------------------------------------------------------

# testssl one service, saving JSON for the parser:   tssl 10.0.0.5:443
tssl() {
    local out="$ENG_ROOT/testssl/${1//[:\/]/_}.json"
    testssl --quiet --overwrite --jsonfile "$out" "$@"
}

# nmap with all output formats saved:   nscan mylabel -sS -p23 10.0.0.5
nscan() {
    local label="$1"; shift
    sudo nmap -oA "$ENG_ROOT/nmap/${label}_$(date +%F_%H%M)" "$@"
}

# nxc with results also logged to file:   nx smb "$TARGETS" -u "$TUSER" -p "$TPASS"
nx() {
    nxc "$@" --log "$ENG_ROOT/nxc/nxc_$(date +%F).log"
}

# ntlmrelayx with everything tee'd to a timestamped log:
#   relay -tf "$ENG_ROOT/nxc/relay_targets.txt" -smb2support -socks
relay() {
    local bin
    bin="$(command -v impacket-ntlmrelayx || command -v ntlmrelayx.py)"
    if [ -z "$bin" ]; then echo "ntlmrelayx not found"; return 1; fi
    sudo "$bin" "$@" 2>&1 | tee -a "$ENG_ROOT/relay/relay_$(date +%F_%H%M).log"
}

# Build the report-prep spreadsheet from everything in $ENG_ROOT:   prep
prep() {
    python3 "$QS_DIR/reportprep.py" --eng-root "$ENG_ROOT" "$@"
}

# Wipe creds from this shell when you're done:   engdone
engdone() {
    unset TUSER TPASS NTHASH
    echo "Credentials cleared from this shell."
}

# --- Summary ---------------------------------------------------------
echo
echo "Engagement : $ENG_NAME"
echo "Folder     : $ENG_ROOT"
echo "Domain/DC  : $DOMAIN / $DC_IP"
echo "LHOST      : ${LHOST:-(not found on $IFACE)}"
echo "User       : ${TUSER:-(none)}   Password: $([ -n "$TPASS" ] && echo set || echo none)   Hash: $([ -n "$NTHASH" ] && echo set || echo none)"
echo
echo "Functions:"
echo "  nx <proto> <args>        nxc, logged to \$ENG_ROOT/nxc/"
echo "                           e.g. nx smb \"\$TARGETS\" -u \"\$TUSER\" -p \"\$TPASS\" --gen-relay-list \"\$ENG_ROOT/nxc/relay_targets.txt\""
echo "  relay <args>             ntlmrelayx (sudo), tee'd to \$ENG_ROOT/relay/"
echo "                           e.g. relay -tf \"\$ENG_ROOT/nxc/relay_targets.txt\" -smb2support -socks"
echo "  tssl <host:port>         testssl, JSON saved to \$ENG_ROOT/testssl/"
echo "  nscan <label> <args>     nmap (sudo) with -oA into \$ENG_ROOT/nmap/"
echo "                           e.g. nscan telnet -sS -p23 --script=telnet-encryption 10.0.0.5"
echo "  prep                     build report-prep spreadsheet from \$ENG_ROOT"
echo "  engdone                  clear credentials from this shell"
echo
