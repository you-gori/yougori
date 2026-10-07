/** Reads the example from EC2 → Connect → SSH client, e.g. `ssh -i "key.pem" ec2-user@ec2-1-2-3-4.compute.amazonaws.com`. */
export function parseSshCommand(text: string): { username: string; host: string; port?: number; key?: string } | null {
  const tokens = (text.trim().match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map(token => token.replace(/^(["'])(.*)\1$/, "$2"))
  if (!/(^|[\\/])ssh(\.exe)?$/i.test(tokens[0] ?? "")) return null
  let username = "", host = "", port: number | undefined, key: string | undefined
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i] ?? ""
    if (token === "-i") key = tokens[++i]
    else if (token === "-p") port = Number(tokens[++i])
    else if (token === "-l") username = tokens[++i] ?? ""
    else if (["-o", "-F", "-J", "-L", "-R", "-D"].includes(token)) i++
    else if (!token.startsWith("-") && !host) {
      const at = token.lastIndexOf("@")
      if (at > 0) { username = token.slice(0, at); host = token.slice(at + 1) } else host = token
    }
  }
  if (!host || (port !== undefined && !(Number.isInteger(port) && port > 0 && port < 65536))) return null
  return { username, host, port, key }
}
