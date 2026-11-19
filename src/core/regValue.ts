/** Extracts the data of `name` from `reg query` output ("    NAME    REG_SZ    data"). */
export function parseRegValue(out: string, name: string): string | undefined {
  for (const line of out.split(/\r?\n/)) {
    const m = /^\s+(\S+)\s+REG_(?:EXPAND_)?SZ\s+(.*)$/.exec(line);
    if (m && m[1].toLowerCase() === name.toLowerCase()) return m[2].trim() || undefined;
  }
  return undefined;
}
