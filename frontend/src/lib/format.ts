/* Display formatting shared by pages. */
export const fmtUtc = (ts: string | null | undefined, withMs = false): string => {
  if (!ts) return 'not observed';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const iso = d.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, withMs ? 23 : 19)} UTC`;
};
export const shortSession = (id: string | null | undefined) => (id ? id.split('~').pop() ?? id : '');
export const fmtScore = (s: number | null | undefined) => (s === null || s === undefined ? 'N/A' : Math.round(s).toString());

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export const severityRank = (s: string) => SEV_ORDER.indexOf(s.toUpperCase() as (typeof SEV_ORDER)[number]);

/** "tcp-<client>_<cport>-<server>_<sport>[-n]" -> readable endpoints. */
export const sessionEndpoints = (id: string | null | undefined): { client: string; server: string } | null => {
  const m = /^tcp-(.+)_(\d+)-(.+)_(\d+)(?:-\d+)?$/.exec(shortSession(id));
  return m ? { client: `${m[1]}:${m[2]}`, server: `${m[3]}:${m[4]}` } : null;
};
