// bounty/lib/dedup.js — canonical keys + candidate dedup.
export function canonicalKey({ endpoint = "", method = "", param = "", vulnClass = "", cwe = "" }) {
  const normEndpoint = String(endpoint).trim().toLowerCase().replace(/\/+$/, "") || "/";
  const normMethod = String(method).trim().toUpperCase();
  const normParam = String(param).trim().toLowerCase();
  const normClass = String(vulnClass).trim().toLowerCase().replace(/[\s_]+/g, "-");
  const normCwe = String(cwe).trim().toUpperCase();
  return [normEndpoint, normMethod, normParam, normClass, normCwe].join("|");
}

export function dedupCandidates(list = []) {
  const seen = new Map();
  const unique = [];
  const duplicates = [];
  for (const item of list) {
    const key = canonicalKey({
      endpoint: item.endpoint ?? item.path ?? "",
      method: item.method ?? "",
      param: item.param ?? "",
      vulnClass: item.vuln_class ?? item.vulnClass ?? "",
      cwe: item.cwe ?? "",
    });
    if (seen.has(key)) {
      duplicates.push(item);
    } else {
      seen.set(key, item);
      unique.push(item);
    }
  }
  return { unique, duplicates };
}

export default { canonicalKey, dedupCandidates };
