// node verify-report.mjs REPORT VCEK
// Verifies a SEV-SNP attestation report offline with the verifier this repository already ships
// (tee/web/snp-verify.js): AMD Genoa ARK (pinned by hash) -> ASK -> VCEK, then the report's ECDSA P-384
// signature by that VCEK. The AMD ARK and ASK come from tee/fixtures. REPORT_DATA binding is not checked
// here: it is per box and does not affect the MEASUREMENT.
// Prints one JSON line {"ok":true,"measurement":"<96 hex>","policy":"<16 hex>"} and exits 0,
// or prints {"ok":false,"error":"..."} and exits 1.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifySnp } from '../../web/snp-verify.js';

const fx = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures');
const read = (p) => new Uint8Array(readFileSync(p));
try {
  if (process.argv.length !== 4) throw new Error('usage: verify-report.mjs REPORT VCEK');
  const r = await verifySnp({
    report: read(process.argv[2]),
    certs: { ark: read(join(fx, 'amd-genoa-ark.der')), ask: read(join(fx, 'amd-genoa-ask.der')), vcek: read(process.argv[3]) },
    // This script only checks the chain and the signature and prints the MEASUREMENT; the caller compares it
    // with the computed fingerprint. So no list is given here, and the verifier is told so in plain terms.
    allowedMeasurements: [],
    allowAnyMeasurement: true,
  });
  console.log(JSON.stringify({ ok: true, measurement: r.measurement, policy: r.policy }));
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: String(e.message || e) }));
  process.exit(1);
}
