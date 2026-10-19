const AV = {N: 0.85, A: 0.62, L: 0.55, P: 0.20};
const AC = {L: 0.77, H: 0.44};
const UI = {N: 0.85, R: 0.62};
const PR_U = {N: 0.85, L: 0.62, H: 0.27};
const PR_C = {N: 0.85, L: 0.68, H: 0.50};
const CIA = {H: 0.56, L: 0.22, N: 0};
const REQUIREMENTS = {H: 1.5, M: 1, L: 0.5, X: 1};
const EXPLOIT = {X: 1, H: 1, F: 0.97, P: 0.94, U: 0.91};
const REMEDIATION = {X: 1, U: 1, W: 0.97, T: 0.96, O: 0.95};
const CONFIDENCE = {X: 1, C: 1, R: 0.96, U: 0.92};
const ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
const ALLOWED = {AV, AC, PR: PR_U, UI, S: {U: 1, C: 1}, C: CIA, I: CIA, A: CIA, E: EXPLOIT, RL: REMEDIATION, RC: CONFIDENCE, CR: REQUIREMENTS, IR: REQUIREMENTS, AR: REQUIREMENTS};
for (const [modified, base] of Object.entries({MAV: 'AV', MAC: 'AC', MPR: 'PR', MUI: 'UI', MS: 'S', MC: 'C', MI: 'I', MA: 'A'})) ALLOWED[modified] = {...ALLOWED[base], X: 1};

function pythonRound(value, digits) {
  if (!Number.isFinite(value)) throw new Error('A score must be finite.');
  if (value === 0) return value;
  const data = new DataView(new ArrayBuffer(8));
  data.setFloat64(0, Math.abs(value));
  const bits = data.getBigUint64(0);
  const encodedExponent = Number((bits >> 52n) & 2047n);
  const fraction = bits & ((1n << 52n) - 1n);
  const mantissa = encodedExponent ? fraction + (1n << 52n) : fraction;
  const exponent = (encodedExponent || 1) - 1023 - 52;
  let numerator = mantissa * 10n ** BigInt(digits);
  let denominator = 1n;
  if (exponent >= 0) numerator <<= BigInt(exponent);
  else denominator <<= BigInt(-exponent);
  let quotient = numerator / denominator;
  const remainder = numerator % denominator;
  if (remainder * 2n > denominator || (remainder * 2n === denominator && quotient % 2n === 1n)) quotient += 1n;
  return Math.sign(value) * Number(quotient) / 10 ** digits;
}

function roundup(value) {
  const integer = pythonRound(value * 100000, 0);
  return integer % 10000 === 0 ? integer / 100000 : (Math.floor(integer / 10000) + 1) / 10;
}

export function parseVector(vector) {
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:3.')) throw new Error('A stored CVSS 3.x vector is required.');
  const metrics = {};
  for (const token of vector.split('/').slice(1)) {
    const [key, value, extra] = token.split(':');
    if (extra !== undefined || !Object.hasOwn(ALLOWED, key) || !Object.hasOwn(ALLOWED[key], value)) throw new Error(`Invalid CVSS metric: ${token}`);
    metrics[key] = value;
  }
  for (const key of ORDER.slice(0, 8)) if (!Object.hasOwn(metrics, key)) throw new Error(`Missing CVSS metric: ${key}`);
  return metrics;
}

function modified(metrics, name, base) {
  const value = metrics[name] ?? 'X';
  return value === 'X' ? metrics[base] : value;
}

function baseScore(metrics) {
  const changed = metrics.S === 'C';
  const impactSubscore = 1 - ((1 - CIA[metrics.C]) * (1 - CIA[metrics.I]) * (1 - CIA[metrics.A]));
  const impact = changed ? 7.52 * (impactSubscore - 0.029) - 3.25 * (impactSubscore - 0.02) ** 15 : 6.42 * impactSubscore;
  const privileges = (changed ? PR_C : PR_U)[metrics.PR];
  const exploitability = 8.22 * AV[metrics.AV] * AC[metrics.AC] * privileges * UI[metrics.UI];
  if (impact <= 0) return 0;
  return roundup(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
}

function environmentalScore(metrics) {
  const changed = modified(metrics, 'MS', 'S') === 'C';
  const confidentiality = CIA[modified(metrics, 'MC', 'C')];
  const integrity = CIA[modified(metrics, 'MI', 'I')];
  const availability = CIA[modified(metrics, 'MA', 'A')];
  const impactSubscore = Math.min(1 - (
    (1 - REQUIREMENTS[metrics.CR ?? 'X'] * confidentiality) *
    (1 - REQUIREMENTS[metrics.IR ?? 'X'] * integrity) *
    (1 - REQUIREMENTS[metrics.AR ?? 'X'] * availability)
  ), 0.915);
  const impact = changed ? 7.52 * (impactSubscore - 0.029) - 3.25 * (impactSubscore * 0.9731 - 0.02) ** 13 : 6.42 * impactSubscore;
  const privileges = (changed ? PR_C : PR_U)[modified(metrics, 'MPR', 'PR')];
  const exploitability = 8.22 * AV[modified(metrics, 'MAV', 'AV')] * AC[modified(metrics, 'MAC', 'AC')] * privileges * UI[modified(metrics, 'MUI', 'UI')];
  if (impact <= 0) return 0;
  const temporal = EXPLOIT[metrics.E ?? 'X'] * REMEDIATION[metrics.RL ?? 'X'] * CONFIDENCE[metrics.RC ?? 'X'];
  return roundup(roundup(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10)) * temporal);
}

export function scoreVector(vector) {
  const metrics = parseVector(vector);
  return {base: baseScore(metrics), environmental: environmentalScore(metrics)};
}

export function sandbox(vector, profile, changes, weights) {
  const metrics = parseVector(vector);
  const settings = weights.environmental;
  const minimum = settings.min_confidence_to_apply ?? 0.5;
  const local = JSON.parse(JSON.stringify(profile));
  const feature = value => ({value, confidence: 1, source: 'manual', evidence: 'Sandbox assumption'});
  local.controls ||= {};
  local.manual ||= {};
  if (Object.hasOwn(changes, 'role')) local.role = feature(changes.role);
  if (Object.hasOwn(changes, 'exposure')) local.exposure = feature(changes.exposure);
  if (Object.hasOwn(changes, 'waf')) local.controls.waf = feature(changes.waf);
  if (Object.hasOwn(changes, 'environment')) local.manual.environment = feature(changes.environment);
  if (local.exposure.value === 'internal' && metrics.AV === 'N' && local.exposure.confidence >= minimum) Object.assign(metrics, settings.internal_when_av_network);
  if (local.controls.waf?.value && local.controls.waf.confidence >= minimum) Object.assign(metrics, settings.waf_present);
  if (local.controls.auth_required?.value && metrics.PR === 'N' && local.controls.auth_required.confidence >= minimum) Object.assign(metrics, settings.auth_required_when_pr_none);
  const role = local.role.confidence >= minimum ? local.role.value : 'unknown';
  let requirements = {...(settings.role_requirements[role] || settings.role_requirements.unknown)};
  if (local.manual.environment?.value === 'test') requirements = {...settings.environment_test};
  const steps = Math.max(0, Number(local.manual.criticality?.value || 0) - settings.criticality_step_above);
  const stepUp = {L: 'M', M: 'H', H: 'H'};
  for (let step = 0; step < steps; step += 1) requirements = Object.fromEntries(Object.entries(requirements).map(([key, value]) => [key, stepUp[value]]));
  Object.assign(metrics, requirements);
  const environmental = environmentalScore(metrics);
  const percentile = changes.epss;
  if (percentile !== null && (!Number.isFinite(percentile) || percentile < 0 || percentile > 1)) throw new Error('EPSS percentile must be in 0..1 or absent.');
  let multiplier = percentile === null ? null : weights.threat.base_multiplier + weights.threat.epss_weight * percentile;
  if (changes.kev) multiplier = Math.max(multiplier || 0, weights.threat.kev_multiplier);
  let risk = multiplier === null ? environmental * 10 : environmental * 10 * multiplier;
  if (changes.kev) {
    risk += weights.threat.kev_boost;
    if (local.exposure.value === 'internet_facing') risk = Math.max(risk, weights.threat.kev_floor_internet_facing);
  }
  risk = pythonRound(Math.min(risk, 100), 1);
  const band = risk >= weights.bands.Critical ? 'Critical' : risk >= weights.bands.High ? 'High' : risk >= weights.bands.Medium ? 'Medium' : 'Low';
  return {
    base: baseScore(metrics), environmental, risk, band, multiplier,
    vector: ['CVSS:3.1', ...ORDER.filter(key => metrics[key] && metrics[key] !== 'X').map(key => `${key}:${metrics[key]}`)].join('/')
  };
}