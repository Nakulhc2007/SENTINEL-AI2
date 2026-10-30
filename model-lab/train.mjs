import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(ROOT, 'data');
const ARTIFACT_DIR = path.join(ROOT, 'artifacts');
const SEED = 20261030;
const ROWS_PER_DOMAIN = 800;
const FOREST_SIZE = 25;
const MAX_DEPTH = 8;
const MIN_LEAF = 12;

const domains = [
  'banking', 'healthcare', 'education', 'government',
  'corporate', 'manufacturing', 'retail', 'public_services'
];
const domainPrefixes = {
  banking: 'BNK', healthcare: 'HLT', education: 'EDU', government: 'GOV',
  corporate: 'COR', manufacturing: 'MFG', retail: 'RTL', public_services: 'PUB'
};
const scenarios = [
  'credential_abuse', 'unauthorized_access', 'excessive_requests',
  'malware_activity', 'document_tampering', 'privilege_misuse', 'data_exfiltration'
];
const numericFeatures = [
  'failed_logins', 'success_after_failures', 'unfamiliar_region', 'after_hours',
  'restricted_access_attempts', 'request_rate_ratio', 'malware_alerts',
  'document_hash_mismatch', 'sensitive_resource_access', 'privilege_changes',
  'unique_source_ips', 'source_reputation', 'managed_device', 'events_in_5m'
];
const featureNames = [...numericFeatures, ...domains.map(domain => `domain_${domain}`)];

function random(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = random(SEED);
const between = (min, max) => Math.floor(rand() * (max - min + 1)) + min;
const chance = probability => rand() < probability;
const rounded = (value, digits = 2) => Number(value.toFixed(digits));

function benignEvent(domain) {
  const event = {
    failed_logins: between(0, 2), success_after_failures: 0, unfamiliar_region: 0,
    after_hours: chance(0.13) ? 1 : 0, restricted_access_attempts: 0,
    request_rate_ratio: rounded(0.35 + rand() * 2.2), malware_alerts: 0,
    document_hash_mismatch: 0, sensitive_resource_access: chance(0.28) ? 1 : 0,
    privilege_changes: 0, unique_source_ips: between(1, 3),
    source_reputation: between(64, 100), managed_device: chance(0.88) ? 1 : 0,
    events_in_5m: between(1, 32)
  };

  // Benign edge cases create realistic overlap with the threat classes.
  if (chance(0.16)) event.failed_logins = between(3, 7);
  if (chance(0.08)) event.request_rate_ratio = rounded(2.4 + rand() * 3.8);
  if (chance(0.035)) event.unfamiliar_region = 1;
  if (chance(0.018)) event.document_hash_mismatch = 1;
  if (chance(0.012)) event.restricted_access_attempts = 1;
  if (chance(0.01)) event.privilege_changes = 1;
  if (domain === 'manufacturing' && chance(0.12)) event.events_in_5m += between(10, 45);
  if (domain === 'retail' && chance(0.12)) event.request_rate_ratio = rounded(2.2 + rand() * 3.5);
  return event;
}

function threatEvent(domain, scenario) {
  const event = benignEvent(domain);
  switch (scenario) {
    case 'credential_abuse':
      event.failed_logins = between(5, 18);
      event.success_after_failures = chance(0.68) ? 1 : 0;
      event.unfamiliar_region = chance(0.58) ? 1 : 0;
      event.after_hours = chance(0.65) ? 1 : event.after_hours;
      event.unique_source_ips = between(1, 7);
      event.source_reputation = between(8, 62);
      event.managed_device = chance(0.22) ? 1 : 0;
      break;
    case 'unauthorized_access':
      event.restricted_access_attempts = between(1, 5);
      event.sensitive_resource_access = chance(0.78) ? 1 : 0;
      event.failed_logins = between(0, 8);
      event.unfamiliar_region = chance(0.36) ? 1 : 0;
      event.source_reputation = between(15, 75);
      event.managed_device = chance(0.38) ? 1 : 0;
      break;
    case 'excessive_requests':
      event.request_rate_ratio = rounded(4.2 + rand() * 10.5);
      event.events_in_5m = between(70, 320);
      event.unique_source_ips = between(2, 16);
      event.source_reputation = between(12, 82);
      break;
    case 'malware_activity':
      event.malware_alerts = between(1, 3);
      event.managed_device = chance(0.24) ? 1 : 0;
      event.source_reputation = between(5, 68);
      event.events_in_5m = between(8, 90);
      break;
    case 'document_tampering':
      event.document_hash_mismatch = 1;
      event.sensitive_resource_access = chance(0.72) ? 1 : 0;
      event.after_hours = chance(0.57) ? 1 : 0;
      event.unfamiliar_region = chance(0.28) ? 1 : 0;
      event.source_reputation = between(22, 92);
      break;
    case 'privilege_misuse':
      event.privilege_changes = between(1, 3);
      event.restricted_access_attempts = chance(0.55) ? between(1, 3) : 0;
      event.after_hours = chance(0.62) ? 1 : event.after_hours;
      event.sensitive_resource_access = chance(0.58) ? 1 : 0;
      event.source_reputation = between(18, 82);
      break;
    case 'data_exfiltration':
      event.sensitive_resource_access = 1;
      event.request_rate_ratio = rounded(2.5 + rand() * 8.5);
      event.events_in_5m = between(35, 250);
      event.unique_source_ips = between(1, 9);
      event.after_hours = chance(0.52) ? 1 : 0;
      event.source_reputation = between(18, 82);
      break;
  }

  // Operational baselines differ by sector while keeping one shared feature schema.
  if (domain === 'banking' && scenario === 'data_exfiltration') event.sensitive_resource_access = 1;
  if (domain === 'healthcare' && scenario === 'unauthorized_access') event.after_hours = 1;
  if (domain === 'education' && scenario === 'credential_abuse') event.unique_source_ips += between(0, 3);
  if (domain === 'government' && scenario === 'privilege_misuse') event.restricted_access_attempts += 1;
  if (domain === 'corporate' && scenario === 'data_exfiltration') event.request_rate_ratio += 1.1;
  if (domain === 'manufacturing' && scenario === 'malware_activity') event.events_in_5m += between(12, 55);
  if (domain === 'retail' && scenario === 'excessive_requests') event.request_rate_ratio += 1.4;
  if (domain === 'public_services' && scenario === 'unauthorized_access') event.sensitive_resource_access = 1;
  return event;
}

function makeDataset() {
  const rows = [];
  const baseDate = Date.UTC(2026, 4, 1);
  for (const domain of domains) {
    const positives = Math.round(ROWS_PER_DOMAIN * 0.34);
    for (let index = 0; index < ROWS_PER_DOMAIN; index++) {
      const suspicious = index < positives ? 1 : 0;
      const scenario = suspicious ? scenarios[between(0, scenarios.length - 1)] : 'routine_activity';
      const signals = suspicious ? threatEvent(domain, scenario) : benignEvent(domain);
      const eventNumber = String(index + 1).padStart(5, '0');
      rows.push({
        event_id: `SYN-${domainPrefixes[domain]}-${eventNumber}`,
        event_time: new Date(baseDate + (rows.length * 5 + between(0, 4)) * 60_000).toISOString(),
        domain,
        scenario,
        ...signals,
        suspicious
      });
    }
  }

  // Stratify within every domain and label so the holdout reflects each sector.
  const splitRand = random(SEED + 41);
  for (const domain of domains) {
    for (const label of [0, 1]) {
      const group = rows.filter(row => row.domain === domain && row.suspicious === label);
      for (let i = group.length - 1; i > 0; i--) {
        const j = Math.floor(splitRand() * (i + 1));
        [group[i], group[j]] = [group[j], group[i]];
      }
      const trainCount = Math.floor(group.length * 0.8);
      group.forEach((row, index) => { row.split = index < trainCount ? 'train' : 'test'; });
    }
  }
  return rows;
}

function toCsv(rows) {
  const columns = Object.keys(rows[0]);
  const escape = value => `"${String(value).replaceAll('"', '""')}"`;
  return [columns.join(','), ...rows.map(row => columns.map(column => escape(row[column])).join(','))].join('\n') + '\n';
}

function vector(row) {
  return [...numericFeatures.map(name => Number(row[name])), ...domains.map(domain => row.domain === domain ? 1 : 0)];
}
function gini(positive, total) {
  if (!total) return 0;
  const p = positive / total;
  return 2 * p * (1 - p);
}
function leaf(samples) {
  const positives = samples.reduce((sum, sample) => sum + sample.y, 0);
  return { p: positives / samples.length, n: samples.length };
}
function shuffled(values, randFn) {
  const result = [...values];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(randFn() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function buildTree(samples, depth, randFn) {
  const positives = samples.reduce((sum, sample) => sum + sample.y, 0);
  if (depth >= MAX_DEPTH || samples.length < MIN_LEAF * 2 || positives === 0 || positives === samples.length) return leaf(samples);

  const featureCount = Math.max(3, Math.floor(Math.sqrt(featureNames.length)));
  const selectedFeatures = shuffled(featureNames.map((_, index) => index), randFn).slice(0, featureCount);
  const parentImpurity = gini(positives, samples.length);
  let best = null;

  for (const featureIndex of selectedFeatures) {
    const ordered = samples.map(sample => ({ value: sample.x[featureIndex], y: sample.y })).sort((a, b) => a.value - b.value);
    let leftPositive = 0;
    for (let index = 0; index < ordered.length - 1; index++) {
      leftPositive += ordered[index].y;
      const leftCount = index + 1;
      const rightCount = ordered.length - leftCount;
      if (leftCount < MIN_LEAF || rightCount < MIN_LEAF || ordered[index].value === ordered[index + 1].value) continue;
      const rightPositive = positives - leftPositive;
      const weighted = (leftCount * gini(leftPositive, leftCount) + rightCount * gini(rightPositive, rightCount)) / ordered.length;
      const gain = parentImpurity - weighted;
      if (!best || gain > best.gain) {
        best = {
          featureIndex,
          threshold: (ordered[index].value + ordered[index + 1].value) / 2,
          gain
        };
      }
    }
  }

  if (!best || best.gain < 0.002) return leaf(samples);
  const left = [], right = [];
  for (const sample of samples) (sample.x[best.featureIndex] <= best.threshold ? left : right).push(sample);
  if (left.length < MIN_LEAF || right.length < MIN_LEAF) return leaf(samples);
  return {
    f: best.featureIndex,
    t: best.threshold,
    gain: best.gain,
    left: buildTree(left, depth + 1, randFn),
    right: buildTree(right, depth + 1, randFn)
  };
}

function predictTree(tree, values) {
  let node = tree;
  while (node.left && node.right) node = values[node.f] <= node.t ? node.left : node.right;
  return node.p;
}

function trainForest(trainingRows) {
  const training = trainingRows.map(row => ({ x: vector(row), y: row.suspicious }));
  const modelRand = random(SEED + 99);
  const trees = [];
  for (let treeIndex = 0; treeIndex < FOREST_SIZE; treeIndex++) {
    const bootstrap = Array.from({ length: training.length }, () => training[Math.floor(modelRand() * training.length)]);
    trees.push(buildTree(bootstrap, 0, modelRand));
  }
  return {
    name: 'SENTINEL synthetic multi-domain classifier',
    algorithm: 'Random Forest (CART decision trees, Gini impurity)',
    seed: SEED,
    threshold: 0.5,
    features: featureNames,
    domains,
    trees
  };
}

function score(model, row) {
  const values = vector(row);
  return model.trees.reduce((total, tree) => total + predictTree(tree, values), 0) / model.trees.length;
}
function metrics(rows, model) {
  let tp = 0, tn = 0, fp = 0, fn = 0;
  const scored = rows.map(row => ({ actual: row.suspicious, probability: score(model, row), domain: row.domain }));
  for (const row of scored) {
    const predicted = row.probability >= model.threshold ? 1 : 0;
    if (predicted && row.actual) tp++;
    else if (predicted && !row.actual) fp++;
    else if (!predicted && row.actual) fn++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  const aucRows = [...scored].sort((a, b) => a.probability - b.probability);
  let positiveRankSum = 0, positiveCount = 0, negativeCount = 0;
  for (let i = 0; i < aucRows.length;) {
    let end = i + 1;
    while (end < aucRows.length && aucRows[end].probability === aucRows[i].probability) end++;
    const averageRank = ((i + 1) + end) / 2;
    for (let j = i; j < end; j++) {
      if (aucRows[j].actual) { positiveCount++; positiveRankSum += averageRank; }
      else negativeCount++;
    }
    i = end;
  }
  const auc = positiveCount && negativeCount
    ? (positiveRankSum - positiveCount * (positiveCount + 1) / 2) / (positiveCount * negativeCount)
    : 0;
  return {
    samples: rows.length,
    confusion_matrix: { true_positive: tp, false_positive: fp, true_negative: tn, false_negative: fn },
    accuracy: rounded((tp + tn) / rows.length, 4),
    precision: rounded(precision, 4),
    recall: rounded(recall, 4),
    f1: rounded(f1, 4),
    roc_auc: rounded(auc, 4)
  };
}

function main() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
  const rows = makeDataset();
  fs.writeFileSync(path.join(DATA_DIR, 'all_domains.csv'), toCsv(rows));
  const domainDir = path.join(DATA_DIR, 'by_domain');
  fs.mkdirSync(domainDir, { recursive: true });
  for (const domain of domains) {
    fs.writeFileSync(path.join(domainDir, `${domain}.csv`), toCsv(rows.filter(row => row.domain === domain)));
  }

  const trainingRows = rows.filter(row => row.split === 'train');
  const testRows = rows.filter(row => row.split === 'test');
  const model = trainForest(trainingRows);
  const report = {
    title: 'SENTINEL-AI synthetic dataset evaluation',
    evaluation_note: 'These metrics measure a deterministic synthetic holdout only. They are not estimates of real-world detection accuracy.',
    dataset: {
      total_rows: rows.length,
      rows_per_domain: ROWS_PER_DOMAIN,
      domains,
      suspicious_rate: rounded(rows.filter(row => row.suspicious).length / rows.length, 4),
      split: { training_rows: trainingRows.length, test_rows: testRows.length, method: '80/20 stratified by domain and label' },
      seed: SEED
    },
    model: { algorithm: model.algorithm, tree_count: model.trees.length, max_depth: MAX_DEPTH, minimum_leaf_size: MIN_LEAF, threshold: model.threshold },
    overall: metrics(testRows, model),
    by_domain: Object.fromEntries(domains.map(domain => [domain, metrics(testRows.filter(row => row.domain === domain), model)]))
  };
  fs.writeFileSync(path.join(ARTIFACT_DIR, 'model.json'), JSON.stringify(model));
  fs.writeFileSync(path.join(ARTIFACT_DIR, 'evaluation.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
}

main();
