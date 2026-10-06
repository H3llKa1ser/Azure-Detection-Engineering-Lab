#!/usr/bin/env node
// Syntax + semantic check of every detection query using Microsoft's
// Kusto.Language library (the same analyzer behind the KQL editor).
// Usage: node scripts/kql/check.js     (run `npm ci` in scripts/kql first)
'use strict';
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
require('@kusto/language-service-next/bridge.min.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.min.js');

const K = global.Kusto.Language;
const ROOT = path.resolve(__dirname, '..', '..');
const DETECTIONS = path.join(ROOT, 'detections');
const SCHEMA = fs.readFileSync(path.join(__dirname, 'schema.kql'), 'utf8') + '\n';

// Same placeholder values as scripts/validate_detections.py
const VARS = {
  canary_secret_name: 'svc-backup-sql-prod-password',
  canary_blob_name: 'finance/2026-payroll-export.csv',
  canary_blob_leaf: '2026-payroll-export.csv',
  key_vault_name: 'kv-detlab-abcde',
  storage_name: 'stdetlababcde',
  watchlist_alias: 'LabApprovedPrivilegedCallers',
};
const render = (s) => s.replace(/\$\{([a-z_]+)\}/g, (_, k) => {
  if (!(k in VARS)) throw new Error(`unknown template variable \${${k}}`);
  return VARS[k];
});

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith('.yaml') ? [path.join(dir, e.name)] : []);
}

function lineOf(text, offset) {
  return text.slice(0, offset).split('\n').length;
}

let failures = 0;
const files = walk(DETECTIONS).sort();
for (const file of files) {
  const doc = yaml.load(render(fs.readFileSync(file, 'utf8')));
  const query = doc.query;
  const full = SCHEMA + query;
  const code = K.KustoCode.ParseAndAnalyze(full, K.GlobalState.Default);
  const diags = code.GetDiagnostics();
  const problems = [];
  for (let i = 0; i < diags.Count; i++) {
    const d = diags.getItem(i);
    const sev = String(d.Severity);
    if (sev !== 'Error') continue;
    const offset = d.Start - SCHEMA.length;
    const where = offset >= 0 ? `query line ${lineOf(query, offset)}` : 'schema.kql';
    problems.push(`${where}: ${d.Message}`);
  }
  // The query's last statement must produce a table.
  const resultType = code.ResultType;
  if (!problems.length && resultType && !(resultType instanceof K.Symbols.TableSymbol)) {
    problems.push(`query result is not tabular (${resultType.Display})`);
  }
  const rel = path.relative(ROOT, file);
  if (problems.length) {
    failures++;
    console.log(`FAIL ${doc.id} (${rel})`);
    problems.forEach((p) => console.log(`     - ${p}`));
  } else {
    console.log(`ok   ${doc.id}`);
  }
}
console.log(`\n${files.length - failures}/${files.length} queries passed KQL analysis`);
process.exit(failures ? 1 : 0);
