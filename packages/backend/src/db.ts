import type { SDK } from "caido:plugin";
import type { Database } from "sqlite";

import type { Confidence, Severity } from "./checks";

export type IssueRow = {
  id: number;
  requestId: string;
  host: string;
  path: string;
  method: string;
  status: number;
  checkId: string;
  checkLabel: string;
  severity: Severity;
  confidence: Confidence;
  evidence: string;
  createdAt: string;
};

type IssueTableRow = {
  id: number;
  request_id: string;
  host: string;
  path: string;
  method: string;
  status: number;
  check_id: string;
  check_label: string;
  severity: Severity;
  confidence: Confidence;
  evidence: string;
  created_at: string;
};

const toIssueRow = (row: IssueTableRow): IssueRow => ({
  id: row.id,
  requestId: row.request_id,
  host: row.host,
  path: row.path,
  method: row.method,
  status: row.status,
  checkId: row.check_id,
  checkLabel: row.check_label,
  severity: row.severity,
  confidence: row.confidence,
  evidence: row.evidence,
  createdAt: row.created_at,
});

let dbPromise: Promise<Database> | undefined;

const initDb = async (sdk: SDK) => {
  const db = await sdk.meta.db();
  await db.exec(`
    CREATE TABLE IF NOT EXISTS issues (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL,
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      method TEXT NOT NULL,
      status INTEGER NOT NULL,
      check_id TEXT NOT NULL,
      check_label TEXT NOT NULL,
      severity TEXT NOT NULL,
      confidence TEXT NOT NULL,
      evidence TEXT NOT NULL,
      dedupe_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL
    );
  `);
  return db;
};

const getDb = (sdk: SDK) => {
  if (dbPromise === undefined) {
    dbPromise = initDb(sdk);
  }
  return dbPromise;
};

type NewIssue = Omit<IssueRow, "id" | "createdAt"> & { dedupeHash: string };

export const insertIssue = async (
  sdk: SDK,
  issue: NewIssue,
): Promise<IssueRow | undefined> => {
  const db = await getDb(sdk);
  const createdAt = new Date().toISOString();
  const statement = await db.prepare(
    `INSERT OR IGNORE INTO issues
      (request_id, host, path, method, status, check_id, check_label, severity, confidence, evidence, dedupe_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const result = await statement.run(
    issue.requestId,
    issue.host,
    issue.path,
    issue.method,
    issue.status,
    issue.checkId,
    issue.checkLabel,
    issue.severity,
    issue.confidence,
    issue.evidence,
    issue.dedupeHash,
    createdAt,
  );

  if (result.changes === 0) {
    return undefined;
  }

  return {
    id: result.lastInsertRowid,
    requestId: issue.requestId,
    host: issue.host,
    path: issue.path,
    method: issue.method,
    status: issue.status,
    checkId: issue.checkId,
    checkLabel: issue.checkLabel,
    severity: issue.severity,
    confidence: issue.confidence,
    evidence: issue.evidence,
    createdAt,
  };
};

export const listIssues = async (sdk: SDK): Promise<IssueRow[]> => {
  const db = await getDb(sdk);
  const statement = await db.prepare("SELECT * FROM issues ORDER BY id DESC");
  const rows = await statement.all<IssueTableRow>();
  return rows.map(toIssueRow);
};

export const clearIssues = async (sdk: SDK): Promise<void> => {
  const db = await getDb(sdk);
  await db.exec("DELETE FROM issues");
};
