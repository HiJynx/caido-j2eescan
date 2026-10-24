import { createHash } from "crypto";

import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";
import type { Cursor, Request, RequestsConnectionItem } from "caido:utils";

import { clearIssues, insertIssue, listIssues, type IssueRow } from "./db";
import { scanExchange, type IssueMatch } from "./scanner";

export type { IssueRow } from "./db";

export type Result<T> =
  | { kind: "Error"; error: string }
  | { kind: "Ok"; value: T };

const REPORTER = "J2EEScan";

const buildDedupeHash = (host: string, path: string, checkId: string) =>
  createHash("sha256").update(`${host}|${path}|${checkId}`).digest("hex");

const persistMatches = async (
  sdk: SDK,
  request: Request,
  status: number,
  matches: IssueMatch[],
): Promise<IssueRow[]> => {
  const host = request.getHost();
  const path = request.getPath();
  const method = request.getMethod();
  const rows: IssueRow[] = [];

  for (const match of matches) {
    const dedupeHash = buildDedupeHash(host, path, match.checkId);

    const row = await insertIssue(sdk, {
      requestId: request.getId(),
      host,
      path,
      method,
      status,
      checkId: match.checkId,
      checkLabel: match.checkLabel,
      severity: match.severity,
      confidence: match.confidence,
      evidence: match.evidence,
      dedupeHash,
    });

    if (row === undefined) continue;

    try {
      await sdk.findings.create({
        title: `J2EE: ${match.checkLabel}`,
        description: `${match.description}\n\n[${match.severity.toUpperCase()} / ${match.confidence}] ${method} ${path}\n\nEvidence:\n${match.evidence}\n\nRemediation:\n${match.remediation}`,
        reporter: REPORTER,
        request,
        dedupeKey: `${REPORTER}:${dedupeHash}`,
      });
    } catch (error) {
      sdk.console.error(
        `j2eescan: failed to create finding for ${match.checkId} on ${method} ${path} - ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    rows.push(row);
  }

  return rows;
};

const toResult = async <T>(run: () => Promise<T>): Promise<Result<T>> => {
  try {
    const value = await run();
    return { kind: "Ok", value };
  } catch (error) {
    return {
      kind: "Error",
      error: error instanceof Error ? error.message : String(error),
    };
  }
};

const getIssues = (sdk: SDK): Promise<Result<IssueRow[]>> =>
  toResult(() => listIssues(sdk));

const clearAllIssues = (sdk: SDK): Promise<Result<undefined>> =>
  toResult(async () => {
    await clearIssues(sdk);
    return undefined;
  });

const PAGE_SIZE = 500;

const fetchHistoryPage = (sdk: SDK, cursor: Cursor | undefined) => {
  const query = sdk.requests.query().first(PAGE_SIZE);
  return (cursor === undefined ? query : query.after(cursor)).execute();
};

const scanHistoryPage = async (
  sdk: SDK,
  items: RequestsConnectionItem[],
): Promise<number> => {
  let found = 0;
  for (const item of items) {
    if (item.response === undefined) continue;
    const matches = scanExchange(item.request, item.response);
    if (matches.length === 0) continue;
    const rows = await persistMatches(
      sdk,
      item.request,
      item.response.getCode(),
      matches,
    );
    found += rows.length;
  }
  return found;
};

const scanAllHistory = async (sdk: SDK): Promise<number> => {
  let found = 0;
  let cursor: Cursor | undefined;
  for (;;) {
    const page = await fetchHistoryPage(sdk, cursor);
    found += await scanHistoryPage(sdk, page.items);
    if (!page.pageInfo.hasNextPage) break;
    cursor = page.pageInfo.endCursor;
  }
  return found;
};

const rescanHistory = (sdk: SDK): Promise<Result<number>> =>
  toResult(() => scanAllHistory(sdk));

export type RescanRequestResult = {
  matched: number;
  added: number;
};

const rescanRequest = (
  sdk: SDK,
  id: string,
): Promise<Result<RescanRequestResult>> =>
  toResult(async () => {
    const item = await sdk.requests.get(id);
    if (item === undefined) {
      throw new Error("Request not found");
    }
    if (item.response === undefined) {
      throw new Error("Request has no response");
    }

    const matches = scanExchange(item.request, item.response);
    if (matches.length === 0) return { matched: 0, added: 0 };

    const rows = await persistMatches(
      sdk,
      item.request,
      item.response.getCode(),
      matches,
    );
    return { matched: matches.length, added: rows.length };
  });

export type API = DefineAPI<{
  getIssues: typeof getIssues;
  clearAllIssues: typeof clearAllIssues;
  rescanHistory: typeof rescanHistory;
  rescanRequest: typeof rescanRequest;
}>;

export type BackendEvents = DefineEvents<{
  "issue-found": (row: IssueRow) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.events.onInterceptResponse(async (eventSdk, request, response) => {
    try {
      const matches = scanExchange(request, response);
      if (matches.length === 0) return;

      const rows = await persistMatches(
        eventSdk,
        request,
        response.getCode(),
        matches,
      );
      for (const row of rows) {
        eventSdk.api.send("issue-found", row);
      }
    } catch (error) {
      eventSdk.console.error(
        `j2eescan: failed to scan response - ${String(error)}`,
      );
    }
  });

  sdk.api.register("getIssues", getIssues);
  sdk.api.register("clearAllIssues", clearAllIssues);
  sdk.api.register("rescanHistory", rescanHistory);
  sdk.api.register("rescanRequest", rescanRequest);
}
