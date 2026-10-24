import type { Request, Response } from "caido:utils";

import { CHECKS, type Check, type CheckContext, type Severity } from "./checks";

const MAX_BODY_LENGTH = 2_000_000;

export type IssueMatch = {
  checkId: string;
  checkLabel: string;
  severity: Severity;
  confidence: Check["confidence"];
  evidence: string;
  description: string;
  remediation: string;
};

const buildContext = (request: Request, response: Response): CheckContext => {
  const path = request.getPath();
  const bodyText = response.getBody()?.toText().slice(0, MAX_BODY_LENGTH) ?? "";
  const requestBodyText =
    request.getBody()?.toText().slice(0, MAX_BODY_LENGTH).toLowerCase() ?? "";

  return {
    method: request.getMethod(),
    path,
    pathLower: path.toLowerCase(),
    host: request.getHost(),
    status: response.getCode(),
    bodyText,
    requestBodyText,
    header: (name: string) => response.getHeader(name) ?? [],
  };
};

export const scanExchange = (
  request: Request,
  response: Response,
): IssueMatch[] => {
  const ctx = buildContext(request, response);
  const issues: IssueMatch[] = [];

  for (const check of CHECKS) {
    let matches;
    try {
      matches = check.run(ctx);
    } catch {
      // A single misbehaving check must never abort the whole scan.
      continue;
    }

    for (const match of matches) {
      issues.push({
        checkId: check.id,
        checkLabel: check.label,
        severity: match.severityOverride ?? check.severity,
        confidence: check.confidence,
        evidence: match.evidence.slice(0, 500),
        description: check.description,
        remediation: check.remediation,
      });
    }
  }

  return issues;
};
