/**
 * Passive J2EE / Java-stack checks.
 *
 * Each check inspects a single request/response pair that has already passed
 * through the proxy. All checks are PASSIVE — they never send new traffic — so
 * they are safe to run automatically on every response. This mirrors the
 * detection half of Burp's J2EEScan, covering Java application servers
 * (Tomcat, JBoss/WildFly, WebLogic, WebSphere, GlassFish, Jetty) and common
 * Java frameworks (Spring Boot, Struts, JSF, OGNL/EL), plus Java-specific
 * information disclosure (stack traces, WEB-INF, JSP source, serialized
 * objects, insecure JSESSIONID handling).
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "certain" | "firm" | "tentative";

export type CheckContext = {
  method: string;
  /** Path including matrix params and query string, lowercased copy in `pathLower`. */
  path: string;
  pathLower: string;
  host: string;
  status: number;
  /** Response body as text, already length-capped by the scanner. */
  bodyText: string;
  /** Lowercased request body text, already length-capped (may be ""). */
  requestBodyText: string;
  /** Case-insensitive response header lookup; returns [] when absent. */
  header: (name: string) => string[];
};

export type CheckMatch = {
  evidence: string;
  /** Lets a check raise/lower severity for a specific finding. */
  severityOverride?: Severity;
};

export type Check = {
  id: string;
  label: string;
  severity: Severity;
  confidence: Confidence;
  description: string;
  remediation: string;
  run: (ctx: CheckContext) => CheckMatch[];
};

const snippet = (text: string, index: number, radius = 120): string => {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + radius);
  return text.slice(start, end).replace(/\s+/g, " ").trim();
};

const firstMatch = (text: string, regex: RegExp): CheckMatch[] => {
  const match = regex.exec(text);
  if (match === null || match.index === undefined) return [];
  return [{ evidence: snippet(text, match.index) }];
};

const anyHeader = (
  ctx: CheckContext,
  name: string,
  regex: RegExp,
): CheckMatch[] => {
  for (const value of ctx.header(name)) {
    if (regex.test(value)) {
      return [{ evidence: `${name}: ${value}` }];
    }
  }
  return [];
};

export const CHECKS: Check[] = [
  {
    id: "java-stacktrace",
    label: "Java Stack Trace Disclosure",
    severity: "medium",
    confidence: "firm",
    description:
      "The response leaks a Java stack trace, exposing internal class names, framework versions and file paths that aid further attacks.",
    remediation:
      "Disable verbose error pages in production. Configure a generic <error-page> in web.xml and set the framework to production/non-debug mode.",
    run: (ctx) =>
      firstMatch(
        ctx.bodyText,
        /(?:(?:at|Caused by:)\s+(?:java|javax|jakarta|org\.apache|org\.springframework|com\.sun|weblogic|jboss|org\.jboss|org\.eclipse\.jetty)\.[\w.$]+)(?:\([\w.]+\.java:\d+\))?/,
      ),
  },
  {
    id: "struts-dev-mode",
    label: "Apache Struts Problem Report / Dev Mode",
    severity: "high",
    confidence: "firm",
    description:
      "The application exposes Struts 2 debug output (devMode). This reveals internal state and is frequently associated with OGNL injection RCE (e.g. S2-* advisories).",
    remediation:
      "Set struts.devMode=false, upgrade Struts to a patched release, and return generic error pages.",
    run: (ctx) =>
      firstMatch(
        ctx.bodyText,
        /Struts Problem Report|struts\.devMode|There is no Action mapped for|tag 'debug'/i,
      ),
  },
  {
    id: "ognl-el-error",
    label: "OGNL / EL / Template Engine Error",
    severity: "medium",
    confidence: "tentative",
    description:
      "An OGNL, Java EL or template-engine exception surfaced in the response. These often indicate server-side expression/template injection sinks.",
    remediation:
      "Never evaluate user input as an expression or template. Validate input and patch the affected library.",
    run: (ctx) =>
      firstMatch(
        ctx.bodyText,
        /ognl\.(?:Ognl|MethodFailed|NoSuchProperty|ExpressionSyntax)Exception|javax\.el\.ELException|jakarta\.el\.ELException|freemarker\.core\.|org\.apache\.velocity|SpelEvaluationException/i,
      ),
  },
  {
    id: "jsf-viewstate",
    label: "JSF ViewState Exposed",
    severity: "low",
    confidence: "firm",
    description:
      "A JavaServer Faces ViewState field was found. A client-side (serialized) ViewState without encryption/MAC can enable tampering or Java deserialization attacks.",
    remediation:
      "Keep ViewState server-side (STATE_SAVING_METHOD=server) or ensure it is encrypted and MAC-protected with a strong secret.",
    run: (ctx) => {
      const re =
        /name="(?:javax|jakarta)\.faces\.ViewState"[^>]*value="([^"]*)"/i;
      const m = re.exec(ctx.bodyText);
      if (m === null) return [];
      const value = m[1] ?? "";
      // rO0AB = base64 of Java serialized header (ac ed 00 05) => client-side serialized ViewState.
      const serialized = value.startsWith("rO0AB") || value.startsWith("H4sI");
      return [
        {
          evidence: `javax.faces.ViewState = ${value.slice(0, 48)}${value.length > 48 ? "…" : ""}`,
          severityOverride: serialized ? "high" : undefined,
        },
      ];
    },
  },
  {
    id: "java-deserialization",
    label: "Java Serialized Object",
    severity: "high",
    confidence: "firm",
    description:
      "A Java serialized object stream was detected in the request or response (magic bytes AC ED 00 05 / base64 'rO0AB'). Deserialization of untrusted data can lead to remote code execution.",
    remediation:
      "Avoid native Java serialization for untrusted data. Use look-ahead deserialization filters (JEP 290) or a safe format such as JSON.",
    run: (ctx) => {
      const body = firstMatch(ctx.bodyText, /rO0AB[A-Za-z0-9+/=]{8,}/);
      if (body.length > 0) return body;
      return firstMatch(ctx.requestBodyText, /rO0AB[A-Za-z0-9+/=]{8,}/);
    },
  },
  {
    id: "spring-boot-actuator",
    label: "Spring Boot Actuator Exposed",
    severity: "medium",
    confidence: "firm",
    description:
      "A Spring Boot Actuator endpoint responded. Endpoints such as /env, /heapdump, /jolokia and /gateway can leak secrets or enable RCE.",
    remediation:
      "Restrict actuator exposure (management.endpoints.web.exposure.include), require authentication, and never expose /heapdump or /env publicly.",
    run: (ctx) => {
      if (ctx.status < 200 || ctx.status >= 400) return [];
      const re =
        /(?:^|\/)(?:actuator(?:\/(?:env|health|beans|heapdump|mappings|configprops|threaddump|loggers|metrics|jolokia|gateway))?|env|beans|heapdump|trace|mappings|configprops)(?:$|\?|\/)/;
      if (!re.test(ctx.pathLower)) return [];
      // Confirm it looks like an actuator response, not just a matching path.
      const looksActuator =
        /heapdump/.test(ctx.pathLower) ||
        /"_links"|"activeProfiles"|"propertySources"|"contexts"|"status"\s*:\s*"UP"/.test(
          ctx.bodyText,
        );
      if (!looksActuator) return [];
      const sensitive = /(heapdump|\/env|\/jolokia|\/gateway)/.test(
        ctx.pathLower,
      );
      return [
        {
          evidence: `${ctx.status} ${ctx.path}`,
          severityOverride: sensitive ? "high" : undefined,
        },
      ];
    },
  },
  {
    id: "jboss-consoles",
    label: "JBoss / WildFly Management Interface",
    severity: "high",
    confidence: "firm",
    description:
      "A JBoss/WildFly management interface (jmx-console, web-console, JMXInvokerServlet, admin-console) is reachable. These are a classic deployment-based RCE vector.",
    remediation:
      "Remove or firewall management consoles, require authentication, and bind the management interface to localhost only.",
    run: (ctx) => {
      if (ctx.status >= 400 && ctx.status !== 401 && ctx.status !== 403)
        return [];
      const re =
        /\/(?:jmx-console|web-console|admin-console|invoker\/(?:jmxinvokerservlet|ejbinvokerservlet)|management)(?:$|\/|\?)/;
      if (!re.test(ctx.pathLower)) return [];
      return [{ evidence: `${ctx.status} ${ctx.path}` }];
    },
  },
  {
    id: "tomcat-manager",
    label: "Apache Tomcat Manager / Host-Manager",
    severity: "medium",
    confidence: "firm",
    description:
      "A Tomcat manager application responded. If weakly authenticated it allows WAR deployment and remote code execution.",
    remediation:
      "Restrict /manager and /host-manager by IP, use strong credentials, or undeploy the manager apps in production.",
    run: (ctx) => {
      if (ctx.status >= 400 && ctx.status !== 401 && ctx.status !== 403)
        return [];
      const re = /\/(?:manager|host-manager)\/(?:html|status|text)(?:$|\/|\?)/;
      if (!re.test(ctx.pathLower)) return [];
      return [{ evidence: `${ctx.status} ${ctx.path}` }];
    },
  },
  {
    id: "weblogic-async",
    label: "Oracle WebLogic Exposed Surface",
    severity: "medium",
    confidence: "tentative",
    description:
      "A WebLogic console or async/UDDI endpoint was detected. Several (CVE-2017-10271, CVE-2019-2725, CVE-2020-14882) lead to unauthenticated RCE.",
    remediation:
      "Patch WebLogic, remove the wls-wsat/async components if unused, and restrict access to /console.",
    run: (ctx) => {
      const re =
        /\/(?:console\/login\/loginform\.jsp|_async\/asyncresponseservice|wls-wsat\/|uddiexplorer\/)/;
      if (!re.test(ctx.pathLower)) return [];
      return [{ evidence: `${ctx.status} ${ctx.path}` }];
    },
  },
  {
    id: "webinf-disclosure",
    label: "WEB-INF / META-INF Disclosure",
    severity: "high",
    confidence: "firm",
    description:
      "A protected Java web resource under WEB-INF or META-INF was served. web.xml and compiled classes expose configuration, credentials and attack surface.",
    remediation:
      "Ensure the container never serves WEB-INF/META-INF content; audit reverse-proxy path normalization and traversal handling.",
    run: (ctx) => {
      if (ctx.status < 200 || ctx.status >= 300) return [];
      if (!/\/(?:web-inf|meta-inf)\//.test(ctx.pathLower)) return [];
      return [{ evidence: `${ctx.status} ${ctx.path}` }];
    },
  },
  {
    id: "jsp-source-disclosure",
    label: "JSP Source Code Disclosure",
    severity: "high",
    confidence: "firm",
    description:
      "Raw JSP source (scriptlets or JSP tags) was returned instead of being executed, leaking server-side code and possibly secrets.",
    remediation:
      "Fix the misconfiguration (e.g. mappings, trailing characters, case tricks) that causes the container to serve .jsp as text.",
    run: (ctx) => {
      if (!/\.jspx?(?:$|\?)/.test(ctx.pathLower)) return [];
      return firstMatch(ctx.bodyText, /<%@\s*page|<%[=!]?\s|<jsp:[a-z]/i);
    },
  },
  {
    id: "jsessionid-insecure-cookie",
    label: "Insecure JSESSIONID Cookie",
    severity: "low",
    confidence: "certain",
    description:
      "A JSESSIONID cookie was set without the Secure and/or HttpOnly flags, exposing the Java session to interception or theft via XSS.",
    remediation:
      "Set <cookie-config><secure>true</secure><http-only>true</http-only></cookie-config> in web.xml (Servlet 3.0+).",
    run: (ctx) => {
      const matches: CheckMatch[] = [];
      for (const cookie of ctx.header("set-cookie")) {
        if (!/jsessionid=/i.test(cookie)) continue;
        const missing: string[] = [];
        if (!/;\s*secure/i.test(cookie)) missing.push("Secure");
        if (!/;\s*httponly/i.test(cookie)) missing.push("HttpOnly");
        if (missing.length === 0) continue;
        matches.push({
          evidence: `JSESSIONID missing ${missing.join(" + ")} — ${cookie.split(";")[0]}`,
        });
      }
      return matches;
    },
  },
  {
    id: "jsessionid-in-url",
    label: "JSESSIONID in URL",
    severity: "medium",
    confidence: "certain",
    description:
      "The session identifier appears in the URL (;jsessionid=). It can leak via Referer headers, logs and browser history, enabling session fixation/hijacking.",
    remediation:
      "Disable URL-based session tracking (tracking-mode COOKIE in web.xml) and reject jsessionid path parameters at the edge.",
    run: (ctx) => {
      const m = /;jsessionid=([^?&/]+)/i.exec(ctx.path);
      if (m === null) return [];
      return [{ evidence: `;jsessionid=${(m[1] ?? "").slice(0, 32)}` }];
    },
  },
  {
    id: "java-server-banner",
    label: "Java App Server Banner Disclosure",
    severity: "info",
    confidence: "certain",
    description:
      "Response headers reveal the Java application server / servlet engine and sometimes its exact version, narrowing the attacker's exploit search.",
    remediation:
      "Suppress Server and X-Powered-By headers (e.g. server.tomcat secure settings, server header off) in production.",
    run: (ctx) => {
      const re =
        /tomcat|coyote|jboss|wildfly|weblogic|websphere|glassfish|payara|jetty|resin|servlet|jsp|jsf|jakarta|spring/i;
      return [
        ...anyHeader(ctx, "server", re),
        ...anyHeader(ctx, "x-powered-by", re),
      ];
    },
  },
  {
    id: "trace-method-enabled",
    label: "HTTP TRACE / Dangerous Verbs Allowed",
    severity: "low",
    confidence: "firm",
    description:
      "The Allow header advertises TRACE/PUT/DELETE. TRACE can enable Cross-Site Tracing; PUT/DELETE may allow unauthorized file operations on Java containers.",
    remediation:
      "Disable the TRACE method and restrict write verbs via security constraints in web.xml or at the reverse proxy.",
    run: (ctx) => anyHeader(ctx, "allow", /\b(?:TRACE|PUT|DELETE)\b/),
  },
  {
    id: "axis-webservice",
    label: "Apache Axis / SOAP Endpoint Exposed",
    severity: "low",
    confidence: "tentative",
    description:
      "An Axis/Axis2 service listing or WSDL was exposed. Admin endpoints and happyaxis.jsp can leak configuration or allow service upload.",
    remediation:
      "Disable the services listing and admin endpoints, and restrict access to WSDL in production.",
    run: (ctx) => {
      if (ctx.status >= 400) return [];
      if (
        !/\/(?:axis2?\/services|services\/listservices|happyaxis\.jsp)|[?&]wsdl(?:$|&)/.test(
          ctx.pathLower,
        )
      )
        return [];
      return [{ evidence: `${ctx.status} ${ctx.path}` }];
    },
  },
];
