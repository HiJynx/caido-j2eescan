# J2EEScan for Caido

A passive **Java / J2EE vulnerability scanner** plugin for [Caido](https://caido.io),
built as the Caido equivalent of Burp Suite's popular **J2EEScan** extension —
which had no counterpart in the Caido plugin store.

It watches proxied traffic and flags Java-stack weaknesses across the common
application servers and frameworks: **Tomcat, JBoss/WildFly, WebLogic,
WebSphere, GlassFish/Payara, Jetty, Spring Boot, Struts 2, JSF, OGNL/EL**.

All checks are **passive** — the plugin never sends new requests on its own, so
it is safe to leave running during an authorized engagement. Findings also flow
into Caido's native **Findings** view (reporter `J2EEScan`).

## Checks included

| Check | Severity | What it catches |
|---|---|---|
| Java Stack Trace Disclosure | medium | `at java./javax./org.apache…` traces leaking internals |
| Apache Struts Problem Report / Dev Mode | high | Struts 2 devMode output (OGNL RCE surface) |
| OGNL / EL / Template Engine Error | medium | OGNL, Jakarta EL, FreeMarker, Velocity, SpEL exceptions |
| JSF ViewState Exposed | low→high | `javax/jakarta.faces.ViewState`; client-side serialized ViewState raised to high |
| Java Serialized Object | high | `AC ED 00 05` / base64 `rO0AB` in request or response |
| Spring Boot Actuator Exposed | medium→high | `/actuator/*`, `/env`, `/heapdump`, `/jolokia`, `/gateway` |
| JBoss / WildFly Management Interface | high | jmx-console, web-console, JMXInvokerServlet, admin-console |
| Apache Tomcat Manager / Host-Manager | medium | `/manager/*`, `/host-manager/*` reachable |
| Oracle WebLogic Exposed Surface | medium | console login, `_async`, `wls-wsat`, uddiexplorer |
| WEB-INF / META-INF Disclosure | high | protected Java resources served directly |
| JSP Source Code Disclosure | high | raw JSP scriptlets/tags returned as text |
| Insecure JSESSIONID Cookie | low | JSESSIONID without Secure / HttpOnly |
| JSESSIONID in URL | medium | `;jsessionid=` in the path (fixation/leak) |
| Java App Server Banner Disclosure | info | Server / X-Powered-By reveal the stack |
| HTTP TRACE / Dangerous Verbs Allowed | low | `Allow:` advertises TRACE/PUT/DELETE |
| Apache Axis / SOAP Endpoint Exposed | low | services listing, happyaxis.jsp, `?wsdl` |

Findings are de-duplicated per `host + path + check`.

## Usage

- Open the **J2EEScan** tab in the left sidebar to see all issues. New issues
  appear live as you browse through the proxy.
- **Scan History** re-runs every check against all requests already in your
  project history.
- Right-click any request row or response and choose **J2EEScan: scan request**
  to scan a single exchange on demand.
- **Clear** empties the plugin's issue table (Caido's own Findings are kept).

## Build

Requires **Node.js 18+** and **pnpm**. (This repo was scaffolded on a machine
without a Node toolchain, so it has not been compiled there — build it on a host
that has Node/pnpm.)

```bash
pnpm install
pnpm build        # produces plugin_package.zip
```

Then in Caido: **Plugins → Install Package** and select the generated
`dist/plugin_package.zip` (or point Caido at the built `dist/` output).

For live development:

```bash
pnpm watch
```

## Project layout

```
caido.config.ts                 # plugin manifest + Vite/Tailwind build config
packages/backend/src/
  checks.ts                     # the J2EE check definitions (add new checks here)
  scanner.ts                    # builds check context, runs all checks
  db.ts                         # SQLite persistence of issues
  index.ts                      # SDK wiring: passive hook, history scan, findings
packages/frontend/src/
  views/App.vue                 # main tab: toolbar + table
  components/IssuesTable/        # PrimeVue DataTable of issues
```

### Adding a check

Append a `Check` object to `CHECKS` in `packages/backend/src/checks.ts`. Each
check receives a `CheckContext` (method, path, host, status, response body,
request body, and a case-insensitive header lookup) and returns zero or more
matches with evidence. Keep checks passive.

## Scope / notes

This is the **detection** half of J2EEScan — the passive signatures and exposed
endpoints. It deliberately does not send active exploit probes. Only use it
against targets you are authorized to test.

Not an official Caido or PortSwigger project.
