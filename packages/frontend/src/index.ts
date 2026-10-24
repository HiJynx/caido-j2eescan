import { Classic } from "@caido/primevue";
import PrimeVue from "primevue/config";
import ToastService from "primevue/toastservice";
import { createApp } from "vue";

import { SDKPlugin } from "./plugins/sdk";
import "./styles/index.css";
import type { FrontendSDK } from "./types";
import App from "./views/App.vue";

export const init = (sdk: FrontendSDK) => {
  const app = createApp(App);

  app.use(PrimeVue, {
    unstyled: true,
    pt: Classic,
  });
  app.use(ToastService);
  app.use(SDKPlugin, sdk);

  const root = document.createElement("div");
  Object.assign(root.style, {
    height: "100%",
    width: "100%",
  });
  root.id = "plugin--j2eescan";

  app.mount(root);

  sdk.navigation.addPage("/j2eescan", {
    body: root,
  });

  sdk.sidebar.registerItem("J2EEScan", "/j2eescan", {
    icon: "fas fa-mug-hot",
  });

  sdk.commands.register("j2eescan.rescan-request", {
    name: "J2EEScan: scan request",
    group: "J2EEScan",
    when: (context) =>
      context.type === "RequestRowContext" ||
      context.type === "ResponseContext",
    run: async (context) => {
      const ids =
        context.type === "RequestRowContext"
          ? context.requests.map((request) => request.id)
          : context.type === "ResponseContext"
            ? [context.request.id]
            : [];

      if (ids.length === 0) return;

      let matched = 0;
      let added = 0;
      for (const id of ids) {
        const result = await sdk.backend.rescanRequest(id);
        if (result.kind === "Ok") {
          matched += result.value.matched;
          added += result.value.added;
        }
      }

      const message =
        added > 0
          ? `${added} new J2EE issue(s) found`
          : matched > 0
            ? "Already recorded — no new issues"
            : "No J2EE issues found";

      sdk.window.showToast(message, {
        variant: added > 0 ? "success" : "info",
      });
    },
  });

  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: "j2eescan.rescan-request",
    leadingIcon: "fas fa-mug-hot",
  });

  sdk.menu.registerItem({
    type: "Response",
    commandId: "j2eescan.rescan-request",
    leadingIcon: "fas fa-mug-hot",
  });
};
