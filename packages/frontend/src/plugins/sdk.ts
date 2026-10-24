import { inject, type InjectionKey, type Plugin } from "vue";

import { type FrontendSDK } from "@/types";

const KEY: InjectionKey<FrontendSDK> = Symbol("FrontendSDK");

// Provides the FrontendSDK to the Vue app. Access it from a component with `useSDK`.
export const SDKPlugin: Plugin = (app, sdk: FrontendSDK) => {
  app.provide(KEY, sdk);
};

export const useSDK = () => {
  return inject(KEY) as FrontendSDK;
};
