<script setup lang="ts">
import type { IssueRow } from "backend";
import Button from "primevue/button";
import Card from "primevue/card";
import Toast from "primevue/toast";
import { useToast } from "primevue/usetoast";
import { onMounted, onUnmounted, ref } from "vue";

import { IssuesTable } from "@/components/IssuesTable";
import { useSDK } from "@/plugins/sdk";

const sdk = useSDK();
const toast = useToast();

const issues = ref<IssueRow[]>([]);
const isRescanning = ref(false);

const loadIssues = async () => {
  const result = await sdk.backend.getIssues();
  if (result.kind === "Error") {
    toast.add({
      severity: "error",
      summary: "Failed to load issues",
      detail: result.error,
      life: 4000,
    });
    return;
  }
  issues.value = result.value;
};

const onRescan = async () => {
  isRescanning.value = true;
  const result = await sdk.backend.rescanHistory();
  isRescanning.value = false;

  if (result.kind === "Error") {
    toast.add({
      severity: "error",
      summary: "Scan failed",
      detail: result.error,
      life: 4000,
    });
    return;
  }

  toast.add({
    severity: "success",
    summary: "History scan complete",
    detail: `${result.value} new issue(s) found`,
    life: 4000,
  });
  await loadIssues();
};

const onClear = async () => {
  if (!window.confirm("Clear all detected J2EE issues? This cannot be undone.")) {
    return;
  }

  const result = await sdk.backend.clearAllIssues();
  if (result.kind === "Error") {
    toast.add({
      severity: "error",
      summary: "Clear failed",
      detail: result.error,
      life: 4000,
    });
    return;
  }

  issues.value = [];
};

const listener = sdk.backend.onEvent("issue-found", (row) => {
  issues.value = [row, ...issues.value];
});

onMounted(loadIssues);
onUnmounted(() => listener.stop());
</script>

<template>
  <div class="h-full p-4">
    <Toast />
    <Card
      class="h-full"
      :pt="{
        body: { class: 'h-full p-0' },
        content: { class: 'h-full flex flex-col gap-4 p-4' },
      }"
    >
      <template #content>
        <div class="flex items-center justify-between">
          <div class="flex flex-col">
            <h1 class="text-lg font-semibold">J2EEScan</h1>
            <span class="text-xs text-surface-400"
              >Passive Java / J2EE vulnerability checks</span
            >
          </div>
          <div class="flex gap-2">
            <Button
              label="Scan History"
              icon="fas fa-magnifying-glass"
              :loading="isRescanning"
              @click="onRescan"
            />
            <Button
              label="Clear"
              icon="fas fa-trash-can"
              severity="danger"
              outlined
              @click="onClear"
            />
          </div>
        </div>

        <IssuesTable class="flex-1 min-h-0" :rows="issues" />
      </template>
    </Card>
  </div>
</template>
