<script setup lang="ts">
import type { IssueRow } from "backend";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Tag from "primevue/tag";
import { computed } from "vue";

const props = defineProps<{
  rows: IssueRow[];
}>();

const severityRank: Record<IssueRow["severity"], number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const displayRows = computed(() =>
  props.rows.map((row) => ({
    ...row,
    severityRank: severityRank[row.severity],
  })),
);

const severityTagMap = {
  critical: "danger",
  high: "warn",
  medium: "info",
  low: "secondary",
  info: "contrast",
} as const;

const severityTag = (severity: IssueRow["severity"]) =>
  severityTagMap[severity];
</script>

<template>
  <DataTable
    :value="displayRows"
    striped-rows
    data-key="id"
    class="h-full"
    scrollable
    scroll-height="flex"
    resizable-columns
    column-resize-mode="fit"
    :sort-field="'severityRank'"
    :sort-order="-1"
  >
    <template #empty>
      <div
        class="flex flex-col items-center justify-center gap-2 py-8 text-surface-400"
      >
        <i class="fas fa-mug-hot text-2xl" />
        <span>No J2EE issues found yet</span>
      </div>
    </template>

    <Column field="severityRank" header="Severity" sortable style="width: 8rem">
      <template #body="{ data }">
        <Tag :value="data.severity" :severity="severityTag(data.severity)" />
      </template>
    </Column>

    <Column
      field="checkLabel"
      header="Issue"
      sortable
      style="width: 18rem; max-width: 18rem"
    >
      <template #body="{ data }">
        <span :title="data.description" class="block truncate">{{
          data.checkLabel
        }}</span>
      </template>
    </Column>

    <Column field="confidence" header="Confidence" sortable style="width: 8rem" />

    <Column field="host" header="Host" sortable style="width: 12rem">
      <template #body="{ data }">
        <span :title="data.host" class="block truncate">{{ data.host }}</span>
      </template>
    </Column>

    <Column header="Request" style="width: 20rem; max-width: 20rem">
      <template #body="{ data }">
        <span :title="`${data.method} ${data.path}`" class="block truncate font-mono text-xs"
          >{{ data.method }} {{ data.path }}</span
        >
      </template>
    </Column>

    <Column field="status" header="Status" sortable style="width: 6rem" />

    <Column header="Evidence" style="width: 24rem; max-width: 24rem">
      <template #body="{ data }">
        <span :title="data.evidence" class="block truncate font-mono text-xs">{{
          data.evidence
        }}</span>
      </template>
    </Column>

    <Column
      field="createdAt"
      header="Detected At"
      sortable
      style="width: 11rem"
    >
      <template #body="{ data }">
        {{ new Date(data.createdAt).toLocaleString() }}
      </template>
    </Column>
  </DataTable>
</template>
