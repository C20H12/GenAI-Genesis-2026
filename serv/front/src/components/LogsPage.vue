<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import Card from "primevue/card";
import DataTable from "primevue/datatable";
import Column from "primevue/column";
import Tag from "primevue/tag";
import InputText from "primevue/inputtext";
import Textarea from "primevue/textarea";
import Dialog from "primevue/dialog";
import type { ProxyLog } from "../data/proxyData";
import { fetchLogsData } from "../services/proxyApi";

type LevelFilter = "OK" | "BLOCKED";

const query = ref("");
const proxyLogs = ref<ProxyLog[]>([]);
const selectedLogId = ref<number | null>(null);
const isLoading = ref(true);
const loadError = ref("");
const isTextDialogOpen = ref(false);
const textDialogTitle = ref("");
const textDialogContent = ref("");

onMounted(async () => {
  try {
    proxyLogs.value = await fetchLogsData();
    selectedLogId.value = proxyLogs.value[0]?.id ?? null;
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : "Failed to load logs.";
  } finally {
    isLoading.value = false;
  }
});

const filteredLogs = computed(() => {
  const term = query.value.trim().toLowerCase();

  return proxyLogs.value.filter(log => {
    const textMatch =
      !term || [log.timestamp, log.source, log.message, log.requestId].join(" ").toLowerCase().includes(term);
    return textMatch;
  });
});

const selectedLog = computed(() => {
  const found = proxyLogs.value.find(log => log.id === selectedLogId.value);
  return found ?? filteredLogs.value[0] ?? null;
});

const rawLogText = computed(() => {
  if (!selectedLog.value) return "";
  const { timestamp, level: severity, source, message, requestId } = selectedLog.value;
  return `[${timestamp}] ${severity} ${source} ${requestId} ${message}`;
});

const levelSeverity = (value: LevelFilter) => {
  if (value === "BLOCKED") return "warn";
  return "info";
};

const formatTime = (t: string) => {
  return new Date(t).toUTCString();
};

const truncateText = (value: string | undefined, max = 52) => {
  if (!value) return "-";
  if (value.length <= max) return value;
  return `${value.slice(0, max)}...`;
};

const showFullText = (title: string, value: string | undefined) => {
  textDialogTitle.value = title;
  textDialogContent.value = value && value.trim() ? value : "-";
  isTextDialogOpen.value = true;
};
</script>

<template>
  <Card class="panel">
    <template #title>Logs</template>
    <template #subtitle>Review proxy runtime events and investigate request traces.</template>
    <template #content>
      <p v-if="loadError">{{ loadError }}</p>
      <p v-else-if="isLoading">Loading logs...</p>
      <template v-else>
        <div class="table-toolbar table-toolbar-split">
          <InputText v-model="query" placeholder="Search logs..." />
        </div>

        <DataTable
          :value="filteredLogs"
          dataKey="id"
          paginator
          :rows="7"
          stripedRows
          @row-click="selectedLogId = $event.data.id"
        >
          <Column field="timestamp" header="Timestamp">
            <template #body="slotProps">
              {{ formatTime(slotProps.data.timestamp) }}
            </template>
          </Column>
          <Column header="Source">
            <template #body="slotProps">
              <button class="cell-link" @click="showFullText('Source', slotProps.data.source)">
                {{ truncateText(slotProps.data.source, 40) }}
              </button>
            </template>
          </Column>
          <Column header="Destination">
            <template #body="slotProps">
              <button class="cell-link" @click="showFullText('Destination', slotProps.data.destination)">
                {{ truncateText(slotProps.data.destination, 40) }}
              </button>
            </template>
          </Column>
          <Column header="Message">
            <template #body="slotProps">
              <button class="cell-link" @click="showFullText('Message', slotProps.data.message)">
                {{ truncateText(slotProps.data.message, 100) }}
              </button>
            </template>
          </Column>
          <Column header="Level">
            <template #body="slotProps">
              <Tag :value="slotProps.data.level" :severity="levelSeverity(slotProps.data.level)" />
            </template>
          </Column>
        </DataTable>

        <Dialog v-model:visible="isTextDialogOpen" :header="textDialogTitle" modal :style="{ width: 'min(36rem, 95vw)' }">
          <p class="dialog-text">{{ textDialogContent }}</p>
        </Dialog>

        <div class="raw-log">
          <h3>Raw Log Line</h3>
          <Textarea :modelValue="rawLogText" readonly rows="5" fluid />
        </div>
      </template>
    </template>
  </Card>
</template>

