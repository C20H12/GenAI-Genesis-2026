<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import Card from "primevue/card";
import Tag from "primevue/tag";
import MeterGroup from "primevue/metergroup";
import DataTable from "primevue/datatable";
import Column from "primevue/column";
import type { OverviewData, TrafficPoint } from "../data/proxyData";
import { fetchOverviewData, fetchTrafficData } from "../services/proxyApi";

const overviewData = ref<OverviewData | null>(null);
const trafficSeries = ref<TrafficPoint[]>([]);
const isLoading = ref(true);
const loadError = ref("");

const parseMetricNumber = (value: string) => Number(value.replace(/,/g, ""));

// const percentage = (value: number, total: number) => {
//   if (total === 0) return "0.0";
//   return ((value / total) * 100).toFixed(1);
// };

onMounted(async () => {
  try {
    const [overview, traffic] = await Promise.all([fetchOverviewData(), fetchTrafficData()]);
    overviewData.value = overview;
    trafficSeries.value = traffic;
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : "Failed to load overview data.";
  } finally {
    isLoading.value = false;
  }
});

const handledConnections = computed(() => {
  if (!overviewData.value) return 0;
  return parseMetricNumber(overviewData.value.connections.value);
});

const approvedRequests = computed(() => {
  if (!overviewData.value) return 0;
  return parseMetricNumber(overviewData.value.approved.value);
});

const blockedRequests = computed(() => {
  if (!overviewData.value) return 0;
  return parseMetricNumber(overviewData.value.blocked.value);
});

const pendingRequests = computed(() => {
  return Math.max(handledConnections.value - approvedRequests.value - blockedRequests.value, 0);
});

const statCards = computed(() => {
  if (!overviewData.value) return [];

  return [
    {
      label: "Traffic Throughput",
      value: overviewData.value.traffic.value,
      delta: overviewData.value.traffic.delta,
      tone: "success" as const,
    },
    {
      label: "Handled Connections",
      value: overviewData.value.connections.value,
      delta: overviewData.value.connections.delta,
      tone: "info" as const,
    },
    {
      label: "Approved Requests",
      value: overviewData.value.approved.value,
      delta: overviewData.value.approved.delta,
      tone: "contrast" as const,
    },
    {
      label: "Blocked Requests",
      value: overviewData.value.blocked.value,
      delta: overviewData.value.blocked.delta,
      tone: "danger" as const,
    },
  ];
});

const approvalBreakdown = computed(() => {
  const brkdownSum = approvedRequests.value + blockedRequests.value + pendingRequests.value;

  return [
    {
      label: `Approved`,
      value: (approvedRequests.value / brkdownSum) * 100,
      color: "#2d6a4f",
    },
    {
      label: `Blocked`,
      value: (blockedRequests.value / brkdownSum) * 100,
      color: "#9d0208",
    },
    {
      label: `Pending`,
      value: (pendingRequests.value / brkdownSum) * 100,
      color: "#e09f3e",
    },
  ];
});
const trafficRows = computed(() =>
  trafficSeries.value.map((point: TrafficPoint) => ({
    ...point,
    total: point.inboundMbps + point.outboundMbps,
  })),
);

const peakTraffic = computed(() => {
  if (trafficRows.value.length === 0) return 0;
  return Math.max(...trafficRows.value.map((row: { total: number }) => row.total));
});
</script>

<template>
  <section class="page-grid">
    <Card v-if="loadError" class="panel panel-wide">
      <template #content>
        <p>{{ loadError }}</p>
      </template>
    </Card>

    <Card v-else-if="isLoading" class="panel panel-wide">
      <template #content>
        <p>Loading overview data...</p>
      </template>
    </Card>

    <template v-else>
      <div class="stats-grid">
        <Card v-for="card in statCards" :key="card.label" class="stat-card">
          <template #content>
            <p class="stat-label">{{ card.label }}</p>
            <p class="stat-value">{{ card.value }}</p>
            <Tag :value="card.delta" :severity="card.tone" rounded />
          </template>
        </Card>
      </div>

      <Card class="panel panel-wide">
        <template #title>Traffic Status (24h)</template>
        <template #subtitle>Inbound and outbound proxy throughput by time segment.</template>
        <template #content>
          <DataTable :value="trafficRows" size="small" stripedRows>
            <Column field="time" header="Time" />
            <Column field="inboundMbps" header="Inbound (MB)" />
            <Column field="outboundMbps" header="Outbound (MB)" />
            <Column field="total" header="Total (MB)" />
          </DataTable>
          <p class="panel-meta">Peak combined traffic: {{ peakTraffic }} MB</p>
        </template>
      </Card>

      <Card class="panel">
        <template #title>Approval Breakdown</template>
        <template #subtitle>Approved, blocked, and pending percentages from overview API data.</template>
        <template #content>
          <MeterGroup :value="approvalBreakdown" />
        </template>
      </Card>
    </template>
  </section>
</template>
