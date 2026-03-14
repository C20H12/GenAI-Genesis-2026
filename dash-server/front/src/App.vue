<script setup lang="ts">
import { computed, ref } from 'vue'
import Card from 'primevue/card'
import SelectButton from 'primevue/selectbutton'
import OverviewPage from './components/OverviewPage.vue'
import BlocklistPage from './components/BlocklistPage.vue'
import LogsPage from './components/LogsPage.vue'

type DashboardPage = 'overview' | 'blocklist' | 'logs'

const activePage = ref<DashboardPage>('overview')

const pageOptions = [
  { label: 'Overview', value: 'overview' },
  { label: 'Blocklist', value: 'blocklist' },
  { label: 'Logs', value: 'logs' },
]

const currentView = computed(() => {
  if (activePage.value === 'blocklist') return BlocklistPage
  if (activePage.value === 'logs') return LogsPage
  return OverviewPage
})
</script>

<template>
  <main class="dashboard-root">
    <Card class="top-shell">
      <template #content>
        <div class="top-shell-content">
          <div>
            <h1>Network Security Dashboard</h1>
          </div>
          <SelectButton
            v-model="activePage"
            :options="pageOptions"
            optionLabel="label"
            optionValue="value"
            :allowEmpty="false"
            aria-label="Dashboard page switcher"
            size="large"
            fluid
          />
        </div>
      </template>
    </Card>

    <section class="page-content">
      <component :is="currentView" />
    </section>
  </main>
</template>
