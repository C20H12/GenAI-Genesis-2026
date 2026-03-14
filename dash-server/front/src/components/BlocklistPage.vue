<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Card from 'primevue/card'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import type { BlockedEntry } from '../data/proxyData'
import { deleteBlockedEntry, fetchBlockedData, updateBlockedEntry } from '../services/proxyApi'

const search = ref('')
const blockedEntries = ref<BlockedEntry[]>([])
const isLoading = ref(true)
const loadError = ref('')
const rowActionError = ref('')
const isManageDialogOpen = ref(false)
const activeEntryId = ref('')
const isSaving = ref(false)
const isDeleting = ref(false)
const editForm = ref({
  destination: '',
  reason: '',
})

onMounted(async () => {
  try {
    blockedEntries.value = await fetchBlockedData()
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'Failed to load blocked entries.'
  } finally {
    isLoading.value = false
  }
})

const filteredEntries = computed(() => {
  const query = search.value.trim().toLowerCase()
  if (!query) return blockedEntries.value

  return blockedEntries.value.filter((entry) => {
    return [entry.id, entry.source, entry.destination, entry.reason, entry.category, entry.status]
      .join(' ')
      .toLowerCase()
      .includes(query)
  })
})

const openManageDialog = (entry: BlockedEntry) => {
  rowActionError.value = ''
  activeEntryId.value = entry.id
  editForm.value = {
    destination: entry.destination,
    reason: entry.reason,
  }
  isManageDialogOpen.value = true
}

const closeManageDialog = () => {
  isManageDialogOpen.value = false
  activeEntryId.value = ''
  rowActionError.value = ''
}

const saveEntry = async () => {
  const destination = editForm.value.destination.trim()
  const reason = editForm.value.reason.trim()

  if (!activeEntryId.value || !destination || !reason) {
    rowActionError.value = 'Destination and reason are required.'
    return
  }

  rowActionError.value = ''
  isSaving.value = true
  try {
    await updateBlockedEntry(activeEntryId.value, { destination, reason })
    blockedEntries.value = blockedEntries.value.map((entry) => {
      if (entry.id !== activeEntryId.value) return entry
      return {
        ...entry,
        destination,
        reason,
      }
    })
    closeManageDialog()
  } catch (error) {
    rowActionError.value = error instanceof Error ? error.message : 'Save request failed.'
  } finally {
    isSaving.value = false
  }
}

const deleteEntry = async () => {
  if (!activeEntryId.value) return

  rowActionError.value = ''
  isDeleting.value = true
  try {
    await deleteBlockedEntry(activeEntryId.value)
    blockedEntries.value = blockedEntries.value.filter((entry) => entry.id !== activeEntryId.value)
    closeManageDialog()
  } catch (error) {
    rowActionError.value = error instanceof Error ? error.message : 'Delete request failed.'
  } finally {
    isDeleting.value = false
  }
}

const formatTime = (t: string) => {
  return new Date(t).toUTCString();
}
</script>

<template>
  <Card class="panel">
    <template #title>Blocklist Management</template>
    <template #subtitle>Inspect blocked entities and why each request was denied.</template>
    <template #content>
      <p v-if="loadError">{{ loadError }}</p>
      <p v-else-if="isLoading">Loading blocked entries...</p>
      <template v-else>
        <InputText
          v-model="search"
          placeholder="Search by IP, destination, reason, status..."
          fluid
        />

        <DataTable :value="filteredEntries" paginator :rows="8" dataKey="id" stripedRows>
          <Column field="id" header="Entry" />
          <Column field="destination" header="Destination" />
          <Column field="reason" header="Reason" />
          <Column field="blockedAt" header="Blocked At">
            <template #body="slotProps">
              {{ formatTime(slotProps.data.blockedAt) }}
            </template>
          </Column>
          <Column header="Manage" style="width: 9rem">
            <template #body="slotProps">
              <Button
                label="Manage"
                size="small"
                severity="secondary"
                @click="openManageDialog(slotProps.data)"
              />
            </template>
          </Column>
        </DataTable>
      </template>

      <Dialog
        v-model:visible="isManageDialogOpen"
        header="Manage Blocked Entry"
        modal
        :style="{ width: 'min(42rem, 95vw)' }"
      >
        <div class="manage-form">
          <p class="stat-label">Destination</p>
          <InputText v-model="editForm.destination" fluid />

          <p class="stat-label">Reason</p>
          <Textarea v-model="editForm.reason" rows="4" fluid />

          <p v-if="rowActionError" class="panel-meta">{{ rowActionError }}</p>
        </div>

        <template #footer>
          <Button label="Cancel" severity="secondary" text @click="closeManageDialog" />
          <Button label="Save" :loading="isSaving" @click="saveEntry" />
          <Button
            label="Delete"
            severity="danger"
            :loading="isDeleting"
            @click="deleteEntry"
          />
        </template>
      </Dialog>
    </template>
  </Card>
</template>
