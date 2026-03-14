import type { BlockedEntry, OverviewData, ProxyLog, TrafficPoint } from '../data/proxyData'

const fetchJson = async <T>(url: string): Promise<T> => {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status} ${response.statusText}`)
  }
  return response.json() as Promise<T>
}

const assertSuccess = async (response: Response): Promise<void> => {
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status} ${response.statusText}`)
  }
}

export const fetchOverviewData = () => fetchJson<OverviewData>('/api/overview.json')
export const fetchTrafficData = () => fetchJson<TrafficPoint[]>('/api/traffic.json')
export const fetchBlockedData = () => fetchJson<BlockedEntry[]>('/api/blocked.json')
export const fetchLogsData = () => fetchJson<ProxyLog[]>('/api/logs.json')

export const updateBlockedEntry = async (
  id: string,
  payload: Pick<BlockedEntry, 'destination' | 'reason'>,
): Promise<void> => {
  const response = await fetch(`/api/blocked/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  })

  // Local mock API is static files only and may not implement PATCH routes.
  if (import.meta.env.DEV && response.status === 404) {
    return
  }

  await assertSuccess(response)
}

export const deleteBlockedEntry = async (id: string): Promise<void> => {
  const response = await fetch(`/api/blocked/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })

  // Local mock API is static files only and may not implement DELETE routes.
  if (import.meta.env.DEV && response.status === 404) {
    return
  }

  await assertSuccess(response)
}
