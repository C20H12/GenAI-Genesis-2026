export type TrafficPoint = {
  time: string
  inboundMbps: number
  outboundMbps: number
}

export type BlockedEntry = {
  id: string
  source: string
  destination: string
  reason: string
  category: 'Malware' | 'Policy' | 'Bot' | 'DLP'
  blockedAt: string
  hitCount: number
  status: 'active' | 'review'
}

export type ProxyLog = {
  id: number
  timestamp: string
  level: 'INFO' | 'WARN' | 'ERROR'
  source: string
  message: string
  requestId: string
}

export type OverviewData = {
  traffic: { value: string; delta: string }
  connections: { value: string; delta: string }
  approved: { value: string; delta: string }
  blocked: { value: string; delta: string }
}
