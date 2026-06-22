import axios from 'axios'
import type { ScanDetail, ScanSummary } from '../types'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 120_000, // les scans peuvent prendre du temps
})

// ── Scans ─────────────────────────────────────────────────────────────────────

export async function uploadScan(
  file: File,
  opts: { min_cvss?: number; severity?: string; after_year?: number; no_api?: boolean }
): Promise<ScanDetail> {
  const form = new FormData()
  form.append('file', file)
  if (opts.min_cvss !== undefined) form.append('min_cvss', String(opts.min_cvss))
  if (opts.severity) form.append('severity', opts.severity)
  if (opts.after_year) form.append('after_year', String(opts.after_year))
  if (opts.no_api) form.append('no_api', 'true')

  const { data } = await api.post<ScanDetail>('/api/scans/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function directScan(
  target: string,
  opts: { nmap_args?: string; min_cvss?: number; severity?: string; after_year?: number; no_api?: boolean }
): Promise<ScanDetail> {
  const form = new FormData()
  form.append('target', target)
  form.append('nmap_args', opts.nmap_args || '-sV -T4 --open')
  if (opts.min_cvss !== undefined) form.append('min_cvss', String(opts.min_cvss))
  if (opts.severity) form.append('severity', opts.severity)
  if (opts.after_year) form.append('after_year', String(opts.after_year))
  if (opts.no_api) form.append('no_api', 'true')

  const { data } = await api.post<ScanDetail>('/api/scans/direct', form)
  return data
}

export async function sshScan(payload: {
  host: string; port: number; username: string
  password?: string; key_path?: string
  filters?: { min_cvss: number; severity: string[]; after_year?: number; no_api: boolean }
}): Promise<ScanDetail> {
  const { data } = await api.post<ScanDetail>('/api/ssh/scan', payload)
  return data
}

export async function listScans(limit = 50, offset = 0): Promise<ScanSummary[]> {
  const { data } = await api.get<ScanSummary[]>('/api/scans', { params: { limit, offset } })
  return data
}

export async function getScan(id: number): Promise<ScanDetail> {
  const { data } = await api.get<ScanDetail>(`/api/scans/${id}`)
  return data
}

export async function deleteScan(id: number): Promise<void> {
  await api.delete(`/api/scans/${id}`)
}

// ── Export ────────────────────────────────────────────────────────────────────

export function exportJsonUrl(id: number): string {
  return `${api.defaults.baseURL}/api/export/${id}/json`
}

export function exportHtmlUrl(id: number): string {
  return `${api.defaults.baseURL}/api/export/${id}/html`
}
