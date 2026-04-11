<template>
  <div class="page">
    <div class="page-header">
      <h1>Sessions</h1>
      <button class="btn btn-ghost btn-sm" @click="load">Refresh</button>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>{{ sessions.length }} session{{ sessions.length !== 1 ? 's' : '' }}</h2>
      </div>
      <div class="table-wrap">
        <table v-if="sessions.length">
          <thead>
            <tr>
              <th>Session ID</th>
              <th>User</th>
              <th>Flow</th>
              <th>Created</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <template v-for="s in sessions" :key="s.id">
              <tr @click="toggle(s.id)" style="cursor:pointer">
                <td><code>{{ s.id }}</code></td>
                <td>{{ s.user_id }}</td>
                <td><code>{{ s.flow_id }}</code></td>
                <td>{{ formatDate(s.created_at) }}</td>
                <td>{{ formatDate(s.expires_at) }}</td>
                <td>
                  <span class="btn btn-ghost btn-sm">{{ expanded === s.id ? '▲' : '▼' }}</span>
                </td>
              </tr>
              <tr v-if="expanded === s.id">
                <td colspan="6" style="background:#f8faff;padding:14px 18px">
                  <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px;font-weight:600">DETAIL</div>
                  <div style="display:grid;grid-template-columns:120px 1fr;gap:4px 12px;font-size:12px">
                    <span style="color:var(--text-muted)">Session ID</span><span>{{ s.id }}</span>
                    <span style="color:var(--text-muted)">User ID</span><span>{{ s.user_id }}</span>
                    <span style="color:var(--text-muted)">Flow ID</span><span>{{ s.flow_id }}</span>
                    <span style="color:var(--text-muted)">Created</span><span>{{ formatDate(s.created_at) }}</span>
                    <span style="color:var(--text-muted)">Expires</span><span>{{ formatDate(s.expires_at) }}</span>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
        <div v-else class="empty">No sessions yet. Complete an OIDC flow to create one.</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'

interface Session {
  id: string
  user_id: string
  flow_id: string
  created_at: string
  expires_at: string
}

const sessions = ref<Session[]>([])
const expanded = ref<string | null>(null)

async function load() {
  const res = await fetch('/api/v1/sessions')
  sessions.value = await res.json()
}

function toggle(id: string) {
  expanded.value = expanded.value === id ? null : id
}

function formatDate(iso: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

onMounted(load)
</script>
