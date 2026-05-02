<template>
  <div class="page">
    <div class="page-header">
      <h1>Admins</h1>
      <button class="btn btn-primary" @click="openCreate">+ New Admin</button>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>{{ admins.length }} admin{{ admins.length !== 1 ? 's' : '' }}</h2>
      </div>
      <div class="table-wrap">
        <table v-if="admins.length">
          <thead>
            <tr>
              <th>Username</th>
              <th>Display Name</th>
              <th>Status</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in admins" :key="a.id">
              <td>{{ a.username }}</td>
              <td>{{ a.display_name }}</td>
              <td>
                <span class="badge" :class="a.active ? 'badge-green' : 'badge-gray'">
                  {{ a.active ? 'active' : 'inactive' }}
                </span>
              </td>
              <td>{{ fmtDate(a.created_at) }}</td>
              <td style="white-space:nowrap">
                <button class="btn btn-ghost btn-sm" @click="openPassword(a)">Password</button>
                <button class="btn btn-ghost btn-sm" style="margin-left:4px" @click="toggleActive(a)">
                  {{ a.active ? 'Deactivate' : 'Activate' }}
                </button>
                <button class="btn btn-danger btn-sm" style="margin-left:4px" @click="deleteAdmin(a)">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">No admins found.</div>
      </div>
    </div>

    <!-- Create admin modal -->
    <div v-if="createModal" class="modal-backdrop" @click.self="createModal = false">
      <div class="modal">
        <div class="modal-header">
          <h3>New Admin</h3>
          <button class="modal-close" @click="createModal = false">&times;</button>
        </div>
        <div class="modal-body">
          <div v-if="createError" class="form-error">{{ createError }}</div>
          <label class="form-label">Username</label>
          <input v-model="createForm.username" class="form-input" placeholder="alice" />
          <label class="form-label">Display Name</label>
          <input v-model="createForm.display_name" class="form-input" placeholder="Alice (optional)" />
          <label class="form-label">Password</label>
          <input v-model="createForm.password" type="password" class="form-input" placeholder="••••••••" />
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="createModal = false">Cancel</button>
          <button class="btn btn-primary" @click="submitCreate">Create</button>
        </div>
      </div>
    </div>

    <!-- Change password modal -->
    <div v-if="pwModal" class="modal-backdrop" @click.self="pwModal = null">
      <div class="modal">
        <div class="modal-header">
          <h3>Change Password — {{ pwModal.username }}</h3>
          <button class="modal-close" @click="pwModal = null">&times;</button>
        </div>
        <div class="modal-body">
          <div v-if="pwError" class="form-error">{{ pwError }}</div>
          <label class="form-label">New Password</label>
          <input v-model="pwForm.password" type="password" class="form-input" placeholder="••••••••" />
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" @click="pwModal = null">Cancel</button>
          <button class="btn btn-primary" @click="submitPassword">Save</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { apiFetch } from '../auth'

interface Admin {
  id: string
  username: string
  display_name: string
  active: boolean
  created_at: string
}

const admins = ref<Admin[]>([])

const createModal = ref(false)
const createError = ref('')
const createForm  = ref({ username: '', display_name: '', password: '' })

const pwModal = ref<Admin | null>(null)
const pwError = ref('')
const pwForm  = ref({ password: '' })

async function load() {
  const res = await apiFetch('/api/v1/admins')
  if (res.ok) admins.value = await res.json()
}

function openCreate() {
  createForm.value = { username: '', display_name: '', password: '' }
  createError.value = ''
  createModal.value = true
}

async function submitCreate() {
  createError.value = ''
  const res = await apiFetch('/api/v1/admins', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(createForm.value),
  })
  if (res.ok) {
    createModal.value = false
    await load()
  } else {
    const body = await res.json().catch(() => ({}))
    createError.value = body?.error?.message ?? 'Failed to create admin.'
  }
}

function openPassword(a: Admin) {
  pwForm.value = { password: '' }
  pwError.value = ''
  pwModal.value = a
}

async function submitPassword() {
  if (!pwModal.value) return
  pwError.value = ''
  const res = await apiFetch(`/api/v1/admins/${pwModal.value.id}/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(pwForm.value),
  })
  if (res.ok) {
    pwModal.value = null
  } else {
    const body = await res.json().catch(() => ({}))
    pwError.value = body?.error?.message ?? 'Failed to change password.'
  }
}

async function toggleActive(a: Admin) {
  const res = await apiFetch(`/api/v1/admins/${a.id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active: !a.active }),
  })
  if (res.ok) {
    await load()
  } else {
    const body = await res.json().catch(() => ({}))
    alert(body?.error?.message ?? 'Failed to update admin.')
  }
}

async function deleteAdmin(a: Admin) {
  if (!confirm(`Delete admin "${a.username}"? This cannot be undone.`)) return
  const res = await apiFetch(`/api/v1/admins/${a.id}`, { method: 'DELETE' })
  if (res.ok || res.status === 204) {
    await load()
  } else {
    const body = await res.json().catch(() => ({}))
    alert(body?.error?.message ?? 'Failed to delete admin.')
  }
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

onMounted(load)
</script>
