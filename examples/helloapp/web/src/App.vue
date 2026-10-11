<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from './api'
import Devices from './components/Devices.vue'
import Groups from './components/Groups.vue'

const me = ref(null)          // /api/me：user/roles/perms（前端据此控权）
const info = ref(null)        // /api/system/info：版本 + 计数概览
const groups = ref([])
const error = ref('')

const roleName = computed(() => me.value?.roles?.join(', ') || '—')

async function loadGroups() {
  try {
    groups.value = await api('/api/groups')
  } catch (e) {
    error.value = e.message
  }
}

onMounted(async () => {
  try {
    me.value = await api('/api/me')
    info.value = await api('/api/system/info')
    await loadGroups()
  } catch (e) {
    error.value = e.message
  }
})

async function logout() {
  await fetch('/logout', { method: 'POST' }).catch(() => {})
  location.replace('/login')
}
</script>

<template>
  <header>
    <h1>helloApp <span class="ver" v-if="info">v{{ info.version }}</span></h1>
    <div v-if="me" class="who">
      <span class="muted">{{ me.user }}（{{ roleName }}）</span>
      <button @click="logout">退出登录</button>
    </div>
  </header>

  <main>
    <p v-if="error" class="error">{{ error }}</p>

    <p v-if="info" class="stats">
      设备 <b>{{ info.counts.devices }}</b> 台 ·
      分组 <b>{{ info.counts.groups }}</b> 个 ·
      审计事件 <b>{{ info.counts.events }}</b> 条
      <span class="muted">（数据目录 {{ info.data_dir }}）</span>
    </p>

    <Devices :me="me" :groups="groups" @groups-changed="loadGroups" />
    <Groups :me="me" :groups="groups" @changed="loadGroups" />
  </main>
</template>

<style>
body { font-family: system-ui, sans-serif; margin: 0; color: #213547; background: #f6f7f9; }
header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 0.8rem 1.5rem; background: #fff; border-bottom: 1px solid #e3e6ea;
}
h1 { font-size: 1.15rem; font-weight: 600; margin: 0; }
h2 { font-size: 1rem; margin: 0; }
.ver { font-size: 0.75rem; color: #8a929c; font-weight: 400; margin-left: 0.3rem; }
.who { display: flex; gap: 0.6rem; align-items: center; }
main { max-width: 960px; margin: 1.2rem auto; padding: 0 1rem; }
section {
  background: #fff; border: 1px solid #e3e6ea; border-radius: 8px;
  padding: 1rem 1.2rem; margin-bottom: 1.2rem;
}
.panel-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.7rem; }
.stats { color: #5a6470; margin: 0 0 1rem; }
.stats b { color: #213547; }
.stats .muted { margin-left: 0.4rem; word-break: break-all; }
.muted { color: #8a929c; font-size: 0.88rem; }
.error { color: #c0392b; }
code { background: #f0f2f5; padding: 0.1rem 0.3rem; border-radius: 4px; }

table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
th, td { text-align: left; padding: 0.45rem 0.5rem; border-bottom: 1px solid #eef0f3; }
th { color: #6b7480; font-weight: 600; font-size: 0.85rem; }
.actions { white-space: nowrap; }
.actions button { margin-right: 0.35rem; }

.badge { padding: 0.12rem 0.55rem; border-radius: 999px; font-size: 0.8rem; }
.st-online { background: #e2f5e9; color: #1d7a3f; }
.st-offline { background: #eceff2; color: #5a6470; }
.st-error { background: #fdeaea; color: #b03434; }

button {
  font: inherit; padding: 0.3rem 0.8rem; border: 1px solid #cfd6dd;
  border-radius: 6px; background: #fff; cursor: pointer;
}
button:hover { background: #f2f4f7; }
button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
button.primary:hover { background: #1d4fd8; }
button.danger { color: #b03434; }
button.danger:hover { background: #fdeaea; }
button:disabled { opacity: 0.45; cursor: not-allowed; }

.toolbar { display: flex; gap: 0.5rem; margin-bottom: 0.8rem; flex-wrap: wrap; }
.toolbar input[type='search'] { flex: 1; min-width: 10rem; }
input, select {
  font: inherit; padding: 0.3rem 0.5rem; border: 1px solid #cfd6dd;
  border-radius: 6px; background: #fff;
}
.pager { display: flex; gap: 0.6rem; align-items: center; margin-top: 0.7rem; }

.form-panel {
  margin-top: 0.9rem; padding: 0.9rem; border: 1px dashed #cfd6dd;
  border-radius: 8px; display: flex; flex-wrap: wrap; gap: 0.7rem; align-items: end;
}
.form-panel h3 { width: 100%; margin: 0 0 0.2rem; font-size: 0.95rem; }
.form-panel label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; color: #5a6470; }
.form-panel.inline { border-style: solid; border-color: #eef0f3; }
.form-actions { display: flex; gap: 0.5rem; width: 100%; }
</style>
