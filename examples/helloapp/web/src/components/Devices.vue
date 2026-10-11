<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, can } from '../api'

const props = defineProps({
  me: { type: Object, default: null },
  groups: { type: Array, default: () => [] },
})
const emit = defineEmits(['groups-changed'])

const writable = computed(() => can(props.me, 'device.write'))

// ---- 列表 / 过滤 / 分页 ----
const items = ref([])
const total = ref(0)
const limit = 20
const offset = ref(0)
const loading = ref(false)
const listErr = ref('')
const fStatus = ref('')
const fGroup = ref('')
const fQuery = ref('')

const STATUS = ['online', 'offline', 'error']
const STATUS_CN = { online: '在线', offline: '离线', error: '故障' }

function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleString() : '—'
}

async function load() {
  loading.value = true
  listErr.value = ''
  try {
    const p = new URLSearchParams({ limit: String(limit), offset: String(offset.value) })
    if (fStatus.value) p.set('status', fStatus.value)
    if (fGroup.value) p.set('group_id', fGroup.value)
    if (fQuery.value) p.set('q', fQuery.value)
    const page = await api(`/api/devices?${p}`)
    items.value = page.items
    total.value = page.total
  } catch (e) {
    listErr.value = e.message
  } finally {
    loading.value = false
  }
}

watch([fStatus, fGroup], () => { offset.value = 0; load() })
watch(fQuery, (v, old) => {            // 关键字 300ms 防抖
  setTimeout(() => { if (fQuery.value === v && v !== old) { offset.value = 0; load() } }, 300)
})

// ---- 新增 / 编辑表单 ----
const showForm = ref(false)
const editingId = ref(null)            // null = 新增
const saving = ref(false)
const formErr = ref('')
const form = reactive({ sn: '', name: '', model: '', group_id: '', status: 'offline' })

function openCreate() {
  editingId.value = null
  Object.assign(form, { sn: '', name: '', model: '', group_id: '', status: 'offline' })
  formErr.value = ''
  showForm.value = true
}

function openEdit(d) {
  editingId.value = d.id
  Object.assign(form, {
    sn: d.sn, name: d.name, model: d.model,
    group_id: d.group_id ?? '', status: d.status,
  })
  formErr.value = ''
  showForm.value = true
}

async function save() {
  saving.value = true
  formErr.value = ''
  try {
    const payload = {
      name: form.name, model: form.model,
      group_id: form.group_id === '' ? null : Number(form.group_id),
    }
    if (editingId.value === null) {
      payload.sn = form.sn
      payload.status = form.status
      await api('/api/devices', { method: 'POST', body: payload })
    } else {
      await api(`/api/devices/${editingId.value}`, { method: 'PATCH', body: payload })
    }
    showForm.value = false
    emit('groups-changed')           // 分组归属变了 → 组内计数刷新
    await load()
  } catch (e) {
    formErr.value = e.message
  } finally {
    saving.value = false
  }
}

// 两击确认替代原生 confirm()（嵌入式 WebView 对话框体验差，且自动化难处理）
const confirmId = ref(null)

async function del(d) {
  if (confirmId.value !== d.id) {
    confirmId.value = d.id
    return
  }
  confirmId.value = null
  listErr.value = ''
  try {
    await api(`/api/devices/${d.id}`, { method: 'DELETE' })
    emit('groups-changed')
    await load()
  } catch (e) {
    listErr.value = e.message
  }
}

async function heartbeat(d) {
  listErr.value = ''
  try {
    Object.assign(d, await api(`/api/devices/${d.id}/heartbeat`, { method: 'POST' }))
  } catch (e) {
    listErr.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <section>
    <div class="panel-head">
      <h2>设备管理</h2>
      <button v-if="writable" class="primary" @click="openCreate">+ 新增设备</button>
    </div>

    <div class="toolbar">
      <select v-model="fStatus" aria-label="状态过滤">
        <option value="">全部状态</option>
        <option v-for="s in STATUS" :key="s" :value="s">{{ STATUS_CN[s] }}</option>
      </select>
      <select v-model="fGroup" aria-label="分组过滤">
        <option value="">全部分组</option>
        <option v-for="g in groups" :key="g.id" :value="String(g.id)">{{ g.name }}</option>
      </select>
      <input v-model="fQuery" type="search" placeholder="搜索名称 / 序列号…" />
      <button @click="load">刷新</button>
    </div>

    <p v-if="listErr" class="error">{{ listErr }}</p>

    <table>
      <thead>
        <tr>
          <th>序列号</th><th>名称</th><th>型号</th><th>分组</th>
          <th>状态</th><th>最近心跳</th><th v-if="writable">操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="loading"><td colspan="7" class="muted">加载中…</td></tr>
        <tr v-else-if="!items.length"><td colspan="7" class="muted">暂无设备</td></tr>
        <tr v-for="d in items" v-else :key="d.id">
          <td><code>{{ d.sn }}</code></td>
          <td>{{ d.name }}</td>
          <td>{{ d.model || '—' }}</td>
          <td>{{ d.group_name || '未分组' }}</td>
          <td><span class="badge" :class="'st-' + d.status">{{ STATUS_CN[d.status] }}</span></td>
          <td class="muted">{{ fmtTime(d.last_seen) }}</td>
          <td v-if="writable" class="actions">
            <button @click="heartbeat(d)">心跳</button>
            <button @click="openEdit(d)">编辑</button>
            <button class="danger" @click="del(d)">{{ confirmId === d.id ? '确认删除' : '删除' }}</button>
          </td>
        </tr>
      </tbody>
    </table>

    <div class="pager">
      <span class="muted">共 {{ total }} 台</span>
      <button :disabled="offset === 0 || loading" @click="offset -= limit; load()">上一页</button>
      <button :disabled="offset + limit >= total || loading" @click="offset += limit; load()">下一页</button>
    </div>

    <form v-if="showForm" class="form-panel" @submit.prevent="save">
      <h3>{{ editingId === null ? '新增设备' : `编辑设备 #${editingId}` }}</h3>
      <label>序列号 <input v-model.trim="form.sn" :disabled="editingId !== null"
        required maxlength="64" placeholder="SN-xxxx" /></label>
      <label>名称 <input v-model.trim="form.name" required maxlength="64" /></label>
      <label>型号 <input v-model.trim="form.model" maxlength="64" /></label>
      <label>分组
        <select v-model="form.group_id">
          <option value="">未分组</option>
          <option v-for="g in groups" :key="g.id" :value="String(g.id)">{{ g.name }}</option>
        </select>
      </label>
      <label v-if="editingId === null">初始状态
        <select v-model="form.status">
          <option v-for="s in STATUS" :key="s" :value="s">{{ STATUS_CN[s] }}</option>
        </select>
      </label>
      <p v-if="formErr" class="error">{{ formErr }}</p>
      <div class="form-actions">
        <button type="submit" class="primary" :disabled="saving">{{ saving ? '保存中…' : '保存' }}</button>
        <button type="button" @click="showForm = false">取消</button>
      </div>
    </form>
  </section>
</template>
