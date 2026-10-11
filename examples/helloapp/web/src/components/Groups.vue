<script setup>
import { computed, reactive, ref } from 'vue'
import { api, can } from '../api'

const props = defineProps({
  me: { type: Object, default: null },
  groups: { type: Array, default: () => [] },
})
const emit = defineEmits(['changed'])

// 必须 computed：me 由 App 异步拉取，setup 时还是 null（非响应式求值会恒为 false）
const writable = computed(() => can(props.me, 'group.write'))
const formErr = ref('')
const saving = ref(false)
const form = reactive({ name: '', description: '' })

async function create() {
  saving.value = true
  formErr.value = ''
  try {
    await api('/api/groups', { method: 'POST', body: { name: form.name, description: form.description } })
    Object.assign(form, { name: '', description: '' })
    emit('changed')
  } catch (e) {
    formErr.value = e.message
  } finally {
    saving.value = false
  }
}

// 两击确认替代原生 confirm()（同 Devices.vue）
const confirmId = ref(null)

async function del(g) {
  if (confirmId.value !== g.id) {
    confirmId.value = g.id
    return
  }
  confirmId.value = null
  formErr.value = ''
  try {
    await api(`/api/groups/${g.id}`, { method: 'DELETE' })
    emit('changed')
  } catch (e) {
    formErr.value = e.message   // 组内仍有设备 → 409 在此透出
  }
}
</script>

<template>
  <section>
    <div class="panel-head">
      <h2>设备分组</h2>
    </div>
    <p v-if="formErr" class="error">{{ formErr }}</p>
    <table>
      <thead>
        <tr><th>名称</th><th>说明</th><th>设备数</th><th v-if="writable">操作</th></tr>
      </thead>
      <tbody>
        <tr v-if="!groups.length"><td colspan="4" class="muted">暂无分组</td></tr>
        <tr v-for="g in groups" v-else :key="g.id">
          <td>{{ g.name }}</td>
          <td class="muted">{{ g.description || '—' }}</td>
          <td>{{ g.device_count }}</td>
          <td v-if="writable" class="actions">
            <button class="danger" :disabled="g.device_count > 0"
                    :title="g.device_count > 0 ? '请先移出组内设备' : ''"
                    @click="del(g)">{{ confirmId === g.id ? '确认删除' : '删除' }}</button>
          </td>
        </tr>
      </tbody>
    </table>

    <form v-if="writable" class="form-panel inline" @submit.prevent="create">
      <label>名称 <input v-model.trim="form.name" required maxlength="64" placeholder="新分组名" /></label>
      <label>说明 <input v-model.trim="form.description" maxlength="256" placeholder="可选" /></label>
      <button type="submit" class="primary" :disabled="saving">{{ saving ? '创建中…' : '+ 新增分组' }}</button>
    </form>
  </section>
</template>
