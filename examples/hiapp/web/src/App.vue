<script setup>
import { onMounted, ref } from 'vue'
import { api } from './api'

const info = ref(null)
const error = ref('')

onMounted(async () => {
  try {
    info.value = await api('/api/hello')
  } catch (e) {
    error.value = e.message || String(e)
  }
})
</script>

<template>
  <main>
    <h1>hiapp</h1>
    <p v-if="error" class="error">{{ error }}</p>
    <dl v-else-if="info">
      <dt>hello</dt>
      <dd>{{ info.hello }}</dd>
      <dt>version</dt>
      <dd>{{ info.version }}</dd>
      <dt>data_dir</dt>
      <dd>{{ info.data_dir }}</dd>
    </dl>
    <p v-else>加载中…</p>
  </main>
</template>

<style>
body { font-family: system-ui, sans-serif; margin: 2rem; color: #213547; }
h1 { font-weight: 600; }
dt { font-weight: 600; margin-top: 0.5rem; }
dd { margin: 0; word-break: break-all; }
.error { color: #c0392b; }
</style>
