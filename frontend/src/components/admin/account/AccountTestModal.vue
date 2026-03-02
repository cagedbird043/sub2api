<template>
  <BaseDialog
    :show="show"
    :title="t('admin.accounts.testAccountConnection')"
    width="comfortable"
    @close="handleClose"
  >
    <div class="space-y-4">
      <!-- Account Info Card -->
      <div
        v-if="account"
        class="flex items-center justify-between rounded-xl border border-gray-200 bg-gradient-to-r from-gray-50 to-gray-100 p-3 dark:border-dark-500 dark:from-dark-700 dark:to-dark-600"
      >
        <div class="flex items-center gap-3">
          <div
            class="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-primary-500 to-primary-600"
          >
            <Icon name="play" size="md" class="text-white" :stroke-width="2" />
          </div>
          <div>
            <div class="font-semibold text-gray-900 dark:text-gray-100">{{ account.name }}</div>
            <div class="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400">
              <span
                class="rounded bg-gray-200 px-1.5 py-0.5 text-[10px] font-medium uppercase dark:bg-dark-500"
              >
                {{ account.type }}
              </span>
              <span>{{ t('admin.accounts.account') }}</span>
            </div>
          </div>
        </div>
        <span
          :class="[
            'rounded-full px-2.5 py-1 text-xs font-semibold',
            account.status === 'active'
              ? 'bg-green-100 text-green-700 dark:bg-green-500/20 dark:text-green-400'
              : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
          ]"
        >
          {{ account.status }}
        </span>
      </div>

      <div class="space-y-1.5">
        <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
          {{ t('admin.accounts.selectTestModel') }}
        </label>
        <Select
          v-model="selectedModelId"
          :options="displayModels"
          :disabled="loadingModels || status === 'connecting'"
          value-key="id"
          label-key="display_name"
          :placeholder="loadingModels ? t('common.loading') + '...' : t('admin.accounts.selectTestModel')"
        >
          <template #selected="{ option }">
            <span v-if="option" class="flex min-w-0 items-center gap-2">
              <span class="truncate">{{ getOptionRequestLabel(option) }}</span>
              <span
                v-if="getOptionMappedTarget(option)"
                class="inline-flex shrink-0 items-center rounded-md bg-primary-50 px-1.5 py-0.5 font-mono text-[11px] text-primary-700 dark:bg-primary-900/30 dark:text-primary-300"
              >
                {{ getOptionMappedTarget(option) }}
              </span>
            </span>
            <span v-else class="text-gray-400 dark:text-gray-500">
              {{ loadingModels ? t('common.loading') + '...' : t('admin.accounts.selectTestModel') }}
            </span>
          </template>

          <template #option="{ option, selected }">
            <div class="flex w-full min-w-0 items-center justify-between gap-2">
              <div class="min-w-0">
                <div class="truncate text-sm text-gray-900 dark:text-gray-100">{{ getOptionRequestLabel(option) }}</div>
                <div v-if="getOptionMappedTarget(option)" class="truncate text-[11px] text-gray-500 dark:text-gray-400">
                  {{ t('admin.accounts.mapsToModel') }}
                </div>
              </div>
              <div class="flex shrink-0 items-center gap-2">
                <span
                  v-if="getOptionMappedTarget(option)"
                  class="inline-flex items-center rounded-md bg-gray-100 px-1.5 py-0.5 font-mono text-[11px] text-gray-600 dark:bg-dark-600 dark:text-gray-300"
                >
                  {{ getOptionMappedTarget(option) }}
                </span>
                <Icon v-if="selected" name="check" size="sm" class="text-primary-500" :stroke-width="2" />
              </div>
            </div>
          </template>
        </Select>
        <p class="text-xs text-gray-500 dark:text-gray-400">
          {{ t('admin.accounts.testModelMappingHint') }}
        </p>
      </div>

      <!-- Terminal Output -->
      <div class="group relative">
        <div
          ref="terminalRef"
          class="max-h-[240px] min-h-[120px] overflow-y-auto rounded-xl border border-gray-700 bg-gray-900 p-4 font-mono text-sm dark:border-gray-800 dark:bg-black"
        >
          <!-- Status Line -->
          <div v-if="status === 'idle'" class="flex items-center gap-2 text-gray-500">
            <Icon name="play" size="sm" :stroke-width="2" />
            <span>{{ t('admin.accounts.readyToTest') }}</span>
          </div>
          <div v-else-if="status === 'connecting'" class="flex items-center gap-2 text-yellow-400">
            <Icon name="refresh" size="sm" class="animate-spin" :stroke-width="2" />
            <span>{{ t('admin.accounts.connectingToApi') }}</span>
          </div>

          <!-- Output Lines -->
          <div v-for="(line, index) in outputLines" :key="index" :class="line.class">
            {{ line.text }}
          </div>

          <!-- Streaming Content -->
          <div v-if="streamingContent" class="text-green-400">
            {{ streamingContent }}<span class="animate-pulse">_</span>
          </div>

          <!-- Result Status -->
          <div
            v-if="status === 'success'"
            class="mt-3 flex items-center gap-2 border-t border-gray-700 pt-3 text-green-400"
          >
            <Icon name="check" size="sm" :stroke-width="2" />
            <span>{{ t('admin.accounts.testCompleted') }}</span>
          </div>
          <div
            v-else-if="status === 'error'"
            class="mt-3 flex items-center gap-2 border-t border-gray-700 pt-3 text-red-400"
          >
            <Icon name="x" size="sm" :stroke-width="2" />
            <span>{{ errorMessage }}</span>
          </div>
        </div>

        <!-- Copy Button -->
        <button
          v-if="outputLines.length > 0"
          @click="copyOutput"
          class="absolute right-2 top-2 rounded-lg bg-gray-800/80 p-1.5 text-gray-400 opacity-0 transition-all hover:bg-gray-700 hover:text-white group-hover:opacity-100"
          :title="t('admin.accounts.copyOutput')"
        >
          <Icon name="link" size="sm" :stroke-width="2" />
        </button>
      </div>

      <!-- Test Info -->
      <div class="flex items-center justify-between px-1 text-xs text-gray-500 dark:text-gray-400">
        <div class="flex items-center gap-3">
          <span class="flex items-center gap-1">
            <Icon name="grid" size="sm" :stroke-width="2" />
            {{ t('admin.accounts.testModel') }}
          </span>
        </div>
        <span class="flex items-center gap-1">
          <Icon name="chat" size="sm" :stroke-width="2" />
          {{ t('admin.accounts.testPrompt') }}
        </span>
      </div>
    </div>

    <template #footer>
      <div class="flex justify-end gap-3">
        <button
          @click="handleClose"
          class="rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-200 dark:bg-dark-600 dark:text-gray-300 dark:hover:bg-dark-500"
          :disabled="status === 'connecting'"
        >
          {{ t('common.close') }}
        </button>
        <button
          @click="startTest"
          :disabled="status === 'connecting' || !selectedModelId"
          :class="[
            'flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-all',
            status === 'connecting' || !selectedModelId
              ? 'cursor-not-allowed bg-primary-400 text-white'
              : status === 'success'
                ? 'bg-green-500 text-white hover:bg-green-600'
                : status === 'error'
                  ? 'bg-orange-500 text-white hover:bg-orange-600'
                  : 'bg-primary-500 text-white hover:bg-primary-600'
          ]"
        >
          <Icon
            v-if="status === 'connecting'"
            name="refresh"
            size="sm"
            class="animate-spin"
            :stroke-width="2"
          />
          <Icon v-else-if="status === 'idle'" name="play" size="sm" :stroke-width="2" />
          <Icon v-else name="refresh" size="sm" :stroke-width="2" />
          <span>
            {{
              status === 'connecting'
                ? t('admin.accounts.testing')
                : status === 'idle'
                  ? t('admin.accounts.startTest')
                  : t('admin.accounts.retry')
            }}
          </span>
        </button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Select from '@/components/common/Select.vue'
import { Icon } from '@/components/icons'
import { useClipboard } from '@/composables/useClipboard'
import { adminAPI } from '@/api/admin'
import type { Account, ClaudeModel } from '@/types'
import type { AccountEffectiveModelMappingResponse } from '@/api/admin/accounts'

const { t } = useI18n()
const { copyToClipboard } = useClipboard()

interface OutputLine {
  text: string
  class: string
}

interface TestModelOption extends Record<string, unknown> {
  id: string
  display_name: string
  request_label: string
  mapped_target?: string
}

const props = defineProps<{
  show: boolean
  account: Account | null
}>()

const emit = defineEmits<{
  (e: 'close'): void
}>()

const terminalRef = ref<HTMLElement | null>(null)
const status = ref<'idle' | 'connecting' | 'success' | 'error'>('idle')
const outputLines = ref<OutputLine[]>([])
const streamingContent = ref('')
const errorMessage = ref('')
const availableModels = ref<ClaudeModel[]>([])
const effectiveMapping = ref<AccountEffectiveModelMappingResponse | null>(null)
const selectedModelId = ref('')
const loadingModels = ref(false)
let eventSource: EventSource | null = null

const defaultModelOrderByPlatform: Record<string, string[]> = {
  anthropic: [
    'claude-sonnet-4-6',
    'claude-opus-4-6-thinking',
    'claude-opus-4-6',
    'claude-sonnet-4-5',
    'claude-opus-4-5'
  ],
  antigravity: [
    'claude-sonnet-4-6',
    'claude-opus-4-6-thinking',
    'gemini-3.1-pro-high',
    'gemini-3.1-pro-low',
    'gemini-3-flash',
    'gemini-2.5-pro',
    'gemini-2.5-flash'
  ],
  gemini: [
    'gemini-3.1-pro-preview',
    'gemini-3-pro-preview',
    'gemini-3-flash-preview',
    'gemini-2.5-pro',
    'gemini-2.5-flash-lite',
    'gemini-2.5-flash'
  ],
  openai: [
    'gpt-5.1-codex-max',
    'gpt-5.1-codex',
    'gpt-5.1',
    'gpt-5-mini'
  ]
}

const modelSortScore = (platform: string, id: string, index: number): number => {
  const preferred = defaultModelOrderByPlatform[platform] ?? []
  const preferredIndex = preferred.indexOf(id)
  if (preferredIndex >= 0) {
    return preferredIndex
  }
  if (id.includes('3.1') || id.includes('4-6') || id.includes('5.1')) {
    return 100 + index
  }
  if (id.includes('3') || id.includes('4-5') || id.includes('5-')) {
    return 200 + index
  }
  return 300 + index
}

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null
}

const getOptionRequestLabel = (option: unknown): string => {
  if (!isRecord(option)) {
    return ''
  }

  const requestLabel = option.request_label
  if (typeof requestLabel === 'string' && requestLabel.trim() !== '') {
    return requestLabel
  }

  const fallbackLabel = option.display_name
  return typeof fallbackLabel === 'string' ? fallbackLabel : ''
}

const getOptionMappedTarget = (option: unknown): string => {
  if (!isRecord(option)) {
    return ''
  }

  const mappedTarget = option.mapped_target
  if (typeof mappedTarget === 'string' && mappedTarget.trim() !== '') {
    return mappedTarget
  }

  return ''
}

const displayModels = computed<TestModelOption[]>(() => {
  const platform = props.account?.platform ?? ''
  const sorted = [...availableModels.value]
    .map((model, index) => ({ model, index }))
    .sort((a, b) => {
      const scoreA = modelSortScore(platform, a.model.id, a.index)
      const scoreB = modelSortScore(platform, b.model.id, b.index)
      if (scoreA !== scoreB) {
        return scoreA - scoreB
      }
      return a.model.id.localeCompare(b.model.id)
    })
    .map(({ model }) => {
      const requestLabel = model.display_name || model.id
      const mappedTarget = effectiveMapping.value?.mapping?.[model.id]
      const targetLabel = mappedTarget && mappedTarget !== model.id ? mappedTarget : ''

      return {
        id: model.id,
        display_name: targetLabel ? `${requestLabel} ${targetLabel}` : requestLabel,
        request_label: requestLabel,
        mapped_target: targetLabel
      }
    })

  return sorted
})

const pickPreferredModelID = (platform: string, models: ClaudeModel[]): string => {
  if (models.length === 0) {
    return ''
  }

  const preferred = defaultModelOrderByPlatform[platform] ?? []
  for (const modelID of preferred) {
    const matched = models.find((model) => model.id === modelID)
    if (matched) {
      return matched.id
    }
  }

  return models[0].id
}

// Load available models when modal opens
watch(
  () => props.show,
  async (newVal) => {
    if (newVal && props.account) {
      resetState()
      await loadAvailableModels()
    } else {
      closeEventSource()
    }
  }
)

const loadAvailableModels = async () => {
  if (!props.account) return

  loadingModels.value = true
  selectedModelId.value = '' // Reset selection before loading
  effectiveMapping.value = null
  try {
    const [models, mapping] = await Promise.all([
      adminAPI.accounts.getAvailableModels(props.account.id),
      adminAPI.accounts.getEffectiveModelMapping(props.account.id).catch(() => null)
    ])

    availableModels.value = models
    effectiveMapping.value = mapping

    if (availableModels.value.length > 0) {
      selectedModelId.value = pickPreferredModelID(props.account.platform, availableModels.value)
    }
  } catch (error) {
    console.error('Failed to load available models:', error)
    // Fallback to empty list
    availableModels.value = []
    selectedModelId.value = ''
  } finally {
    loadingModels.value = false
  }
}

const resetState = () => {
  status.value = 'idle'
  outputLines.value = []
  streamingContent.value = ''
  errorMessage.value = ''
}

const handleClose = () => {
  // 防止在连接测试进行中关闭对话框
  if (status.value === 'connecting') {
    return
  }
  closeEventSource()
  emit('close')
}

const closeEventSource = () => {
  if (eventSource) {
    eventSource.close()
    eventSource = null
  }
}

const addLine = (text: string, className: string = 'text-gray-300') => {
  outputLines.value.push({ text, class: className })
  scrollToBottom()
}

const scrollToBottom = async () => {
  await nextTick()
  if (terminalRef.value) {
    terminalRef.value.scrollTop = terminalRef.value.scrollHeight
  }
}

const startTest = async () => {
  if (!props.account || !selectedModelId.value) return

  resetState()
  status.value = 'connecting'
  addLine(t('admin.accounts.startingTestForAccount', { name: props.account.name }), 'text-blue-400')
  addLine(t('admin.accounts.testAccountTypeLabel', { type: props.account.type }), 'text-gray-400')
  addLine('', 'text-gray-300')

  closeEventSource()

  try {
    // Create EventSource for SSE
    const url = `/api/v1/admin/accounts/${props.account.id}/test`

    // Use fetch with streaming for SSE since EventSource doesn't support POST
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ model_id: selectedModelId.value })
    })

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }

    const reader = response.body?.getReader()
    if (!reader) {
      throw new Error('No response body')
    }

    const decoder = new TextDecoder()
    let buffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() || ''

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const jsonStr = line.slice(6).trim()
          if (jsonStr) {
            try {
              const event = JSON.parse(jsonStr)
              handleEvent(event)
            } catch (e) {
              console.error('Failed to parse SSE event:', e)
            }
          }
        }
      }
    }
  } catch (error: any) {
    status.value = 'error'
    errorMessage.value = error.message || 'Unknown error'
    addLine(`Error: ${errorMessage.value}`, 'text-red-400')
  }
}

const handleEvent = (event: {
  type: string
  text?: string
  model?: string
  success?: boolean
  error?: string
}) => {
  switch (event.type) {
    case 'test_start':
      addLine(t('admin.accounts.connectedToApi'), 'text-green-400')
      if (event.model) {
        addLine(t('admin.accounts.usingModel', { model: event.model }), 'text-cyan-400')
      }
      addLine(t('admin.accounts.sendingTestMessage'), 'text-gray-400')
      addLine('', 'text-gray-300')
      addLine(t('admin.accounts.response'), 'text-yellow-400')
      break

    case 'content':
      if (event.text) {
        streamingContent.value += event.text
        scrollToBottom()
      }
      break

    case 'test_complete':
      // Move streaming content to output lines
      if (streamingContent.value) {
        addLine(streamingContent.value, 'text-green-300')
        streamingContent.value = ''
      }
      if (event.success) {
        status.value = 'success'
      } else {
        status.value = 'error'
        errorMessage.value = event.error || 'Test failed'
      }
      break

    case 'error':
      status.value = 'error'
      errorMessage.value = event.error || 'Unknown error'
      if (streamingContent.value) {
        addLine(streamingContent.value, 'text-green-300')
        streamingContent.value = ''
      }
      break
  }
}

const copyOutput = () => {
  const text = outputLines.value.map((l) => l.text).join('\n')
  copyToClipboard(text, t('admin.accounts.outputCopied'))
}
</script>
