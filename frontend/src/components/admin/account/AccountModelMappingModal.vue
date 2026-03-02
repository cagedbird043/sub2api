<template>
  <BaseDialog
    :show="show"
    :title="t('admin.accounts.modelMappingDetailsTitle')"
    width="wide"
    @close="handleClose"
  >
    <div class="space-y-4">
      <div
        v-if="account"
        class="flex items-center justify-between rounded-xl border border-cyan-200 bg-gradient-to-r from-cyan-50 to-sky-100 p-3 dark:border-cyan-700/50 dark:from-cyan-900/20 dark:to-sky-900/20"
      >
        <div class="flex items-center gap-3">
          <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-sky-600">
            <Icon name="swap" size="md" class="text-white" />
          </div>
          <div>
            <div class="font-semibold text-gray-900 dark:text-gray-100">{{ account.name }}</div>
            <div class="text-xs text-gray-500 dark:text-gray-400">
              {{ t('admin.accounts.mappingRuleCount', { count: mappingRows.length }) }}
            </div>
          </div>
        </div>
      </div>

      <div
        v-if="showDefaultHint"
        class="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-700/50 dark:bg-amber-900/20 dark:text-amber-300"
      >
        {{ t('admin.accounts.antigravityDefaultMappingHint') }}
      </div>

      <div
        v-if="deprecatedWarnings.length > 0"
        class="space-y-2 rounded-lg border border-orange-200 bg-orange-50 px-3 py-3 text-xs text-orange-800 dark:border-orange-700/50 dark:bg-orange-900/20 dark:text-orange-300"
      >
        <div class="font-medium">{{ t('admin.accounts.deprecatedMappingTitle') }}</div>
        <div
          v-for="warning in deprecatedWarnings"
          :key="`${warning.from}->${warning.to}->${warning.deprecated_model}`"
          class="font-mono"
        >
          <span>{{ warning.from }}</span>
          <span class="mx-1">-&gt;</span>
          <span>{{ warning.to }}</span>
          <span class="mx-1">|</span>
          <span>{{ warning.deprecated_model }}</span>
          <span v-if="warning.suggested_model" class="ml-1">{{ t('admin.accounts.deprecatedSuggestedModel', { model: warning.suggested_model }) }}</span>
        </div>
      </div>

      <div v-if="loadingMapping" class="flex items-center justify-center py-10">
        <LoadingSpinner />
      </div>

      <div
        v-else-if="mappingRows.length === 0 && !editingMapping"
        class="rounded-lg border border-gray-200 bg-gray-50 px-4 py-6 text-sm text-gray-600 dark:border-dark-600 dark:bg-dark-700/40 dark:text-gray-300"
      >
        {{ t('admin.accounts.noModelMappingConfigured') }}
      </div>

      <div v-else-if="!editingMapping" class="overflow-hidden rounded-lg border border-gray-200 dark:border-dark-600">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-600">
          <thead class="bg-gray-50 dark:bg-dark-700/50">
            <tr>
              <th class="px-4 py-2 text-left text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-300">
                {{ t('admin.accounts.requestModel') }}
              </th>
              <th class="px-4 py-2 text-left text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-300">
                {{ t('admin.accounts.targetModel') }}
              </th>
              <th class="px-4 py-2 text-left text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-300">
                {{ t('admin.accounts.mappingSource') }}
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200 bg-white dark:divide-dark-600 dark:bg-dark-800">
            <tr v-for="row in mappingRows" :key="`${row.from}->${row.to}`">
              <td class="px-4 py-2 font-mono text-xs text-gray-800 dark:text-gray-200">{{ row.from }}</td>
              <td class="px-4 py-2 font-mono text-xs text-gray-800 dark:text-gray-200">{{ row.to }}</td>
              <td class="px-4 py-2">
                <span
                  :class="[
                    'inline-flex rounded-full px-2 py-0.5 text-xs font-medium',
                    row.source === 'custom'
                      ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300'
                      : 'bg-gray-100 text-gray-700 dark:bg-dark-600 dark:text-gray-300'
                  ]"
                >
                  {{ row.source === 'custom' ? t('admin.accounts.mappingSourceCustom') : t('admin.accounts.mappingSourceDefault') }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else class="space-y-3">
        <div v-for="(row, index) in editableRows" :key="`${index}-${row.from}-${row.to}`" class="flex items-center gap-2">
          <input
            v-model="row.from"
            type="text"
            class="input flex-1"
            :placeholder="t('admin.accounts.requestModel')"
          />
          <Icon name="arrowRight" size="sm" class="text-gray-400" />
          <input
            v-model="row.to"
            type="text"
            class="input flex-1"
            :placeholder="t('admin.accounts.targetModel')"
          />
          <button
            type="button"
            class="rounded-lg p-2 text-red-500 transition-colors hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/20"
            @click="removeEditableRow(index)"
          >
            <Icon name="x" size="sm" />
          </button>
        </div>
        <button
          type="button"
          class="w-full rounded-lg border-2 border-dashed border-gray-300 px-4 py-2 text-sm text-gray-600 transition-colors hover:border-gray-400 hover:text-gray-700 dark:border-dark-500 dark:text-gray-400 dark:hover:border-dark-400 dark:hover:text-gray-300"
          @click="addEditableRow"
        >
          {{ t('admin.accounts.addMapping') }}
        </button>
      </div>
    </div>

    <template #footer>
      <div class="flex justify-end gap-3">
        <button
          v-if="!editingMapping"
          @click="startEditMapping"
          :disabled="!canEditMapping || loadingMapping || restoringMapping || savingMapping"
          :class="[
            'inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
            !canEditMapping || loadingMapping || restoringMapping || savingMapping
              ? 'cursor-not-allowed bg-gray-100 text-gray-400 dark:bg-dark-700 dark:text-dark-400'
              : 'bg-primary-100 text-primary-700 hover:bg-primary-200 dark:bg-primary-900/30 dark:text-primary-300 dark:hover:bg-primary-900/50'
          ]"
        >
          <Icon name="edit" size="sm" />
          {{ t('admin.accounts.editMapping') }}
        </button>
        <button
          v-if="editingMapping"
          @click="cancelEditMapping"
          :disabled="savingMapping"
          class="inline-flex items-center gap-2 rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-200 dark:bg-dark-600 dark:text-gray-300 dark:hover:bg-dark-500"
        >
          <Icon name="x" size="sm" />
          {{ t('common.cancel') }}
        </button>
        <button
          v-if="editingMapping"
          @click="handleSaveMapping"
          :disabled="savingMapping"
          :class="[
            'inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
            savingMapping
              ? 'cursor-not-allowed bg-gray-100 text-gray-400 dark:bg-dark-700 dark:text-dark-400'
              : 'bg-green-100 text-green-700 hover:bg-green-200 dark:bg-green-900/30 dark:text-green-300 dark:hover:bg-green-900/50'
          ]"
        >
          <Icon name="check" size="sm" />
          {{ t('common.save') }}
        </button>
        <button
          v-if="!editingMapping"
          @click="handleRestoreDefaultMapping"
          :disabled="!canRestoreDefault || restoringMapping || loadingMapping || savingMapping"
          :class="[
            'inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
            !canRestoreDefault || restoringMapping || loadingMapping || savingMapping
              ? 'cursor-not-allowed bg-gray-100 text-gray-400 dark:bg-dark-700 dark:text-dark-400'
              : 'bg-amber-100 text-amber-700 hover:bg-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:hover:bg-amber-900/50'
          ]"
        >
          <Icon name="refresh" size="sm" />
          {{ t('admin.accounts.restoreDefaultMapping') }}
        </button>
        <button
          v-if="!editingMapping"
          @click="handleCopyMappingJson"
          :disabled="loadingMapping || mappingRows.length === 0 || savingMapping"
          :class="[
            'inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
            loadingMapping || mappingRows.length === 0 || savingMapping
              ? 'cursor-not-allowed bg-gray-100 text-gray-400 dark:bg-dark-700 dark:text-dark-400'
              : 'bg-cyan-100 text-cyan-700 hover:bg-cyan-200 dark:bg-cyan-900/30 dark:text-cyan-300 dark:hover:bg-cyan-900/50'
          ]"
        >
          <Icon name="copy" size="sm" />
          {{ t('admin.accounts.copyMappingJson') }}
        </button>
        <button
          @click="handleClose"
          class="rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-200 dark:bg-dark-600 dark:text-gray-300 dark:hover:bg-dark-500"
        >
          {{ t('common.close') }}
        </button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import LoadingSpinner from '@/components/common/LoadingSpinner.vue'
import Icon from '@/components/icons/Icon.vue'
import { adminAPI } from '@/api/admin'
import { useClipboard } from '@/composables/useClipboard'
import { useAppStore } from '@/stores/app'
import type { Account } from '@/types'
import type { AccountEffectiveModelMappingResponse } from '@/api/admin/accounts'

interface MappingRow {
  from: string
  to: string
  source: 'custom' | 'default'
}

interface EditableMappingRow {
  from: string
  to: string
}

const props = defineProps<{
  show: boolean
  account: Account | null
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'restored'): void
  (e: 'updated'): void
}>()

const { t } = useI18n()
const appStore = useAppStore()
const { copyToClipboard } = useClipboard()

const loadingMapping = ref(false)
const restoringMapping = ref(false)
const savingMapping = ref(false)
const editingMapping = ref(false)
const effectiveMappingResponse = ref<AccountEffectiveModelMappingResponse | null>(null)
const editableRows = ref<EditableMappingRow[]>([])

const mappingRows = computed<MappingRow[]>(() => {
  const response = effectiveMappingResponse.value
  if (!response) {
    return []
  }
  // source=none 表示账号使用平台默认映射，
  // backend 在 GetAccountEffectiveModelMapping 中已将平台默认映射写入 response.mapping，直接展示即可。
  const source: 'custom' | 'default' = response.source === 'custom' ? 'custom' : 'default'
  return Object.entries(response.mapping)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([from, to]) => ({ from, to, source }))
})

const deprecatedWarnings = computed(() => {
  const warnings = effectiveMappingResponse.value?.deprecated_warnings ?? []
  return warnings.filter((warning) => warning.deprecated_model.trim() === warning.to.trim())
})

const showDefaultHint = computed(() => {
  const src = effectiveMappingResponse.value?.source
  // none / default 都表示正在使用平台默认映射
  return props.account?.platform === 'antigravity' && (src === 'default' || src === 'none')
})

const canRestoreDefault = computed(() => effectiveMappingResponse.value?.source === 'custom')
const canEditMapping = computed(() => {
  const source = effectiveMappingResponse.value?.source
  return source === 'custom' || source === 'default' || source === 'none'
})

const mappingJsonText = computed(() => {
  const response = effectiveMappingResponse.value
  if (!response) {
    return '{}'
  }

  const sortedEntries = Object.entries(response.mapping).sort(([a], [b]) => a.localeCompare(b))
  return JSON.stringify(Object.fromEntries(sortedEntries), null, 2)
})

const loadEffectiveMapping = async () => {
  if (!props.show || !props.account) {
    return
  }

  effectiveMappingResponse.value = null
  editingMapping.value = false
  editableRows.value = []
  loadingMapping.value = true
  try {
    effectiveMappingResponse.value = await adminAPI.accounts.getEffectiveModelMapping(props.account.id)
  } catch (error) {
    console.error('Failed to load effective model mapping:', error)
    effectiveMappingResponse.value = null
    appStore.showError(t('admin.accounts.loadMappingFailed'))
  } finally {
    loadingMapping.value = false
  }
}

watch(
  () => [props.show, props.account?.id] as const,
  () => {
    if (!props.show) {
      effectiveMappingResponse.value = null
      return
    }
    loadEffectiveMapping()
  },
  { immediate: true }
)

const handleClose = () => {
  emit('close')
}

const startEditMapping = () => {
  if (!canEditMapping.value) {
    return
  }

  editableRows.value = mappingRows.value.map((row) => ({
    from: row.from,
    to: row.to
  }))

  if (editableRows.value.length === 0) {
    editableRows.value.push({ from: '', to: '' })
  }

  editingMapping.value = true
}

const cancelEditMapping = () => {
  editingMapping.value = false
  editableRows.value = []
}

const addEditableRow = () => {
  editableRows.value.push({ from: '', to: '' })
}

const removeEditableRow = (index: number) => {
  editableRows.value.splice(index, 1)
}

const handleSaveMapping = async () => {
  if (!props.account || !editingMapping.value) {
    return
  }

  const mapping: Record<string, string> = {}
  for (const row of editableRows.value) {
    const from = row.from.trim()
    const to = row.to.trim()
    if (!from || !to) {
      continue
    }
    mapping[from] = to
  }

  if (Object.keys(mapping).length === 0) {
    appStore.showError(t('admin.accounts.mappingEditEmptyError'))
    return
  }

  savingMapping.value = true
  try {
    await adminAPI.accounts.update(props.account.id, {
      credentials: {
        ...(props.account.credentials ?? {}),
        model_mapping: mapping
      }
    })

    appStore.showSuccess(t('admin.accounts.mappingEditSaved'))
    editingMapping.value = false
    editableRows.value = []
    emit('updated')
    await loadEffectiveMapping()
  } catch (error) {
    console.error('Failed to save model mapping:', error)
    appStore.showError(t('admin.accounts.mappingEditSaveFailed'))
  } finally {
    savingMapping.value = false
  }
}

const handleCopyMappingJson = async () => {
  if (mappingRows.value.length === 0) {
    return
  }
  await copyToClipboard(mappingJsonText.value, t('admin.accounts.mappingJsonCopied'))
}

const handleRestoreDefaultMapping = async () => {
  if (!props.account || !canRestoreDefault.value || savingMapping.value) {
    return
  }

  restoringMapping.value = true
  try {
    effectiveMappingResponse.value = await adminAPI.accounts.restoreDefaultModelMapping(props.account.id)
    appStore.showSuccess(t('admin.accounts.restoreDefaultMappingSuccess'))
    emit('restored')
  } catch (error) {
    console.error('Failed to restore default mapping:', error)
    appStore.showError(t('admin.accounts.restoreDefaultMappingFailed'))
  } finally {
    restoringMapping.value = false
  }
}
</script>
