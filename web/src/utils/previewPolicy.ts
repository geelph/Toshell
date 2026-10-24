// 文件预览规则（前端）。清单以服务端 /api/v1/files/preview-policy 为权威，
// 服务端会对预览请求做二次校验（前端限制不是安全边界）。
// 这里的内置清单只是"拿不到服务端策略"时的兜底，必须与
// internal/common/preview 保持同款；服务端可达时会被覆盖。

export type PreviewCategory =
  | 'text'
  | 'image'
  | 'executable'
  | 'archive'
  | 'database'
  | 'unknown'

export interface PreviewPolicy {
  text_extensions: string[]
  image_extensions: string[]
  executable_extensions: string[]
  archive_extensions: string[]
  database_extensions: string[]
  max_inline_bytes: number
  oversize_preview_bytes: number
  max_unknown_preview_bytes: number
  max_image_preview_bytes: number
  max_source_bytes: number
  unknown_message?: string
  blocked_message?: string
  force_read_only_note?: string
  note?: string
}

export interface PreviewDecision {
  allowed: boolean
  category: PreviewCategory
  ext: string
  code: string
  message: string
  requiresConfirmation: boolean
  downloadOnly: boolean
  truncated: boolean
  previewBytes: number
}

export const DEFAULT_PREVIEW_POLICY: PreviewPolicy = {
  text_extensions: [
    'asc', 'bash', 'bat', 'c', 'cc', 'cer', 'cfg', 'cjs', 'cmd', 'conf',
    'cpp', 'crt', 'csr', 'css', 'csv', 'cxx', 'diff', 'dockerfile', 'env',
    'gitignore', 'go', 'gradle', 'h', 'hpp', 'htm', 'html', 'ini', 'java',
    'js', 'json', 'jsx', 'key', 'less', 'log', 'lua', 'makefile', 'md',
    'mjs', 'patch', 'pem', 'php', 'pl', 'properties', 'ps1', 'psm1', 'pub',
    'py', 'rb', 'rs', 'rtf', 'sass', 'scss', 'sh', 'sql', 'svelte', 'tex',
    'toml', 'ts', 'tsv', 'tsx', 'txt', 'vue', 'xml', 'yaml', 'yml', 'zsh',
  ],
  image_extensions: ['bmp', 'gif', 'jpeg', 'jpg', 'png', 'webp'],
  executable_extensions: [
    'a', 'apk', 'bin', 'class', 'com', 'cpl', 'deb', 'dll', 'drv', 'dylib',
    'elf', 'exe', 'img', 'iso', 'jar', 'ko', 'lib', 'msi', 'o', 'obj', 'ocx',
    'ps1exe', 'pyc', 'pyo', 'rpm', 'scr', 'so', 'sys', 'vhd', 'vhdx',
    'vmdk', 'wasm',
  ],
  archive_extensions: [
    '7z', 'ace', 'arj', 'bz2', 'cab', 'gz', 'iso9660', 'lz', 'lzma', 'rar',
    'tar', 'tgz', 'xz', 'z', 'zip', 'zst',
  ],
  database_extensions: [
    'accdb', 'db', 'dmp', 'edb', 'frm', 'ibd', 'kdbx', 'ldf', 'mdb', 'mdf',
    'myd', 'myi', 'ndf', 'ost', 'pst', 'sqlite', 'sqlite3',
  ],
  max_inline_bytes: 1024 * 1024,
  oversize_preview_bytes: 64 * 1024,
  max_unknown_preview_bytes: 8 * 1024,
  max_image_preview_bytes: 2 * 1024 * 1024,
  max_source_bytes: 64 * 1024 * 1024,
  unknown_message: '该后缀不在预览白名单，可能是二进制文件；建议下载后在本地查看。',
  blocked_message: '该文件属于可执行/压缩包/数据库类型，不提供内联预览；请下载后在本地查看。',
  force_read_only_note: '强制预览只读：内容按纯文本渲染，不执行、不内联为 HTML/SVG。',
  note: '清单由服务端 /api/v1/files/preview-policy 下发；服务端会二次校验。',
}

let currentPolicy: PreviewPolicy = DEFAULT_PREVIEW_POLICY
let policyPromise: Promise<PreviewPolicy> | null = null

export function getPreviewPolicy(): PreviewPolicy {
  return currentPolicy
}

/** 拉取服务端策略（失败时保留内置兜底，不阻塞文件列表）。 */
export async function ensurePreviewPolicy(): Promise<PreviewPolicy> {
  if (policyPromise) return policyPromise
  policyPromise = (async () => {
    try {
      const token = localStorage.getItem('toshell-token')
      const resp = await fetch('/api/v1/files/preview-policy', {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!resp.ok) return currentPolicy
      const data = (await resp.json()) as Partial<PreviewPolicy>
      const merged: PreviewPolicy = { ...DEFAULT_PREVIEW_POLICY }
      for (const key of [
        'text_extensions', 'image_extensions', 'executable_extensions',
        'archive_extensions', 'database_extensions',
      ] as const) {
        const v = data[key]
        if (Array.isArray(v) && v.length > 0) merged[key] = v.map(String)
      }
      for (const key of [
        'max_inline_bytes', 'oversize_preview_bytes', 'max_unknown_preview_bytes',
        'max_image_preview_bytes', 'max_source_bytes',
      ] as const) {
        const v = data[key]
        if (typeof v === 'number' && v > 0) merged[key] = v
      }
      if (typeof data.unknown_message === 'string' && data.unknown_message) {
        merged.unknown_message = data.unknown_message
      }
      if (typeof data.blocked_message === 'string' && data.blocked_message) {
        merged.blocked_message = data.blocked_message
      }
      currentPolicy = merged
    } catch {
      // 老服务端没有该接口 / 网络失败：保持内置清单
    }
    return currentPolicy
  })()
  return policyPromise
}

/** 测试/会话切换用：重置为内置清单。 */
export function resetPreviewPolicy(): void {
  currentPolicy = DEFAULT_PREVIEW_POLICY
  policyPromise = null
}

export function extOf(name: string): string {
  const trimmed = name.replace(/\.+$/, '')
  const idx = trimmed.lastIndexOf('.')
  if (idx < 0 || idx === trimmed.length - 1) return ''
  return trimmed.slice(idx + 1).toLowerCase()
}

function toSet(list: string[]): Set<string> {
  return new Set(list.map((e) => e.toLowerCase()))
}

let cachedSets: {
  policy: PreviewPolicy
  text: Set<string>
  image: Set<string>
  executable: Set<string>
  archive: Set<string>
  database: Set<string>
} | null = null

function setsFor(policy: PreviewPolicy) {
  if (cachedSets && cachedSets.policy === policy) return cachedSets
  cachedSets = {
    policy,
    text: toSet(policy.text_extensions),
    image: toSet(policy.image_extensions),
    executable: toSet(policy.executable_extensions),
    archive: toSet(policy.archive_extensions),
    database: toSet(policy.database_extensions),
  }
  return cachedSets
}

export function classifyExt(name: string, policy: PreviewPolicy = currentPolicy): PreviewCategory {
  const ext = extOf(name)
  if (!ext) return 'unknown'
  const s = setsFor(policy)
  if (s.text.has(ext)) return 'text'
  if (s.image.has(ext)) return 'image'
  if (s.executable.has(ext)) return 'executable'
  if (s.archive.has(ext)) return 'archive'
  if (s.database.has(ext)) return 'database'
  return 'unknown'
}

export function humanBytes(n: number): string {
  if (n >= 1024 * 1024) return `${Math.round(n / (1024 * 1024))} MB`
  if (n >= 1024) return `${Math.round(n / 1024)} KB`
  return `${n} B`
}

/**
 * 预览判定（与 internal/common/preview.Decide 同规则）。
 * 返回的 message 可直接展示在弹窗里；force 仅对未识别后缀生效。
 */
export function decidePreview(
  name: string,
  size: number,
  force = false,
  policy: PreviewPolicy = currentPolicy,
): PreviewDecision {
  const ext = extOf(name)
  const cat = classifyExt(name, policy)
  const bytes = Number.isFinite(size) && size > 0 ? size : 0
  const base = { category: cat, ext, requiresConfirmation: false, downloadOnly: false, truncated: false }

  if (cat === 'executable' || cat === 'archive' || cat === 'database') {
    const kind =
      cat === 'archive' ? '压缩包' : cat === 'database' ? '数据库/邮件库文件' : '可执行/二进制文件'
    return {
      ...base,
      allowed: false,
      code: 'preview_blocked',
      message: `该${ext ? ' .' + ext.toUpperCase() + ' ' : ''}文件属于${kind}，不提供内联预览（避免浏览器渲染或脚本执行）；请下载后在本地查看。`,
      downloadOnly: true,
      previewBytes: 0,
    }
  }

  if (cat === 'image') {
    if (bytes > policy.max_image_preview_bytes) {
      return {
        ...base,
        allowed: false,
        code: 'preview_too_large',
        message: `该图片超过 ${humanBytes(policy.max_image_preview_bytes)}，内联预览会占用大量传输；请下载后在本地查看。`,
        downloadOnly: true,
        previewBytes: 0,
      }
    }
    return { ...base, allowed: true, code: 'ok', message: '图片预览', previewBytes: bytes }
  }

  if (cat === 'text') {
    if (bytes > policy.max_source_bytes) {
      return {
        ...base,
        allowed: false,
        code: 'preview_too_large',
        message: `文件超过 ${humanBytes(policy.max_source_bytes)}，预览需要完整回传，请下载后在本地查看。`,
        downloadOnly: true,
        previewBytes: 0,
      }
    }
    if (bytes > policy.max_inline_bytes) {
      return {
        ...base,
        allowed: true,
        code: 'ok',
        message: `文件较大（超过 ${humanBytes(policy.max_inline_bytes)}），仅显示前 ${humanBytes(policy.oversize_preview_bytes)}。`,
        truncated: true,
        previewBytes: policy.oversize_preview_bytes,
      }
    }
    return { ...base, allowed: true, code: 'ok', message: '文本预览', previewBytes: bytes }
  }

  // unknown
  if (bytes > policy.max_source_bytes) {
    return {
      ...base,
      allowed: false,
      code: 'preview_too_large',
      message: `文件超过 ${humanBytes(policy.max_source_bytes)}，预览需要完整回传，请下载后在本地查看。`,
      downloadOnly: true,
      previewBytes: 0,
    }
  }
  if (!force) {
    const prefix = ext ? `该后缀（.${ext}）` : '该文件'
    return {
      ...base,
      allowed: false,
      code: 'preview_unknown_ext',
      message: `${prefix}不在预览白名单，可能是二进制文件；建议下载后在本地查看。可仍以只读方式预览前 ${humanBytes(policy.max_unknown_preview_bytes)}（内容不会执行）。`,
      requiresConfirmation: true,
      previewBytes: policy.max_unknown_preview_bytes,
    }
  }
  return {
    ...base,
    allowed: true,
    code: 'preview_forced',
    message: `未识别后缀，已按操作员确认强制只读预览前 ${humanBytes(policy.max_unknown_preview_bytes)}。`,
    truncated: bytes > policy.max_unknown_preview_bytes,
    previewBytes: policy.max_unknown_preview_bytes,
  }
}
