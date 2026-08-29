import { useCallback, useRef, useState } from 'react'
import { Upload, ImageIcon, Video, X, AlertCircle, CheckCircle, Loader2 } from 'lucide-react'
import { uploadApi } from '@/api/client'
import { UploadResult } from '@/types'
import { cn } from '@/utils/helpers'

interface Props {
  onUploadComplete: (result: UploadResult, file: File) => void
  onClose: () => void
}

type UploadState = 'idle' | 'uploading' | 'done' | 'error'

const ACCEPTED = {
  image: ['image/jpeg', 'image/png', 'image/webp', 'image/gif'],
  video: ['video/mp4', 'video/quicktime', 'video/webm'],
}
const ALL_ACCEPTED = [...ACCEPTED.image, ...ACCEPTED.video]
const MAX_MB = 25

export default function FileUpload({ onUploadComplete, onClose }: Props) {
  const inputRef                   = useRef<HTMLInputElement>(null)
  const [dragOver, setDragOver]    = useState(false)
  const [state,    setState]       = useState<UploadState>('idle')
  const [progress, setProgress]    = useState(0)
  const [error,    setError]       = useState('')
  const [preview,  setPreview]     = useState<string | null>(null)
  const [fileName, setFileName]    = useState('')

  const handleFile = useCallback(async (file: File) => {
    setError('')

    // Type check
    if (!ALL_ACCEPTED.includes(file.type)) {
      setError('Unsupported file type. Please upload a JPEG, PNG, WebP, GIF, or MP4 file.')
      return
    }

    // Size check
    if (file.size > MAX_MB * 1024 * 1024) {
      setError(`File too large. Maximum size is ${MAX_MB} MB.`)
      return
    }

    setFileName(file.name)
    setState('uploading')
    setProgress(0)

    // Preview for images
    if (ACCEPTED.image.includes(file.type)) {
      const reader = new FileReader()
      reader.onload = e => setPreview(e.target?.result as string)
      reader.readAsDataURL(file)
    }

    try {
      const isVideo  = ACCEPTED.video.includes(file.type)
      const uploader = isVideo ? uploadApi.video : uploadApi.image

      const { data } = await uploader(file, (pct) => setProgress(pct))

      setState('done')
      setProgress(100)

      // Notify parent after brief success flash
      setTimeout(() => onUploadComplete(data as UploadResult, file), 800)
    } catch (err: unknown) {
      const msg = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail || 'Upload failed'
        : 'Upload failed. Please try again.'
      setError(msg)
      setState('error')
    }
  }, [onUploadComplete])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
  }

  return (
    <div className="absolute bottom-full left-0 right-0 mb-2 mx-4 z-10 animate-slide-up">
      <div className="bg-aegis-surface border border-aegis-border rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-aegis-border">
          <div className="flex items-center gap-2">
            <Upload className="w-4 h-4 text-aegis-accent" />
            <span className="text-sm font-medium text-[#e6edf3]">Upload file for analysis</span>
          </div>
          <button onClick={onClose} className="text-aegis-muted hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Drop zone */}
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => state === 'idle' && inputRef.current?.click()}
          className={cn(
            'relative p-6 transition-all',
            state === 'idle' && 'cursor-pointer',
            dragOver && 'bg-aegis-accent/5',
          )}
        >
          <input
            ref={inputRef}
            type="file"
            accept={ALL_ACCEPTED.join(',')}
            onChange={handleInputChange}
            className="hidden"
          />

          {/* Idle */}
          {state === 'idle' && (
            <div className={cn(
              'border-2 border-dashed rounded-xl p-8 text-center transition-colors',
              dragOver ? 'border-aegis-accent bg-aegis-accent/5' : 'border-aegis-border hover:border-aegis-accent/60'
            )}>
              <div className="flex justify-center gap-3 mb-3">
                <ImageIcon className="w-8 h-8 text-aegis-muted" />
                <Video className="w-8 h-8 text-aegis-muted" />
              </div>
              <p className="text-sm text-[#e6edf3] font-medium mb-1">
                Drop an image or video here
              </p>
              <p className="text-xs text-aegis-muted mb-4">or click to browse</p>
              <div className="flex flex-wrap gap-2 justify-center">
                {['QR Code scan', 'Deepfake detection', 'Image analysis'].map(tag => (
                  <span key={tag} className="px-2.5 py-1 rounded-full text-xs border border-aegis-border text-aegis-muted">
                    {tag}
                  </span>
                ))}
              </div>
              <p className="text-xs text-aegis-muted mt-3">
                JPEG, PNG, WebP, GIF, MP4 · Max {MAX_MB} MB
              </p>
            </div>
          )}

          {/* Uploading */}
          {state === 'uploading' && (
            <div className="space-y-4 text-center">
              {preview && (
                <img src={preview} alt="Preview" className="w-24 h-24 object-cover rounded-lg mx-auto border border-aegis-border" />
              )}
              <div className="space-y-2">
                <div className="flex items-center justify-center gap-2 text-sm text-[#e6edf3]">
                  <Loader2 className="w-4 h-4 animate-spin text-aegis-accent" />
                  <span>Uploading {fileName}…</span>
                </div>
                <div className="w-full bg-aegis-border rounded-full h-1.5">
                  <div
                    className="bg-aegis-accent h-1.5 rounded-full transition-all duration-300"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <p className="text-xs text-aegis-muted">{progress}%</p>
              </div>
            </div>
          )}

          {/* Done */}
          {state === 'done' && (
            <div className="flex items-center justify-center gap-3 py-4">
              <CheckCircle className="w-6 h-6 text-green-400" />
              <div>
                <p className="text-sm text-[#e6edf3] font-medium">Upload complete!</p>
                <p className="text-xs text-aegis-muted">Starting analysis…</p>
              </div>
            </div>
          )}

          {/* Error */}
          {state === 'error' && (
            <div className="space-y-3">
              <div className="flex items-start gap-3 bg-red-900/20 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-400">
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
              <button
                onClick={() => { setState('idle'); setError(''); setPreview(null) }}
                className="w-full py-2 text-sm text-aegis-muted hover:text-white border border-aegis-border rounded-lg hover:bg-white/5 transition-colors"
              >
                Try again
              </button>
            </div>
          )}
        </div>

        {/* Capability hint */}
        {state === 'idle' && (
          <div className="px-4 py-3 border-t border-aegis-border bg-aegis-bg/50">
            <div className="grid grid-cols-2 gap-2 text-xs text-aegis-muted">
              <span>📷 QR code → decoded + safety check</span>
              <span>🎭 Photo/video → deepfake detection</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
