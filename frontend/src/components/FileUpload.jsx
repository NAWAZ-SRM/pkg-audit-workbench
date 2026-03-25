import { useMemo, useState } from 'react'
import styles from './FileUpload.module.css'

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return 'unknown size'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

const MAX_FILE_SIZE_BYTES = 500 * 1024

export function FileUpload({ onAnalyse }) {
  const [selectedFile, setSelectedFile] = useState(null)
  const [inlineError, setInlineError] = useState(null)

  const fileDescription = useMemo(() => {
    if (!selectedFile) return null
    return `${selectedFile.name} (${formatBytes(selectedFile.size)})`
  }, [selectedFile])

  const acceptAndSetFile = (file) => {
    if (!file) return
    const lower = file.name.toLowerCase()
    if (!lower.endsWith('.txt') && !lower.endsWith('.json')) {
      setInlineError('Only requirements.txt and package.json supported')
      setSelectedFile(null)
      return
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setInlineError('File too large. Maximum 500KB supported.')
      setSelectedFile(null)
      return
    }
    setInlineError(null)
    setSelectedFile(file)
  }

  const handleFileChange = (event) => {
    const file = event.target.files?.[0]
    acceptAndSetFile(file)
  }

  const handleDrop = (event) => {
    event.preventDefault()
    const file = event.dataTransfer.files?.[0]
    acceptAndSetFile(file)
  }

  const handleDragOver = (event) => {
    event.preventDefault()
  }

  const handleSubmit = () => {
    if (!selectedFile) {
      setInlineError('Please select a file first.')
      return
    }
    onAnalyse(selectedFile)
  }

  const loadSampleFile = async (samplePath, sampleName) => {
    try {
      const response = await fetch(samplePath)
      const text = await response.text()
      const file = new File([text], sampleName, {
        type: sampleName.endsWith('.json') ? 'application/json' : 'text/plain',
      })
      acceptAndSetFile(file)
    } catch {
      setInlineError('Failed to load sample file.')
    }
  }

  return (
    <div className={styles.wrapper}>
      <div className={styles.card}>
        <div
          className={styles.dropzone}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
        >
          <h1 className={styles.title}>Dependency Vulnerability Timeline</h1>
          <p className={styles.subtitle}>Drop requirements.txt or package.json here</p>
          <div className={styles.buttonRow}>
            <label className={styles.btnSecondary}>
              Choose File
              <input hidden type="file" accept=".txt,.json" onChange={handleFileChange} />
            </label>
            <button type="button" className={styles.btn} onClick={handleSubmit}>
              Analyse Dependencies
            </button>
          </div>
          {fileDescription && <p className={styles.fileInfo}>Selected: {fileDescription}</p>}
          {inlineError && <p className={styles.error}>{inlineError}</p>}
        </div>

        <p className={styles.sampleLabel}>Try sample files</p>
        <div className={styles.buttonRow}>
          <button
            type="button"
            className={styles.btnSecondary}
            onClick={() => loadSampleFile('/samples/sample_requirements.txt', 'requirements.txt')}
          >
            Try sample requirements.txt
          </button>
          <button
            type="button"
            className={styles.btnSecondary}
            onClick={() => loadSampleFile('/samples/sample_package.json', 'package.json')}
          >
            Try sample package.json
          </button>
          <button
            type="button"
            className={styles.btnSecondary}
            onClick={() => loadSampleFile('/samples/sample_conflicting.txt', 'requirements.txt')}
          >
            Try conflicting deps
          </button>
        </div>
      </div>
    </div>
  )
}
