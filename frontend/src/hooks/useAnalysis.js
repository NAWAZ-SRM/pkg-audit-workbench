import { useCallback, useMemo, useState } from 'react'

const rawApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim()

function normalizeApiBaseUrl(value) {
  if (!value) return null
  try {
    const url = new URL(value)
    return `${url.origin}${url.pathname}`.replace(/\/$/, '')
  } catch {
    return null
  }
}

const API_BASE_URL = normalizeApiBaseUrl(rawApiBaseUrl)
const API_BASE_URL_ERROR =
  rawApiBaseUrl && !API_BASE_URL
    ? `Invalid VITE_API_BASE_URL: "${rawApiBaseUrl}". Use format like http://127.0.0.1:8000`
    : null

export function useAnalysis() {
  const [status, setStatus] = useState('idle')
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [step, setStep] = useState(null)
  const [fileName, setFileName] = useState(null)

  const analyse = useCallback(async (file) => {
    setStatus('uploading')
    setError(null)
    setData(null)
    setStep('Uploading file...')
    setFileName(file?.name ?? null)

    if (!API_BASE_URL) {
      setStatus('error')
      setStep(null)
      setError(API_BASE_URL_ERROR ?? 'Network error. Is the backend running?')
      return
    }

    const formData = new FormData()
    formData.append('file', file)

    let healthTimer = null
    const pollHealth = async () => {
      try {
        await fetch(`${API_BASE_URL}/health`)
      } catch {
        return
      }
    }

    healthTimer = window.setInterval(pollHealth, 2000)
    void pollHealth()

    try {
      const response = await fetch(`${API_BASE_URL}/analyse`, {
        method: 'POST',
        body: formData,
      })

      const payload = await response.json().catch(() => ({}))

      if (response.ok) {
        setData(payload)
        setStatus('results')
        setStep(null)
        if (healthTimer) window.clearInterval(healthTimer)
        return
      }

      if (response.status === 400 || response.status === 422) {
        setError(payload?.detail ?? 'Request could not be processed.')
      } else if (response.status === 502) {
        setError('Could not reach dependency databases. Try again shortly.')
      } else if (response.status === 500) {
        setError('Analysis failed internally. Check your file format.')
      } else if (response.status === 413) {
        setError('File too large. Maximum 500KB supported.')
      } else {
        setError(payload?.detail ?? 'Request failed.')
      }

      setStatus('error')
      setStep(null)
      if (healthTimer) window.clearInterval(healthTimer)
    } catch {
      setStatus('error')
      setStep(null)
      setError('Network error. Is the backend running?')
      if (healthTimer) window.clearInterval(healthTimer)
    }
  }, [])

  const reset = useCallback(() => {
    setStatus('idle')
    setData(null)
    setError(null)
    setStep(null)
    setFileName(null)
  }, [])

  return useMemo(
    () => ({
      status,
      data,
      error,
      step,
      fileName,
      setStep,
      analyse,
      reset,
    }),
    [analyse, data, error, fileName, reset, status, step],
  )
}
