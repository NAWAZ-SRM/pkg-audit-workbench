import { useEffect, useMemo, useState } from 'react'
import { ConflictPanel } from './components/ConflictPanel'
import { CVEDetail } from './components/CVEDetail'
import { FileUpload } from './components/FileUpload'
import { LoadingScreen } from './components/LoadingScreen'
import { ResolutionPanel } from './components/ResolutionPanel'
import { Timeline } from './components/Timeline'
import { useAnalysis } from './hooks/useAnalysis'
import styles from './App.module.css'

function App() {
  const { status, data, error, step, fileName, setStep, analyse, reset } = useAnalysis()
  const [activeTab, setActiveTab] = useState('timeline')
  const [cveDetailState, setCveDetailState] = useState(null)

  const fileLabel = useMemo(() => {
    const name = fileName ?? 'uploaded file'
    if (!data?.ecosystem) return name
    return `${name} • ${String(data.ecosystem).toUpperCase()}`
  }, [data?.ecosystem, fileName])

  useEffect(() => {
    if (status === 'results') {
      setActiveTab('timeline')
    }
  }, [status])

  useEffect(() => {
    if (status !== 'results') {
      setCveDetailState(null)
    }
  }, [status])

  if (status === 'idle') {
    return <FileUpload onAnalyse={analyse} />
  }

  if (status === 'uploading') {
    return <LoadingScreen step={step} setStep={setStep} />
  }

  if (status === 'error') {
    return (
      <div className={styles.errorWrap}>
        <div className={styles.errorCard}>
          <h2>Analysis failed</h2>
          <p>{error}</p>
          <button type="button" className={styles.retry} onClick={reset}>
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.app}>
      <header className={styles.topbar}>
        <div className={styles.topTitle}>{fileLabel}</div>
        <button type="button" className={styles.topButton} onClick={reset}>
          Analyse another
        </button>
      </header>

      <div className={styles.tabs}>
        <button
          type="button"
          className={activeTab === 'timeline' ? styles.activeTab : styles.tab}
          onClick={() => setActiveTab('timeline')}
        >
          Timeline
        </button>
        <button
          type="button"
          className={activeTab === 'conflicts' ? styles.activeTab : styles.tab}
          onClick={() => setActiveTab('conflicts')}
        >
          Conflicts
        </button>
        <button
          type="button"
          className={activeTab === 'resolution' ? styles.activeTab : styles.tab}
          onClick={() => setActiveTab('resolution')}
        >
          Resolution
        </button>
      </div>

      <main className={styles.content}>
        {activeTab === 'timeline' && (
          <Timeline
            packages={data?.packages ?? []}
            onCVEClick={(cve, packageName) => setCveDetailState({ cve, packageName })}
          />
        )}
        {activeTab === 'conflicts' && <ConflictPanel conflicts={data?.conflicts ?? []} />}
        {activeTab === 'resolution' && <ResolutionPanel resolution={data?.resolution ?? null} />}
      </main>

      <CVEDetail detail={cveDetailState} onClose={() => setCveDetailState(null)} />
    </div>
  )
}

export default App
