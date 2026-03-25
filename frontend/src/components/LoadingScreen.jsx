import { useEffect, useRef } from 'react'
import styles from './LoadingScreen.module.css'

const steps = [
  'Uploading file...',
  'Scanning for vulnerabilities...',
  'Fetching package metadata...',
  'Resolving safe versions...',
]

export function LoadingScreen({ step, setStep }) {
  const indexRef = useRef(0)

  useEffect(() => {
    if (!step) {
      setStep(steps[0])
    }

    const timer = window.setInterval(() => {
      indexRef.current = (indexRef.current + 1) % steps.length
      setStep(steps[indexRef.current])
    }, 2500)

    return () => window.clearInterval(timer)
  }, [setStep, step])

  return (
    <div className={styles.wrapper}>
      <div className={styles.card}>
        <h2 className={styles.title}>Analysing your dependencies...</h2>
        <div className={styles.step}>{step ?? 'Uploading file...'}</div>
        <div className={styles.barOuter}>
          <div className={styles.barInner} />
        </div>
      </div>
    </div>
  )
}
