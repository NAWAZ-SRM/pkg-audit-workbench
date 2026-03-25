import { useMemo, useState } from 'react'
import styles from './ResolutionPanel.module.css'

function toRequirementsTxt(resolution) {
  if (!resolution || !Array.isArray(resolution.packages)) return ''
  return resolution.packages
    .map((pkg) => `${pkg.name}==${pkg.recommended_version}`)
    .join('\n')
}

function toPipInstallCommand(resolution) {
  if (!resolution || !Array.isArray(resolution.packages) || resolution.packages.length === 0) {
    return ''
  }
  const pinned = resolution.packages.map((pkg) => `${pkg.name}==${pkg.recommended_version}`).join(' ')
  return `pip install ${pinned}`
}

function truncateName(name) {
  if (typeof name !== 'string') return ''
  if (name.length <= 40) return name
  return `${name.slice(0, 39)}…`
}

export function ResolutionPanel({ resolution }) {
  const [copiedFormat, setCopiedFormat] = useState(null)

  const requirementsText = useMemo(() => toRequirementsTxt(resolution), [resolution])
  const pipInstallText = useMemo(() => toPipInstallCommand(resolution), [resolution])

  if (!resolution) {
    return <div className={styles.empty}>Resolution unavailable</div>
  }

  const copyRequirements = async () => {
    try {
      await navigator.clipboard.writeText(requirementsText)
      setCopiedFormat('requirements')
      window.setTimeout(() => setCopiedFormat(null), 2000)
    } catch {
      setCopiedFormat(null)
    }
  }

  const copyPipInstall = async () => {
    try {
      await navigator.clipboard.writeText(pipInstallText)
      setCopiedFormat('pip')
      window.setTimeout(() => setCopiedFormat(null), 2000)
    } catch {
      setCopiedFormat(null)
    }
  }

  return (
    <div className={styles.wrapper}>
      <div className={styles.pythonCard}>Recommended Python: {resolution.python_version}</div>

      <div className={styles.statusRow}>
        <span className={resolution.all_cves_resolved ? styles.statusOk : styles.statusBad}>
          {resolution.all_cves_resolved ? 'All CVEs Resolved ✓' : 'All CVEs Resolved ✗'}
        </span>
        <span className={resolution.all_conflicts_resolved ? styles.statusOk : styles.statusBad}>
          {resolution.all_conflicts_resolved
            ? 'All Conflicts Resolved ✓'
            : 'All Conflicts Resolved ✗'}
        </span>
      </div>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Package</th>
              <th>Current</th>
              <th>Recommended</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {resolution.packages?.map((pkg) => (
              <tr key={pkg.name} className={pkg.changed ? styles.changed : ''}>
                <td className={styles.packageCell} title={pkg.name}>
                  {truncateName(pkg.name)}
                </td>
                <td>{pkg.current_version}</td>
                <td>{pkg.recommended_version}</td>
                <td>{pkg.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className={styles.copyRow}>
        <button
          type="button"
          className={styles.copyBtn}
          onClick={copyRequirements}
          disabled={!requirementsText}
        >
          {copiedFormat === 'requirements' ? 'Copied ✓' : 'Copy as requirements.txt'}
        </button>
        <button
          type="button"
          className={styles.copyBtnSecondary}
          onClick={copyPipInstall}
          disabled={!pipInstallText}
        >
          {copiedFormat === 'pip' ? 'Copied ✓' : 'Copy as pip install command'}
        </button>
      </div>
    </div>
  )
}
