import styles from './CVEDetail.module.css'

function formatDate(value) {
  if (!value) return 'Unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  })
}

export function CVEDetail({ detail, onClose }) {
  if (!detail?.cve) return null

  const { cve, packageName } = detail

  return (
    <aside className={styles.drawer} aria-label="CVE details">
      <div className={styles.header}>
        <div>
          <h3 className={styles.title}>{cve.cve_id ?? 'Unknown CVE'}</h3>
          <div className={styles.subTitle}>{packageName}</div>
        </div>
        <button type="button" className={styles.closeBtn} onClick={onClose}>
          Close
        </button>
      </div>

      <div className={styles.grid}>
        <div>
          <span className={styles.label}>Severity</span>
          <span className={styles.value}>{cve.severity ?? 'UNKNOWN'}</span>
        </div>
        <div>
          <span className={styles.label}>CVSS</span>
          <span className={styles.value}>{cve.cvss_score ?? 'N/A'}</span>
        </div>
        <div>
          <span className={styles.label}>Disclosed</span>
          <span className={styles.value}>{formatDate(cve.disclosed_at)}</span>
        </div>
        <div>
          <span className={styles.label}>Patched</span>
          <span className={styles.value}>{formatDate(cve.patched_at)}</span>
        </div>
      </div>

      <div className={styles.block}>
        <div className={styles.label}>Summary</div>
        <p className={styles.text}>{cve.summary ?? 'No summary available.'}</p>
      </div>

      <div className={styles.block}>
        <div className={styles.label}>Affected range</div>
        <div className={styles.code}>{cve.affected_range ?? 'Unknown'}</div>
      </div>

      <div className={styles.block}>
        <div className={styles.label}>Patch version</div>
        <div className={styles.code}>{cve.patch_version ?? 'No patch available yet'}</div>
      </div>
    </aside>
  )
}
