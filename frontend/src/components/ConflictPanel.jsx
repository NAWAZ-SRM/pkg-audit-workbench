import styles from './ConflictPanel.module.css'

export function ConflictPanel({ conflicts }) {
  const safeConflicts = Array.isArray(conflicts) ? conflicts : []

  const sorted = [...safeConflicts].sort((a, b) => {
    if (a.conflict_type === b.conflict_type) return 0
    if (a.conflict_type === 'python_incompatible') return -1
    return 1
  })

  if (sorted.length === 0) {
    return <div className={styles.empty}>No conflicts detected ✓</div>
  }

  return (
    <div className={styles.wrapper}>
      {sorted.map((conflict, index) => (
        <article
          key={`${conflict.package}-${conflict.required_by}-${conflict.required_specifier}-${index}`}
          className={styles.card}
        >
          <div className={styles.row}>
            <span className={styles.pkg} title={conflict.package}>
              {conflict.package}
            </span>
            <span className={styles.version}>{conflict.installed_version}</span>
          </div>
          <div className={styles.row}>→ required by {conflict.required_by}</div>
          <div className={styles.row}>
            <span className={styles.code}>{conflict.required_specifier}</span>
            <span
              className={
                conflict.conflict_type === 'python_incompatible'
                  ? styles.typePython
                  : styles.typeVersion
              }
            >
              {conflict.conflict_type === 'python_incompatible'
                ? 'Python Incompatible'
                : 'Version Conflict'}
            </span>
          </div>
        </article>
      ))}
    </div>
  )
}
