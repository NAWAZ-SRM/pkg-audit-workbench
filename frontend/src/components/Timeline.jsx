import { useEffect, useMemo, useRef, useState } from 'react'
import { filterRows, initTimeline, updateDimensions } from '../utils/d3Timeline'
import styles from './Timeline.module.css'

const FILTERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'CLEAN']

export function Timeline({ packages, onCVEClick }) {
  const wrapperRef = useRef(null)
  const svgRef = useRef(null)
  const sentinelRef = useRef(null)
  const [activeFilters, setActiveFilters] = useState(FILTERS)
  const [visibleRows, setVisibleRows] = useState(50)

  const hasData = useMemo(() => Array.isArray(packages) && packages.length > 0, [packages])
  const virtualizedPackages = useMemo(
    () => (packages.length > 50 ? packages.slice(0, visibleRows) : packages),
    [packages, visibleRows],
  )

  useEffect(() => {
    if (packages.length <= 50) {
      setVisibleRows(packages.length)
      return
    }
    setVisibleRows(50)
  }, [packages])

  useEffect(() => {
    if (!svgRef.current) return
    initTimeline(svgRef.current, virtualizedPackages, onCVEClick)
  }, [virtualizedPackages, onCVEClick])

  useEffect(() => {
    if (!svgRef.current) return
    filterRows(activeFilters)
    updateDimensions(svgRef.current, wrapperRef.current?.clientWidth ?? 960)
  }, [activeFilters])

  useEffect(() => {
    if (!wrapperRef.current || !svgRef.current) return undefined

    const observer = new ResizeObserver((entries) => {
      const first = entries[0]
      if (!first || !svgRef.current) return
      updateDimensions(svgRef.current, first.contentRect.width)
    })

    observer.observe(wrapperRef.current)
    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    if (packages.length <= 50 || !sentinelRef.current) return undefined

    const observer = new IntersectionObserver(
      (entries) => {
        const first = entries[0]
        if (!first?.isIntersecting) return
        setVisibleRows((prev) => {
          if (prev >= packages.length) return prev
          return Math.min(prev + 25, packages.length)
        })
      },
      { rootMargin: '150px' },
    )

    observer.observe(sentinelRef.current)
    return () => observer.disconnect()
  }, [packages.length])

  const toggleFilter = (filter) => {
    setActiveFilters((prev) => {
      if (prev.includes(filter)) {
        if (prev.length === 1) return prev
        return prev.filter((item) => item !== filter)
      }
      return [...prev, filter]
    })
  }

  if (!hasData) {
    return <div className={styles.empty}>No packages analysed.</div>
  }

  return (
    <section className={styles.wrapper}>
      <div className={styles.filterBar}>
        {FILTERS.map((filter) => {
          const active = activeFilters.includes(filter)
          return (
            <button
              key={filter}
              type="button"
              className={active ? styles.filterActive : styles.filter}
              onClick={() => toggleFilter(filter)}
            >
              {filter}
            </button>
          )
        })}
      </div>
      <div className={styles.chartWrap} ref={wrapperRef}>
        <svg ref={svgRef} className={styles.chart} />
      </div>
      {packages.length > 50 && (
        <>
          <div className={styles.virtualHint}>
            Showing {virtualizedPackages.length} of {packages.length} packages — scroll to load more
          </div>
          <div ref={sentinelRef} className={styles.sentinel} aria-hidden="true" />
        </>
      )}
    </section>
  )
}
