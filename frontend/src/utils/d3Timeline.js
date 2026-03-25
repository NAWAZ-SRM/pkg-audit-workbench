import * as d3 from 'd3'

const SEVERITY_COLORS = {
  CRITICAL: '#c0392b',
  HIGH: '#e74c3c',
  MEDIUM: '#e67e22',
  LOW: '#f1c40f',
  UNKNOWN: '#95a5a6',
  CLEAN: '#27ae60',
}

const TRACK_COLORS = {
  clean: '#27ae60',
  unpatched: '#c0392b',
  patched: '#e67e22',
}

const MARGIN = {
  top: 28,
  right: 24,
  bottom: 44,
  left: 220,
}

const ROW_HEIGHT = 48
const MARKER_RADIUS = 7
const COLLAPSE_LIMIT = 5
const COLLAPSE_GAP = 4

let chartState = {
  rows: [],
  activeSeverities: new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'CLEAN']),
  width: 960,
  domainStart: null,
  domainEnd: null,
  xScale: null,
  xAxisBase: null,
  zoomTransform: d3.zoomIdentity,
  expandedRows: new Set(),
  onCVEClick: null,
  zoomBehavior: null,
}

function normalizeSeverity(severity) {
  if (!severity || typeof severity !== 'string') return 'UNKNOWN'
  const upper = severity.toUpperCase()
  return SEVERITY_COLORS[upper] ? upper : 'UNKNOWN'
}

function rowSeverity(report) {
  const vulnerabilities = Array.isArray(report?.vulnerabilities) ? report.vulnerabilities : []
  const top = vulnerabilities
    .map((vuln) => normalizeSeverity(vuln?.severity))
    .sort((a, b) => {
      const priority = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 }
      return (priority[a] ?? 5) - (priority[b] ?? 5)
    })[0]
  return top ?? 'CLEAN'
}

function hasUnpatched(report) {
  const vulnerabilities = Array.isArray(report?.vulnerabilities) ? report.vulnerabilities : []
  return vulnerabilities.some((vuln) => !vuln?.patched_at)
}

function buildRows(data) {
  const safeData = Array.isArray(data) ? data : []

  return safeData.map((report, index) => {
    const packageName = report?.package?.name ?? `package-${index + 1}`
    const vulnerabilities = Array.isArray(report?.vulnerabilities) ? report.vulnerabilities : []

    const events = vulnerabilities
      .filter((vuln) => Boolean(vuln?.disclosed_at))
      .map((vuln, eventIndex) => {
        const disclosedAt = new Date(vuln.disclosed_at)
        const patchedAt = vuln.patched_at ? new Date(vuln.patched_at) : null
        return {
          ...vuln,
          rowId: packageName,
          eventId: `${packageName}-${vuln.cve_id ?? eventIndex}`,
          disclosedDate: disclosedAt,
          patchedDate: patchedAt,
          severity: normalizeSeverity(vuln?.severity),
          isValidDate: !Number.isNaN(disclosedAt.getTime()),
          patchValid: patchedAt ? !Number.isNaN(patchedAt.getTime()) : false,
        }
      })
      .filter((event) => event.isValidDate)
      .sort((a, b) => a.disclosedDate.getTime() - b.disclosedDate.getTime())

    let trackColor = TRACK_COLORS.clean
    if (!report?.is_clean) {
      trackColor = hasUnpatched(report) ? TRACK_COLORS.unpatched : TRACK_COLORS.patched
    }

    return {
      id: packageName,
      name: packageName,
      report,
      severity: rowSeverity(report),
      events,
      isClean: Boolean(report?.is_clean),
      trackColor,
      collapsed: events.length > COLLAPSE_LIMIT,
    }
  })
}

function getDateDomain(rows) {
  const allDates = rows.flatMap((row) => row.events.map((event) => event.disclosedDate))
  const now = new Date()

  if (allDates.length === 0) {
    const start = d3.timeDay.offset(now, -30)
    const end = d3.timeDay.offset(now, 30)
    return { start, end }
  }

  const minDate = d3.min(allDates)
  const start = d3.timeDay.offset(minDate, -30)
  const end = d3.timeDay.offset(now, 30)
  return { start, end }
}

function isRowVisible(row) {
  if (!chartState.activeSeverities.size) return true
  if (row.isClean) return chartState.activeSeverities.has('CLEAN')
  return chartState.activeSeverities.has(row.severity)
}

function getVisibleRows() {
  return chartState.rows.filter((row) => isRowVisible(row))
}

function chartHeight(rowCount) {
  const rowsHeight = Math.max(rowCount * ROW_HEIGHT, ROW_HEIGHT)
  return MARGIN.top + MARGIN.bottom + rowsHeight
}

function labelValue(row) {
  if (row.name.length <= 28) return row.name
  return `${row.name.slice(0, 27)}…`
}

function eventTooltip(event) {
  const disclosure = d3.timeFormat('%b %d, %Y')(event.disclosedDate)
  return `${event.cve_id ?? 'Unknown CVE'} • ${event.severity} • ${disclosure}`
}

function ensureTooltip(root) {
  let tooltip = root.select('div.timeline-tooltip')
  if (tooltip.empty()) {
    tooltip = root
      .append('div')
      .attr('class', 'timeline-tooltip')
      .style('position', 'fixed')
      .style('z-index', '1000')
      .style('pointer-events', 'none')
      .style('padding', '6px 8px')
      .style('border-radius', '6px')
      .style('background', 'rgba(44, 62, 80, 0.95)')
      .style('color', '#fff')
      .style('font-size', '12px')
      .style('opacity', '0')
      .style('transition', 'opacity 120ms ease')
  }
  return tooltip
}

function showTooltip(tooltip, text, pointerEvent) {
  tooltip
    .style('opacity', '1')
    .text(text)
    .style('left', `${pointerEvent.clientX + 10}px`)
    .style('top', `${pointerEvent.clientY + 10}px`)
}

function hideTooltip(tooltip) {
  tooltip.style('opacity', '0')
}

function syncAxis(baseLayer, axisLayer, width) {
  const innerWidth = Math.max(width - MARGIN.left - MARGIN.right, 120)

  chartState.xAxisBase = d3.scaleTime().domain([chartState.domainStart, chartState.domainEnd]).range([0, innerWidth])
  chartState.xScale = chartState.zoomTransform.rescaleX(chartState.xAxisBase)

  axisLayer
    .attr('transform', `translate(${MARGIN.left}, ${MARGIN.top + chartHeight(getVisibleRows().length) - MARGIN.bottom})`)
    .call(d3.axisBottom(chartState.xScale).tickFormat(d3.timeFormat('%b %Y')))

  baseLayer.select('.axis-baseline').attr('x2', innerWidth)
}

function updateRows(svgElement) {
  const svg = d3.select(svgElement)
  const root = d3.select(svgElement.parentElement)
  const tooltip = ensureTooltip(root)

  const visibleRows = getVisibleRows()
  const height = chartHeight(visibleRows.length)
  const width = chartState.width

  svg.attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMinYMin meet').attr('height', height)

  const baseLayer = svg.select('g.timeline-base')
  const axisLayer = svg.select('g.timeline-axis')
  syncAxis(baseLayer, axisLayer, width)

  const rowLayer = baseLayer.select('g.timeline-rows').attr('transform', `translate(${MARGIN.left}, ${MARGIN.top})`)
  const rows = rowLayer.selectAll('g.timeline-row').data(visibleRows, (d) => d.id)

  rows.exit().remove()

  const rowsEnter = rows
    .enter()
    .append('g')
    .attr('class', 'timeline-row')
    .attr('transform', (_d, idx) => `translate(0, ${idx * ROW_HEIGHT})`)

  rowsEnter.append('line').attr('class', 'row-track').attr('x1', 0).attr('x2', 0).attr('y1', ROW_HEIGHT / 2).attr('y2', ROW_HEIGHT / 2).attr('stroke-width', 3)

  rowsEnter
    .append('text')
    .attr('class', 'row-label')
    .attr('x', -12)
    .attr('y', ROW_HEIGHT / 2)
    .attr('dominant-baseline', 'middle')
    .attr('text-anchor', 'end')
    .style('font-size', '12px')
    .style('font-weight', '600')
    .style('fill', '#2c3e50')

  rowsEnter.append('g').attr('class', 'row-events')

  const rowsMerged = rowsEnter.merge(rows)

  rowsMerged.attr('transform', (_d, idx) => `translate(0, ${idx * ROW_HEIGHT})`)

  const innerWidth = Math.max(width - MARGIN.left - MARGIN.right, 120)
  rowsMerged
    .select('line.row-track')
    .attr('x2', innerWidth)
    .attr('stroke', (d) => d.trackColor)

  rowsMerged
    .select('text.row-label')
    .text((d) => labelValue(d))

  rowsMerged
    .select('text.row-label')
    .selectAll('title')
    .data([1])
    .join('title')
    .text((d, idx, nodes) => {
      const row = d3.select(nodes[idx].parentNode).datum()
      return row.name
    })

  rowsMerged.each(function bindEvents(rowData) {
    const rowGroup = d3.select(this).select('g.row-events')
    const shouldCollapse = rowData.collapsed && !chartState.expandedRows.has(rowData.id)

    if (rowData.events.length === 0) {
      rowGroup.selectAll('*').remove()
      return
    }

    if (shouldCollapse) {
      const centerX = d3.mean(rowData.events.map((event) => chartState.xScale(event.disclosedDate))) ?? 0
      const collapseData = [{
        rowId: rowData.id,
        count: rowData.events.length,
        x: centerX,
        severity: rowData.severity,
      }]

      const collapsed = rowGroup.selectAll('g.collapsed-group').data(collapseData, (d) => d.rowId)
      collapsed.exit().remove()

      const collapsedEnter = collapsed.enter().append('g').attr('class', 'collapsed-group').style('cursor', 'pointer')
      collapsedEnter.append('circle').attr('r', 11)
      collapsedEnter.append('text').attr('text-anchor', 'middle').attr('dominant-baseline', 'middle').style('font-size', '10px').style('font-weight', '700').style('fill', '#fff')

      const collapsedMerged = collapsedEnter.merge(collapsed)
      collapsedMerged.attr('transform', (d) => `translate(${d.x}, ${ROW_HEIGHT / 2})`)
      collapsedMerged
        .select('circle')
        .attr('fill', (d) => SEVERITY_COLORS[d.severity] ?? SEVERITY_COLORS.UNKNOWN)
      collapsedMerged.select('text').text((d) => d.count)

      collapsedMerged
        .on('click', (_event, d) => {
          chartState.expandedRows.add(d.rowId)
          updateRows(svgElement)
        })
        .on('mouseenter', (pointerEvent, d) => {
          showTooltip(tooltip, `${d.count} CVEs — click to expand`, pointerEvent)
        })
        .on('mousemove', (pointerEvent, d) => {
          showTooltip(tooltip, `${d.count} CVEs — click to expand`, pointerEvent)
        })
        .on('mouseleave', () => hideTooltip(tooltip))

      rowGroup.selectAll('g.event-group').remove()
      rowGroup.selectAll('g.patch-group').remove()
      return
    }

    rowGroup.selectAll('g.collapsed-group').remove()

    const eventGroups = rowGroup.selectAll('g.event-group').data(rowData.events, (d) => d.eventId)
    eventGroups.exit().remove()

    const eventEnter = eventGroups.enter().append('g').attr('class', 'event-group').style('cursor', 'pointer')

    eventEnter.append('circle').attr('class', 'event-marker').attr('r', MARKER_RADIUS)

    const eventMerged = eventEnter.merge(eventGroups)
    eventMerged.attr('transform', (d, idx) => {
      const xBase = chartState.xScale(d.disclosedDate)
      const jitter = (idx % 3) * COLLAPSE_GAP - COLLAPSE_GAP
      return `translate(${xBase + jitter}, ${ROW_HEIGHT / 2})`
    })

    eventMerged
      .select('circle.event-marker')
      .attr('fill', (d) => (d.patchedDate ? SEVERITY_COLORS[d.severity] : '#ffffff'))
      .attr('stroke', (d) => SEVERITY_COLORS[d.severity])
      .attr('stroke-width', 2)

    eventMerged
      .on('mouseenter', (pointerEvent, d) => {
        showTooltip(tooltip, d.patchedDate ? eventTooltip(d) : `${eventTooltip(d)} • No patch available yet`, pointerEvent)
      })
      .on('mousemove', (pointerEvent, d) => {
        showTooltip(tooltip, d.patchedDate ? eventTooltip(d) : `${eventTooltip(d)} • No patch available yet`, pointerEvent)
      })
      .on('mouseleave', () => hideTooltip(tooltip))
      .on('click', (_pointerEvent, d) => {
        if (typeof chartState.onCVEClick === 'function') {
          chartState.onCVEClick(d, rowData.name)
        }
      })

    const patchData = rowData.events.filter((event) => event.patchValid)
    const patchGroups = rowGroup.selectAll('g.patch-group').data(patchData, (d) => `${d.eventId}-patch`)
    patchGroups.exit().remove()

    const patchEnter = patchGroups.enter().append('g').attr('class', 'patch-group')
    patchEnter.append('path').attr('class', 'patch-marker')

    const patchMerged = patchEnter.merge(patchGroups)
    patchMerged.attr('transform', (d) => `translate(${chartState.xScale(d.patchedDate)}, ${ROW_HEIGHT / 2})`)
    patchMerged
      .select('path.patch-marker')
      .attr('d', d3.symbol().type(d3.symbolTriangle).size(80))
      .attr('fill', (d) => SEVERITY_COLORS[d.severity])
      .attr('opacity', 0.85)

    patchMerged
      .on('mouseenter', (pointerEvent, d) => {
        const patched = d3.timeFormat('%b %d, %Y')(d.patchedDate)
        showTooltip(tooltip, `${d.cve_id ?? 'Unknown CVE'} patched on ${patched}`, pointerEvent)
      })
      .on('mousemove', (pointerEvent, d) => {
        const patched = d3.timeFormat('%b %d, %Y')(d.patchedDate)
        showTooltip(tooltip, `${d.cve_id ?? 'Unknown CVE'} patched on ${patched}`, pointerEvent)
      })
      .on('mouseleave', () => hideTooltip(tooltip))
  })
}

function bindZoomBehavior(svgElement) {
  const svg = d3.select(svgElement)
  const overlay = svg.select('rect.zoom-overlay')

  chartState.zoomBehavior = d3
    .zoom()
    .scaleExtent([1, 10])
    .translateExtent([
      [MARGIN.left, 0],
      [chartState.width - MARGIN.right, 0],
    ])
    .extent([
      [MARGIN.left, 0],
      [chartState.width - MARGIN.right, 0],
    ])
    .on('zoom', (event) => {
      chartState.zoomTransform = event.transform
      updateRows(svgElement)
    })

  overlay.call(chartState.zoomBehavior)
  overlay.call(chartState.zoomBehavior.transform, chartState.zoomTransform)
}

function ensureRoot(svgElement) {
  const svg = d3.select(svgElement)
  svg.attr('width', '100%').attr('role', 'img').attr('aria-label', 'Dependency vulnerability timeline')

  if (svg.select('g.timeline-base').empty()) {
    const baseLayer = svg.append('g').attr('class', 'timeline-base')
    baseLayer.append('line').attr('class', 'axis-baseline').attr('x1', 0).attr('y1', 0).attr('y2', 0).attr('stroke', '#d0d9e2').attr('stroke-width', 1)
    baseLayer.append('g').attr('class', 'timeline-rows')
    svg.append('g').attr('class', 'timeline-axis')
    svg.append('rect').attr('class', 'zoom-overlay').attr('fill', 'transparent')
  }

  const overlay = svg.select('rect.zoom-overlay')
  overlay.attr('x', MARGIN.left).attr('y', MARGIN.top).attr('height', 200)

  bindZoomBehavior(svgElement)
}

function syncZoomOverlay(svgElement) {
  const svg = d3.select(svgElement)
  const visibleCount = getVisibleRows().length
  const h = chartHeight(visibleCount)
  const overlayHeight = Math.max(h - MARGIN.top - MARGIN.bottom, ROW_HEIGHT)
  svg.select('rect.zoom-overlay').attr('height', overlayHeight)
}

export function initTimeline(svgElement, data, onCVEClick) {
  if (!svgElement) return

  chartState.rows = buildRows(data)
  chartState.onCVEClick = onCVEClick
  chartState.expandedRows = new Set()

  const { start, end } = getDateDomain(chartState.rows)
  chartState.domainStart = start
  chartState.domainEnd = end
  chartState.zoomTransform = d3.zoomIdentity

  ensureRoot(svgElement)
  syncZoomOverlay(svgElement)
  updateRows(svgElement)
}

export function filterRows(severities) {
  chartState.activeSeverities = new Set(Array.isArray(severities) ? severities : [])
}

export function updateDimensions(svgElement, newWidth) {
  if (!svgElement) return
  const width = Number.isFinite(newWidth) ? Math.max(Math.floor(newWidth), 480) : 960
  chartState.width = width
  bindZoomBehavior(svgElement)
  syncZoomOverlay(svgElement)
  updateRows(svgElement)
}
