// SVG icon utilities and definitions (extracted from main.ts)

/** Create an SVG element from attributes (avoids innerHTML for ObsidianReviewBot compliance). */
export type SvgSpec = {
  width: number
  height: number
  viewBox: string
  children: Array<{ tag: string; attrs: Record<string, string> }>
}

export function createSvgIcon(
  parent: HTMLElement,
  svgSpec: SvgSpec,
  attrs?: Record<string, string>
): SVGElement {
  const ns = 'http://www.w3.org/2000/svg'
  const svg = parent.ownerDocument.createElementNS(ns, 'svg')
  svg.setAttribute('width', String(svgSpec.width))
  svg.setAttribute('height', String(svgSpec.height))
  svg.setAttribute('viewBox', svgSpec.viewBox)
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v)
  }
  for (const child of svgSpec.children) {
    const el = parent.ownerDocument.createElementNS(ns, child.tag)
    for (const [k, v] of Object.entries(child.attrs)) el.setAttribute(k, v)
    svg.appendChild(el)
  }
  parent.appendChild(svg)
  return svg
}

// ─── Icon definitions ────────────────────────────────────────────────

export const SVG_HOME_18: SvgSpec = {
  width: 18,
  height: 18,
  viewBox: '0 0 24 24',
  children: [
    {
      tag: 'path',
      attrs: {
        d: 'M12 3l9 8h-3v9h-5v-6h-2v6H6v-9H3l9-8z',
        fill: 'currentColor',
      },
    },
  ],
}

export const SVG_RESET_10: SvgSpec = {
  width: 10,
  height: 10,
  viewBox: '0 0 24 24',
  children: [
    {
      tag: 'path',
      attrs: {
        d: 'M1 4v6h6',
        fill: 'none',
        stroke: 'currentColor',
        'stroke-width': '2.5',
        'stroke-linecap': 'round',
        'stroke-linejoin': 'round',
      },
    },
    {
      tag: 'path',
      attrs: {
        d: 'M3.51 15a9 9 0 105.64-12.28L1 10',
        fill: 'none',
        stroke: 'currentColor',
        'stroke-width': '2.5',
        'stroke-linecap': 'round',
        'stroke-linejoin': 'round',
      },
    },
  ],
}

export const SVG_RESET_11: SvgSpec = {
  width: 11,
  height: 11,
  viewBox: '0 0 24 24',
  children: [
    {
      tag: 'path',
      attrs: {
        d: 'M1 4v6h6',
        fill: 'none',
        stroke: 'currentColor',
        'stroke-width': '2.5',
        'stroke-linecap': 'round',
        'stroke-linejoin': 'round',
      },
    },
    {
      tag: 'path',
      attrs: {
        d: 'M3.51 15a9 9 0 105.64-12.28L1 10',
        fill: 'none',
        stroke: 'currentColor',
        'stroke-width': '2.5',
        'stroke-linecap': 'round',
        'stroke-linejoin': 'round',
      },
    },
  ],
}
