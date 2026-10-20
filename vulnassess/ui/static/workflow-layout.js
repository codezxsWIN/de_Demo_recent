// Icon modules include the readable label below their 96px connection centre.
const NODE_HALF_WIDTH = 95;
const NODE_TOP = 48;
const NODE_BOTTOM = 122;

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

export function moveNode(layout, id, x, y, size) {
  return {
    ...layout,
    [id]: {
      x: clamp(Math.round(x), NODE_HALF_WIDTH, size.width - NODE_HALF_WIDTH),
      y: clamp(Math.round(y), NODE_TOP, size.height - NODE_BOTTOM),
    },
  };
}

export function readLayout(raw, specs, size) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const result = {};
  for (const {id} of specs) {
    const point = raw[id];
    if (point && Number.isFinite(point.x) && Number.isFinite(point.y)) {
      result[id] = moveNode({}, id, point.x, point.y, size)[id];
    }
  }
  return result;
}

export function positionNodes(nodes, layout) {
  return nodes.map(node => ({...node, ...(layout[node.id] || {})}));
}

export function pathNodeIds(steps, fallback) {
  const ids = steps.flatMap(step => [step.node, ...(step.edges || []).flatMap(edge => edge.split(':'))]).filter(Boolean);
  return new Set(ids.length ? ids : fallback);
}

const mainConnections = new Set(['scope:nmap', 'nmap:canonical', 'canonical:intel', 'intel:score', 'score:queue', 'queue:report']);

// Filter only the drawing. The dependency graph and every module remain intact.
export function showConnection(edge, selected = '', all = false, running = new Set()) {
  if (all) return true;
  if (selected) return edge.from === selected || edge.to === selected;
  const id = `${edge.from}:${edge.to}`;
  return mainConnections.has(id) || running.has(id);
}
