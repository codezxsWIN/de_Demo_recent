// Smooth connections first; obstacle-aware lanes remain the fallback for custom layouts.
export const moduleBox = node => ({left: node.x - 95, right: node.x + 95, top: node.y - 48, bottom: node.y + 142});
export const moduleObstacles = node => [
  {left: node.x - 52, right: node.x + 52, top: node.y - 52, bottom: node.y + 52},
  {left: node.x - 95, right: node.x + 95, top: node.y + 56, bottom: node.y + 142},
];
const key = edge => `${edge.from}:${edge.to}`;
const distance = (a, b) => Math.abs(a.x - b.x) + Math.abs(a.y - b.y);

export function segmentHitsBox(a, b, box) {
  let low = 0, high = 1;
  for (const [axis, min, max] of [['x', box.left, box.right], ['y', box.top, box.bottom]]) {
    const delta = b[axis] - a[axis];
    if (delta === 0) { if (a[axis] <= min || a[axis] >= max) return false; continue; }
    const values = [(min - a[axis]) / delta, (max - a[axis]) / delta].sort((x,y) => x-y);
    low = Math.max(low, values[0]); high = Math.min(high, values[1]);
    if (low >= high) return false;
  }
  return low < high;
}

function smoothConnection(from, to, nodes, nodePorts) {
  // Include endpoint captions: a curve must not depart through its own title.
  const boxes = nodes.flatMap(node => moduleObstacles(node).map((b,i) => {
    const pad = i === 0 && [from.id,to.id].includes(node.id) ? 0 : 12;
    return {left:b.left-pad,right:b.right+pad,top:b.top-pad,bottom:b.bottom+pad};
  }));
  let best = null;
  for (const a of nodePorts.get(from.id)) for (const b of nodePorts.get(to.id)) {
    const span = distance(a.point, b.point);
    const gap = Math.abs(b.point.x-a.point.x);
    const handles = [[.25,.75],[.75,.25],[.45,.45]].map(([a,b]) => [Math.max(24,gap*a),Math.max(24,gap*b)]);
    handles.push([Math.max(64,Math.min(260,span*.4)),Math.max(64,Math.min(260,span*.4))]);
    for (const [reachA,reachB] of handles) {
      const vector = side => side === 'E' ? {x:1,y:0} : side === 'W' ? {x:-1,y:0} : {x:0,y:-1};
      const av = vector(a.side), bv = vector(b.side);
      const c1 = {x:a.point.x+av.x*reachA,y:a.point.y+av.y*reachA};
      const c2 = {x:b.point.x+bv.x*reachB,y:b.point.y+bv.y*reachB};
      const points = Array.from({length:161}, (_, i) => {
        const t=i/160, u=1-t;
        return {x:u*u*u*a.point.x+3*u*u*t*c1.x+3*u*t*t*c2.x+t*t*t*b.point.x,
          y:u*u*u*a.point.y+3*u*u*t*c1.y+3*u*t*t*c2.y+t*t*t*b.point.y};
      });
      if (points.some((point,i) => i && boxes.some(box => segmentHitsBox(points[i-1],point,box)))) continue;
      const length = points.slice(1).reduce((sum,p,i) => sum + distance(points[i],p),0);
      const cost = length + (a.side !== 'E' ? 700 : 0) + (b.side !== 'W' ? 180 : 0);
      if (!best || cost < best.cost) best = {points, cost, clear:true, kind:'curve',
        path:`M${a.point.x},${a.point.y} C${c1.x},${c1.y} ${c2.x},${c2.y} ${b.point.x},${b.point.y}`};
    }
  }
  return best;
}

function ports(node, size) {
  return [
    {side: 'E', point: {x: node.x + 52, y: node.y}, gate: {x: node.x + 76, y: node.y}},
    {side: 'W', point: {x: node.x - 52, y: node.y}, gate: {x: node.x - 76, y: node.y}},
    {side: 'N', point: {x: node.x, y: node.y - 52}, gate: {x: node.x, y: node.y - 68}},
  ].filter(port => port.gate.x > 0 && port.gate.x < size.width && port.gate.y > 0 && port.gate.y < size.height);
}

class Heap {
  items = [];
  push(item) {
    const a = this.items; let i = a.length; a.push(item);
    while (i > 0) { const p = (i - 1) >> 1; if (a[p].rank <= item.rank) break; a[i] = a[p]; i = p; }
    a[i] = item;
  }
  pop() {
    const a = this.items; const first = a[0]; const last = a.pop();
    if (a.length) {
      let i = 0;
      while (i * 2 + 1 < a.length) {
        let child = i * 2 + 1;
        if (child + 1 < a.length && a[child + 1].rank < a[child].rank) child++;
        if (a[child].rank >= last.rank) break;
        a[i] = a[child]; i = child;
      }
      a[i] = last;
    }
    return first;
  }
}

function simplify(points) {
  const result = [];
  for (const point of points) {
    if (result.length && distance(result.at(-1), point) === 0) continue;
    if (result.length > 1) {
      const a = result.at(-2), b = result.at(-1);
      if ((a.x === b.x && b.x === point.x) || (a.y === b.y && b.y === point.y)) result.pop();
    }
    result.push(point);
  }
  return result;
}

export function routePath(points, radius = 8) {
  if (!points.length) return '';
  let path = `M${points[0].x},${points[0].y}`;
  for (let i = 1; i < points.length - 1; i++) {
    const a = points[i - 1], b = points[i], c = points[i + 1];
    const r = Math.min(radius, distance(a, b) / 2, distance(b, c) / 2);
    const before = {x: b.x + Math.sign(a.x - b.x) * r, y: b.y + Math.sign(a.y - b.y) * r};
    const after = {x: b.x + Math.sign(c.x - b.x) * r, y: b.y + Math.sign(c.y - b.y) * r};
    path += ` L${before.x},${before.y} Q${b.x},${b.y} ${after.x},${after.y}`;
  }
  const end = points.at(-1);
  return `${path} L${end.x},${end.y}`;
}

export function routeConnections(nodes, edges, size) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const overlapping = new Set();
  for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
    const collides = moduleObstacles(nodes[i]).some(a => moduleObstacles(nodes[j]).some(b => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top));
    if (collides) {overlapping.add(nodes[i].id); overlapping.add(nodes[j].id);}
  }
  const boxes = nodes.flatMap(moduleObstacles).map(b => ({left: b.left - 12, right: b.right + 12, top: b.top - 12, bottom: b.bottom + 12}));
  const nodePorts = new Map(nodes.map(node => [node.id, ports(node, size)]));
  const allPorts = [...nodePorts.values()].flat();
  const xs = [...new Set([12, size.width - 12, ...nodes.flatMap(node => [node.x - 115, node.x, node.x + 115]), ...allPorts.map(port => port.gate.x)])].filter(x => x > 0 && x < size.width).sort((a, b) => a - b);
  const ys = [...new Set([12, size.height - 12, ...nodes.flatMap(node => [node.y - 68, node.y, node.y + 142]), ...allPorts.map(port => port.gate.y)])].filter(y => y > 0 && y < size.height).sort((a, b) => a - b);
  const width = xs.length;
  const coordinates = Array.from({length: width * ys.length}, (_, index) => ({x: xs[index % width], y: ys[Math.floor(index / width)]}));
  const blocked = coordinates.map(p => boxes.some(b => p.x > b.left && p.x < b.right && p.y > b.top && p.y < b.bottom));
  const segmentKey = (a, b) => a < b ? `${a}:${b}` : `${b}:${a}`;
  const adjacent = coordinates.map((p, id) => {
    if (blocked[id]) return [];
    const x = id % width, y = Math.floor(id / width);
    return [[x - 1, y], [x + 1, y], [x, y - 1], [x, y + 1]].filter(([nx, ny]) => nx >= 0 && nx < width && ny >= 0 && ny < ys.length).map(([nx, ny]) => ny * width + nx).filter(next => {
      if (blocked[next]) return false;
      const q = coordinates[next];
      return !boxes.some(b => p.x === q.x
        ? p.x > b.left && p.x < b.right && Math.max(p.y, q.y) > b.top && Math.min(p.y, q.y) < b.bottom
        : p.y > b.top && p.y < b.bottom && Math.max(p.x, q.x) > b.left && Math.min(p.x, q.x) < b.right);
    });
  });
  const occupied = new Map();
  const crossing = new Map();
  const result = new Map();
  const locate = point => ys.indexOf(point.y) * width + xs.indexOf(point.x);

  function search(start, end) {
    const source = locate(start), target = locate(end);
    if (blocked[source] || blocked[target]) return null;
    const costs = new Map([[source * 3 + 2, 0]]);
    const parents = new Map(); const heap = new Heap();
    heap.push({id: source, direction: 2, cost: 0, rank: distance(start, end)});
    while (heap.items.length) {
      const entry = heap.pop(); const state = entry.id * 3 + entry.direction;
      if (entry.cost !== costs.get(state)) continue;
      if (entry.id === target) {
        const ids = []; let current = state;
        while (current !== undefined) {ids.push(Math.floor(current / 3)); current = parents.get(current);}
        return ids.reverse();
      }
      for (const next of adjacent[entry.id]) {
        const direction = coordinates[next].x === coordinates[entry.id].x ? 1 : 0;
        const bend = entry.direction !== 2 && direction !== entry.direction ? 28 : 0;
        const congestion = (occupied.get(segmentKey(entry.id, next)) || 0) * 12;
        const crosses = (crossing.get(`${next}:${1 - direction}`) || 0) * 36;
        const cost = entry.cost + distance(coordinates[entry.id], coordinates[next]) + bend + congestion + crosses;
        const nextState = next * 3 + direction;
        if (cost >= (costs.get(nextState) ?? Infinity)) continue;
        costs.set(nextState, cost); parents.set(nextState, state);
        heap.push({id: next, direction, cost, rank: cost + distance(coordinates[next], end)});
      }
    }
    return null;
  }

  const ordered = [...edges].sort((a, b) => distance(byId.get(a.from), byId.get(a.to)) - distance(byId.get(b.from), byId.get(b.to)) || key(a).localeCompare(key(b)));
  for (const edge of ordered) {
    const from = byId.get(edge.from), to = byId.get(edge.to);
    if (edge.from === 'canonical' && edge.to === 'report' && !overlapping.has(edge.from) && !overlapping.has(edge.to)) {
      const points = [{x:from.x,y:from.y-52},{x:from.x,y:64},{x:to.x,y:64},{x:to.x,y:to.y-52}];
      const obstacles = nodes.filter(node => ![from.id,to.id].includes(node.id)).flatMap(moduleObstacles);
      if (!points.some((p,i) => i && obstacles.some(box => segmentHitsBox(points[i-1],p,box)))) {
        result.set(key(edge),{points,path:routePath(points,64),clear:true,kind:'lane'}); continue;
      }
    }
    if (!overlapping.has(edge.from) && !overlapping.has(edge.to)) {
      const smooth = smoothConnection(from, to, nodes, nodePorts);
      if (smooth) { result.set(key(edge), smooth); continue; }
    }
    const east = to.x >= from.x;
    const aPorts = [...nodePorts.get(edge.from)].sort((a, b) => Number(b.side === (east ? 'E' : 'W')) - Number(a.side === (east ? 'E' : 'W')));
    const targetSide = Math.abs(to.x - from.x) < 160 ? to.y > from.y ? 'N' : 'E' : east ? 'W' : 'E';
    const bPorts = [...nodePorts.get(edge.to)].sort((a, b) => Number(b.side === targetSide) - Number(a.side === targetSide));
    let route = null;
    for (const a of aPorts) {
      if (overlapping.has(edge.from) || overlapping.has(edge.to)) break;
      for (const b of bPorts) {
        const ids = search(a.gate, b.gate);
        if (!ids) continue;
        const points = simplify([a.point, a.gate, ...ids.map(id => coordinates[id]), b.gate, b.point]);
        route = {points, path: routePath(points), clear: true};
        for (let i = 1; i < ids.length; i++) {
          const segment = segmentKey(ids[i - 1], ids[i]);
          occupied.set(segment, (occupied.get(segment) || 0) + 1);
          const direction = coordinates[ids[i - 1]].x === coordinates[ids[i]].x ? 1 : 0;
          crossing.set(`${ids[i]}:${direction}`, (crossing.get(`${ids[i]}:${direction}`) || 0) + 1);
        }
        break;
      }
      if (route) break;
    }
    // Overlapping custom node positions can make a clear route impossible.
    // Keep the relationship visible and explicitly flag it instead of hiding it.
    if (!route) {
      const points = [{x: from.x + 52, y: from.y}, {x: to.x - 52, y: from.y}, {x: to.x - 52, y: to.y}];
      route = {points, path: routePath(points), clear: false};
    }
    result.set(key(edge), route);
  }
  return result;
}
