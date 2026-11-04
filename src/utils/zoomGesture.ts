export interface Point2D {
  x: number;
  y: number;
}

export interface ZoomTransform {
  scale: number;
  panX: number;
  panY: number;
}

export interface PinchSessionSnapshot {
  startDistance: number;
  startScale: number;
  startPanX: number;
  startPanY: number;
  /** Midpoint relative to stage center at pinch start */
  startRelMidX: number;
  /** Midpoint relative to stage center at pinch start */
  startRelMidY: number;
}

export const MIN_ZOOM_SCALE = 1;
export const MAX_ZOOM_SCALE = 5;
export const DOUBLE_TAP_ZOOM_SCALE = 2.5;
export const ZOOM_ACTIVE_EPSILON = 1.015;

export function getTouchDistance(p1: Point2D, p2: Point2D): number {
  return Math.hypot(p2.x - p1.x, p2.y - p1.y);
}

export function getTouchMidpoint(p1: Point2D, p2: Point2D): Point2D {
  return {
    x: (p1.x + p2.x) / 2,
    y: (p1.y + p2.y) / 2,
  };
}

/**
 * Clamps zoom scale into [MIN_ZOOM_SCALE, MAX_ZOOM_SCALE] and constrains pan offsets
 * so the zoomed book page cannot be dragged completely outside the stage bounds.
 * Automatically snaps near-1x scales back to { scale: 1, panX: 0, panY: 0 }.
 */
export function clampZoomPan(
  rawScale: number,
  rawPanX: number,
  rawPanY: number,
  stageWidth: number,
  stageHeight: number
): ZoomTransform {
  const safeScale = Number.isFinite(rawScale)
    ? Math.min(MAX_ZOOM_SCALE, Math.max(MIN_ZOOM_SCALE, rawScale))
    : 1;

  if (safeScale < ZOOM_ACTIVE_EPSILON) {
    return { scale: 1, panX: 0, panY: 0 };
  }

  const maxPanX = Math.max(0, ((safeScale - 1) * Math.max(1, stageWidth)) / 2);
  const maxPanY = Math.max(0, ((safeScale - 1) * Math.max(1, stageHeight)) / 2);

  const clampedPanX = Math.min(maxPanX, Math.max(-maxPanX, Number.isFinite(rawPanX) ? rawPanX : 0));
  const clampedPanY = Math.min(maxPanY, Math.max(-maxPanY, Number.isFinite(rawPanY) ? rawPanY : 0));

  return {
    scale: Math.round(safeScale * 1000) / 1000,
    panX: Math.round(clampedPanX * 100) / 100,
    panY: Math.round(clampedPanY * 100) / 100,
  };
}

/**
 * Computes the next zoom transform during a two-finger pinch gesture while keeping
 * the book page point under the two-finger midpoint anchored under the user's fingers.
 */
export function computePinchZoomTransform(
  session: PinchSessionSnapshot,
  currentRelMidX: number,
  currentRelMidY: number,
  currentDistance: number,
  stageWidth: number,
  stageHeight: number
): ZoomTransform {
  const safeStartDist = Math.max(12, session.startDistance);
  const ratio = Math.max(0.1, currentDistance) / safeStartDist;
  const nextScale = Math.min(
    MAX_ZOOM_SCALE,
    Math.max(MIN_ZOOM_SCALE, session.startScale * ratio)
  );

  const scaleFactor = nextScale / Math.max(MIN_ZOOM_SCALE, session.startScale);
  const nextPanX = currentRelMidX - (session.startRelMidX - session.startPanX) * scaleFactor;
  const nextPanY = currentRelMidY - (session.startRelMidY - session.startPanY) * scaleFactor;

  return clampZoomPan(nextScale, nextPanX, nextPanY, stageWidth, stageHeight);
}

/**
 * Toggles zoom on double-tap: zooms into DOUBLE_TAP_ZOOM_SCALE centered on the tap point
 * when currently at 1x, or resets back to 1x when already zoomed in.
 */
export function computeDoubleTapZoomTransform(
  current: ZoomTransform,
  tapRelX: number,
  tapRelY: number,
  stageWidth: number,
  stageHeight: number
): ZoomTransform {
  if (current.scale >= ZOOM_ACTIVE_EPSILON) {
    return { scale: 1, panX: 0, panY: 0 };
  }
  const targetScale = DOUBLE_TAP_ZOOM_SCALE;
  const nextPanX = -tapRelX * (targetScale - 1);
  const nextPanY = -tapRelY * (targetScale - 1);
  return clampZoomPan(targetScale, nextPanX, nextPanY, stageWidth, stageHeight);
}
