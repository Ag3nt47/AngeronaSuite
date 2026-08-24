"""Opt-in, local camera hand controls for ARIA navigation.

The camera is never opened at import time or while this connector is disabled.
When enabled, optional OpenCV + MediaPipe backends produce only a gesture name;
frames and landmarks are neither persisted nor sent over a network.  This layer
has no host-action API.  The GUI maps gestures to navigation, focus, speech
interruption, or cancellation; ARIA WRITE tools still require their normal
explicit confirmation token.
"""
from __future__ import annotations

import importlib.util
import math
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Iterable, Sequence


def _have(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


@dataclass(frozen=True)
class GestureEvent:
    name: str
    confidence: float
    ts: float


def _point(value) -> tuple[float, float, float]:
    if hasattr(value, "x"):
        return float(value.x), float(value.y), float(getattr(value, "z", 0.0))
    seq = tuple(value)
    return float(seq[0]), float(seq[1]), float(seq[2] if len(seq) > 2 else 0.0)


def classify_landmarks(landmarks: Sequence[object]) -> tuple[str, float]:
    """Classify one MediaPipe-compatible 21-landmark hand."""
    if len(landmarks) != 21:
        return "", 0.0
    pts = [_point(value) for value in landmarks]

    def distance(a: int, b: int) -> float:
        return math.dist(pts[a], pts[b])

    palm = max(0.04, distance(0, 9))
    extended = {
        "index": pts[8][1] < pts[6][1] - palm * 0.10,
        "middle": pts[12][1] < pts[10][1] - palm * 0.10,
        "ring": pts[16][1] < pts[14][1] - palm * 0.08,
        "pinky": pts[20][1] < pts[18][1] - palm * 0.06,
    }
    folded_count = sum(not state for state in extended.values())
    thumb_spread = distance(4, 5) > palm * 0.65

    if distance(4, 8) < palm * 0.38:
        return "pinch", 0.94
    if all(extended.values()) and thumb_spread:
        return "open_palm", 0.93
    if extended["index"] and extended["middle"] and not extended["ring"] and not extended["pinky"]:
        return "victory", 0.91
    if extended["index"] and folded_count == 3:
        return "point", 0.89
    thumb_up = (
        pts[4][1] < pts[3][1] - palm * 0.20
        and abs(pts[4][0] - pts[3][0]) < palm * 0.75
    )
    if folded_count == 4 and thumb_up:
        return "thumbs_up", 0.90
    if folded_count == 4 and all(distance(tip, 0) < palm * 1.35 for tip in (8, 12, 16, 20)):
        return "fist", 0.92
    return "", 0.0


class HandControls:
    """Camera worker plus hold/cooldown filtering for deliberate gestures."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        camera_index: int = 0,
        hold_seconds: float = 0.9,
        cooldown_seconds: float = 1.2,
    ) -> None:
        self.enabled = bool(enabled)
        self.camera_index = max(0, min(16, int(camera_index)))
        self.hold_seconds = max(0.2, min(5.0, float(hold_seconds)))
        self.cooldown_seconds = max(0.2, min(10.0, float(cooldown_seconds)))
        self.last_error = ""
        self._events: "queue.Queue[GestureEvent]" = queue.Queue(maxsize=8)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stable_name = ""
        self._stable_since = 0.0
        self._latched_name = ""
        self._last_emitted: dict[str, float] = {}
        self._palm_motion: deque[tuple[float, float]] = deque(maxlen=12)
        self._lock = threading.RLock()

    def capabilities(self) -> dict[str, bool]:
        return {"opencv": _have("cv2"), "mediapipe": _have("mediapipe")}

    def status(self) -> str:
        if not self.enabled:
            return "hand controls: OFF (opt-in)"
        caps = self.capabilities()
        if not all(caps.values()):
            missing = ", ".join(name for name, ready in caps.items() if not ready)
            return f"hand controls: unavailable (missing {missing})"
        if self._thread is not None and self._thread.is_alive():
            return f"hand controls: ON (camera {self.camera_index}, local-only)"
        return "hand controls: ready but not running"

    def start(self) -> bool:
        """Start camera processing only after the explicit enable switch."""
        if not self.enabled:
            self.last_error = "hand controls are disabled"
            return False
        caps = self.capabilities()
        if not all(caps.values()):
            self.last_error = "missing optional packages: " + ", ".join(
                name for name, ready in caps.items() if not ready
            )
            return False
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop.clear()
            worker = threading.Thread(
                target=self._camera_loop, name="AriaHandControls", daemon=True
            )
            self._thread = worker
            try:
                worker.start()
            except Exception as exc:
                self._thread = None
                self.last_error = f"camera worker failed to start: {exc}"
                return False
        return True

    def stop(self) -> None:
        self._stop.set()
        worker = self._thread
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=2.0)
        with self._lock:
            if self._thread is worker and (worker is None or not worker.is_alive()):
                self._thread = None

    def poll(self, limit: int = 4) -> list[GestureEvent]:
        out: list[GestureEvent] = []
        for _ in range(max(0, min(16, int(limit)))):
            try:
                out.append(self._events.get_nowait())
            except queue.Empty:
                break
        return out

    def _emit(self, name: str, confidence: float, now: float) -> GestureEvent | None:
        if now - self._last_emitted.get(name, -10_000.0) < self.cooldown_seconds:
            return None
        event = GestureEvent(name, confidence, now)
        self._last_emitted[name] = now
        try:
            self._events.put_nowait(event)
        except queue.Full:
            try:
                self._events.get_nowait()
            except queue.Empty:
                pass
            try:
                self._events.put_nowait(event)
            except queue.Full:
                return None
        return event

    def process_landmarks(
        self, landmarks: Sequence[object], *, now: float | None = None
    ) -> GestureEvent | None:
        """Feed landmarks through motion, hold, and cooldown filters."""
        stamp = time.monotonic() if now is None else float(now)
        name, confidence = classify_landmarks(landmarks)
        if name != self._latched_name:
            self._latched_name = ""
        if name == "open_palm":
            pts = [_point(value) for value in landmarks]
            palm_x = sum(pts[index][0] for index in (0, 5, 9, 13, 17)) / 5.0
            self._palm_motion.append((stamp, palm_x))
            while self._palm_motion and stamp - self._palm_motion[0][0] > 0.8:
                self._palm_motion.popleft()
            if len(self._palm_motion) >= 3:
                displacement = palm_x - self._palm_motion[0][1]
                if abs(displacement) >= 0.22:
                    self._stable_name = ""
                    self._stable_since = stamp
                    self._palm_motion.clear()
                    event = self._emit(
                        "swipe_right" if displacement > 0 else "swipe_left",
                        min(0.98, 0.80 + abs(displacement) / 2),
                        stamp,
                    )
                    if event is not None:
                        self._latched_name = event.name
                    return event
        else:
            self._palm_motion.clear()

        if not name:
            self._stable_name = ""
            self._stable_since = stamp
            self._latched_name = ""
            return None
        if name == self._latched_name:
            return None
        if name != self._stable_name:
            self._stable_name = name
            self._stable_since = stamp
            return None
        if stamp - self._stable_since < self.hold_seconds:
            return None
        self._stable_since = stamp
        event = self._emit(name, confidence, stamp)
        if event is not None:
            self._latched_name = name
        return event

    def _camera_loop(self) -> None:  # pragma: no cover - hardware dependent
        capture = None
        hands = None
        try:
            import cv2  # type: ignore
            import mediapipe as mp  # type: ignore

            solutions = getattr(mp, "solutions", None)
            if solutions is None or not hasattr(solutions, "hands"):
                raise RuntimeError("installed MediaPipe build has no solutions.hands API")
            capture = cv2.VideoCapture(self.camera_index)
            if not capture.isOpened():
                raise RuntimeError(f"camera {self.camera_index} could not be opened")
            capture.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            capture.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            hands = solutions.hands.Hands(
                static_image_mode=False,
                max_num_hands=1,
                model_complexity=0,
                min_detection_confidence=0.70,
                min_tracking_confidence=0.65,
            )
            while not self._stop.is_set():
                ok, frame = capture.read()
                if not ok:
                    self.last_error = "camera frame capture failed"
                    if self._stop.wait(0.15):
                        break
                    continue
                frame = cv2.flip(frame, 1)
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                result = hands.process(rgb)
                found: Iterable[object] = getattr(result, "multi_hand_landmarks", ()) or ()
                first = next(iter(found), None)
                if first is None:
                    self.process_landmarks((), now=time.monotonic())
                else:
                    self.process_landmarks(first.landmark, now=time.monotonic())
        except Exception as exc:
            self.last_error = f"hand-control camera stopped: {exc}"
        finally:
            if hands is not None:
                try:
                    hands.close()
                except Exception:
                    pass
            if capture is not None:
                try:
                    capture.release()
                except Exception:
                    pass
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None

    def self_test(self) -> tuple[bool, str]:
        try:
            def fixture(kind: str) -> list[tuple[float, float, float]]:
                pts = [(0.5, 0.70, 0.0) for _ in range(21)]
                pts[0] = (0.5, 0.86, 0.0)
                for mcp, pip, tip, x in (
                    (5, 6, 8, 0.38), (9, 10, 12, 0.47),
                    (13, 14, 16, 0.56), (17, 18, 20, 0.65),
                ):
                    pts[mcp] = (x, 0.64, 0.0)
                    pts[pip] = (x, 0.53, 0.0)
                    pts[tip] = (x, 0.72, 0.0)
                pts[3] = (0.33, 0.65, 0.0)
                pts[4] = (0.24, 0.62, 0.0)
                if kind in {"open_palm", "victory", "point"}:
                    names = {"open_palm": (8, 12, 16, 20), "victory": (8, 12), "point": (8,)}[kind]
                    for tip in names:
                        pts[tip] = (pts[tip][0], 0.28, 0.0)
                if kind == "open_palm":
                    pts[4] = (0.16, 0.52, 0.0)
                if kind == "thumbs_up":
                    pts[3] = (0.33, 0.52, 0.0)
                    pts[4] = (0.32, 0.24, 0.0)
                if kind == "pinch":
                    pts[4] = (0.37, 0.29, 0.0)
                    pts[8] = (0.38, 0.28, 0.0)
                return pts

            for expected in ("open_palm", "victory", "point", "thumbs_up", "pinch", "fist"):
                actual, confidence = classify_landmarks(fixture(expected))
                assert actual == expected and confidence >= 0.8, (expected, actual)

            off = HandControls(enabled=False)
            assert not off.start() and "disabled" in off.last_error
            held = HandControls(enabled=True, hold_seconds=0.5, cooldown_seconds=1.0)
            palm = fixture("open_palm")
            assert held.process_landmarks(palm, now=1.0) is None
            event = held.process_landmarks(palm, now=1.6)
            assert event is not None and event.name == "open_palm"
            assert held.process_landmarks(palm, now=1.7) is None
            assert held.poll()[0].name == "open_palm"
            return True, (
                "OK — camera is opt-in; six local gesture classifiers, deliberate "
                "hold, cooldown, bounded event queue, and disabled no-op passed."
            )
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = HandControls().self_test()
    print(f"[hand_controls] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
