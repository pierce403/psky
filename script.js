// Optional control for the shared-write illustration; content works without JS.
const motionToggle = document.querySelector("#motion-toggle");
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
let pausedByUser = false;

function updateMotion() {
  const paused = pausedByUser || reducedMotion.matches;
  document.documentElement.classList.toggle("motion-paused", paused);
  motionToggle.setAttribute("aria-pressed", String(paused));
  motionToggle.disabled = reducedMotion.matches;
  motionToggle.textContent = reducedMotion.matches
    ? "Motion off (system)"
    : paused
      ? "Resume motion"
      : "Pause motion";
}

if (motionToggle) {
  document.documentElement.classList.add("motion-enabled");
  motionToggle.hidden = false;
  motionToggle.addEventListener("click", () => {
    pausedByUser = !pausedByUser;
    updateMotion();
  });
  reducedMotion.addEventListener("change", updateMotion);
  updateMotion();
}
