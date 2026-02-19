import { refreshRequestViewer } from "./request_viewer";
import { refreshCookies } from "./cookies";

export function initOptionsNavigation() {
  const navItems = document.querySelectorAll(".nav-item");

  function activateView(view) {
    if (!view) return;

    const btn = document.querySelector(`.nav-item[data-view="${view}"]`);
    if (!btn) return;

    // Update sidebar active state
    navItems.forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");

    // Hide all views
    document.querySelectorAll(".view-section").forEach((v) => {
      v.classList.add("hidden");
      v.classList.remove("active");
    });

    // Show target view
    const target = document.getElementById(`view-${view}`);
    if (!target) {
      console.warn("Missing view:", view);
      return;
    }

    target.classList.remove("hidden");
    target.classList.add("active");

    // Lazy load
    if (view === "dashboard") {
      refreshRequestViewer();
    } else if (view === "cookies") {
      refreshCookies();
    }
  }

  // Click handler
  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      activateView(btn.dataset.view);
    });
  });

  // Auto-open tab from URL
  const params = new URLSearchParams(window.location.search);
  const tab = params.get("tab");

  if (tab) {
    activateView(tab);
  }
}
