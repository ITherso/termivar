(() => {
  "use strict";

  const initialize = () => {
    const sidebar = document.querySelector(".wy-nav-side");
    const content = document.querySelector(".wy-nav-content-wrap");
    const toggle = document.querySelector(".tmv-nav-toggle");
    const mobile = window.matchMedia("(max-width: 768px)");

    if (!(sidebar instanceof HTMLElement) || !(toggle instanceof HTMLButtonElement)) {
      return;
    }

    sidebar.id = "termivar-navigation";

    const sync = () => {
      const isMobile = mobile.matches;
      const isOpen = isMobile && sidebar.classList.contains("shift");

      toggle.setAttribute("aria-expanded", String(isOpen));
      toggle.setAttribute(
        "aria-label",
        isOpen ? "Close documentation navigation" : "Open documentation navigation",
      );

      if (isMobile && !isOpen) {
        sidebar.setAttribute("aria-hidden", "true");
        sidebar.inert = true;
      } else {
        sidebar.removeAttribute("aria-hidden");
        sidebar.inert = false;
      }
    };

    const syncAfterTheme = () => window.requestAnimationFrame(sync);

    toggle.addEventListener("click", syncAfterTheme);
    sidebar.addEventListener("click", (event) => {
      if (event.target instanceof Element && event.target.closest("a")) {
        syncAfterTheme();
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || !mobile.matches || !sidebar.classList.contains("shift")) {
        return;
      }
      sidebar.classList.remove("shift");
      content?.classList.remove("shift");
      sync();
      toggle.focus();
    });

    if (typeof mobile.addEventListener === "function") {
      mobile.addEventListener("change", sync);
    } else {
      mobile.addListener(sync);
    }

    document
      .querySelectorAll(".wy-menu-vertical li.current > a")
      .forEach((link) => link.setAttribute("aria-current", "page"));
    sync();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
