(function () {
  const root = document.documentElement;
  const button = document.getElementById("theme-toggle");
  const stored = localStorage.getItem("ratshield-theme");

  if (stored === "light" || stored === "dark") {
    root.setAttribute("data-theme", stored);
  }

  function sync() {
    if (!button) return;
    const dark = root.getAttribute("data-theme") !== "light";
    button.textContent = dark ? "Light" : "Dark";
  }

  sync();

  if (button) {
    button.addEventListener("click", function () {
      const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      localStorage.setItem("ratshield-theme", next);
      sync();
    });
  }
})();
