// Entry point. Routes between the first-run wizard and the code
// panel based on backend state, and owns the global custom right-
// click menu (native menus close the popup on focus).

import { initWizard } from "./wizard.js";
import { initCodePanel } from "./code-panel.js";

const { invoke } = window.__TAURI__.core;

window.addEventListener("DOMContentLoaded", async () => {
  const mainPanel = document.querySelector("#main-panel");
  const wizard = document.querySelector("#wizard");

  try {
    const initialized = await invoke("is_initialized");
    if (initialized) {
      mainPanel.classList.remove("hidden");
      initCodePanel(mainPanel);
    } else {
      wizard.classList.remove("hidden");
      initWizard(wizard);
    }
  } catch (err) {
    console.error("is_initialized failed:", err);
    mainPanel.classList.remove("hidden");
    initCodePanel(mainPanel);
  }

  // Custom right-click menu (native menus close the popup on focus).
  // Copy uses the current selection; Select all targets the visible
  // wizard pane or the code panel's status line — codes themselves
  // are user-select: none.
  const ctxMenu = document.querySelector("#ctx-menu");
  const ctxCopy = document.querySelector("#ctx-copy");
  const ctxSelectAll = document.querySelector("#ctx-select-all");
  const hideCtx = () => ctxMenu.classList.remove("visible");

  document.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const margin = 4;
    const x = Math.min(e.clientX, window.innerWidth - ctxMenu.offsetWidth - margin);
    const y = Math.min(e.clientY, window.innerHeight - ctxMenu.offsetHeight - margin);
    ctxMenu.style.left = `${x}px`;
    ctxMenu.style.top = `${y}px`;
    ctxMenu.classList.add("visible");
  });

  document.addEventListener("click", (e) => {
    if (!ctxMenu.contains(e.target)) hideCtx();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideCtx();
  });

  ctxCopy.addEventListener("click", async () => {
    const text = window.getSelection().toString();
    if (text) {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // Fallback for environments without clipboard API.
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
    }
    hideCtx();
  });

  ctxSelectAll.addEventListener("click", () => {
    const visiblePane =
      document.querySelector(".wizard-pane:not(.hidden)") ||
      document.querySelector(".code-pane:not(.hidden)");
    if (visiblePane) {
      const range = document.createRange();
      range.selectNodeContents(visiblePane);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
    hideCtx();
  });
});
