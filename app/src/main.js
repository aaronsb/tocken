const { invoke } = window.__TAURI__.core;

window.addEventListener("DOMContentLoaded", () => {
  const btn = document.querySelector("#touch-btn");
  const status = document.querySelector("#status");
  const details = document.querySelector("#details-body");
  const ctxMenu = document.querySelector("#ctx-menu");
  const ctxCopy = document.querySelector("#ctx-copy");
  const ctxSelectAll = document.querySelector("#ctx-select-all");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    status.textContent = "Touch your YubiKey now…";
    status.className = "status pending";
    details.textContent = "";
    try {
      const result = await invoke("verify_touch");
      status.textContent = result.message;
      status.className = "status ok";
      details.textContent = JSON.stringify(result, null, 2);
    } catch (err) {
      status.textContent = String(err);
      status.className = "status err";
      details.textContent = String(err);
    } finally {
      btn.disabled = false;
    }
  });

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
    const sel = window.getSelection().toString();
    const text = sel || details.textContent || status.textContent;
    if (text) {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
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
    const range = document.createRange();
    range.selectNodeContents(details);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    hideCtx();
  });
});
