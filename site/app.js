/* Progressive enhancement: clipboard copy for code blocks. */

document.querySelectorAll(".copy-button").forEach((button) => {
  button.addEventListener("click", async () => {
    if (!(button instanceof HTMLButtonElement)) return;
    const text = button.getAttribute("data-copy") ?? "";
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
      button.setAttribute("data-state", "done");
    } catch {
      button.textContent = "Failed";
      button.setAttribute("data-state", "error");
    } finally {
      window.setTimeout(() => {
        button.textContent = original;
        button.removeAttribute("data-state");
      }, 1500);
    }
  });
});
