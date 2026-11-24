/* Progressive enhancement: clipboard copy and the local Web Worker analyzer. */

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

const toolSelect = document.getElementById("tool-select");
const fileInput = document.getElementById("file-input");
const file2Input = document.getElementById("file2-input");
const secondFileWrap = document.getElementById("second-file-wrap");
const patternWrap = document.getElementById("pattern-wrap");
const patternInput = document.getElementById("pattern-input");
const runButton = document.getElementById("run-button");
const status = document.getElementById("online-status");
const resultCode = document.getElementById("result-code");
const copyResult = document.getElementById("copy-result");
const downloadResult = document.getElementById("download-result");

if (toolSelect instanceof HTMLSelectElement && fileInput instanceof HTMLInputElement &&
    runButton instanceof HTMLButtonElement && status instanceof HTMLElement && resultCode instanceof HTMLElement) {
  const MAX_BYTES = 64 * 1024 * 1024;
  let worker = null;
  let nextId = 1;
  const pending = new Map();

  const getWorker = () => {
    if (worker) return worker;
    worker = new Worker("worker.js");
    worker.addEventListener("message", (event) => {
      const reply = event.data;
      const resolvePending = pending.get(reply.id);
      if (!resolvePending) return;
      pending.delete(reply.id);
      resolvePending(reply);
    });
    worker.addEventListener("error", () => {
      status.textContent = "The analyzer worker failed. Reload the page and try again.";
      runButton.disabled = false;
    });
    return worker;
  };

  const askWorker = (request) => new Promise((resolve, reject) => {
    try {
      const id = nextId++;
      pending.set(id, resolve);
      getWorker().postMessage({ id, request });
    } catch (error) {
      reject(error);
    }
  });

  const updateVisibility = () => {
    const tool = toolSelect.value;
    if (secondFileWrap instanceof HTMLElement) secondFileWrap.hidden = tool !== "diff";
    if (patternWrap instanceof HTMLElement) patternWrap.hidden = tool !== "find-bytes";
    if (fileInput instanceof HTMLInputElement) fileInput.multiple = false;
    runButton.textContent = tool === "diff" ? "Compare files" : "Analyze file";
  };
  toolSelect.addEventListener("change", updateVisibility);
  updateVisibility();

  const readFile = async (input) => {
    const file = input instanceof HTMLInputElement ? input.files?.[0] : null;
    if (!file) throw new Error("Choose a file first.");
    if (file.size > MAX_BYTES) throw new Error("File exceeds the 64 MB browser cap.");
    return { bytes: new Uint8Array(await file.arrayBuffer()), label: file.name };
  };

  const setStatus = (message) => { status.textContent = message; };

  runButton.addEventListener("click", async () => {
    runButton.disabled = true;
    setStatus("Analyzing locally...");
    try {
      const first = await readFile(fileInput);
      const request = {
        tool: toolSelect.value,
        bytes: first.bytes,
        label: first.label,
        arg: patternInput instanceof HTMLInputElement ? patternInput.value.trim() : "",
      };
      if (request.tool === "diff") {
        const second = await readFile(file2Input);
        request.otherBytes = second.bytes;
        request.otherLabel = second.label;
      }
      const reply = await askWorker(request);
      if (!reply.ok) throw new Error(reply.error || "Analysis failed.");
      resultCode.textContent = JSON.stringify(reply.result, null, 2);
      setStatus(`Done. ${request.label} analyzed in your browser.`);
    } catch (error) {
      resultCode.textContent = "";
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      runButton.disabled = false;
    }
  });

  copyResult.addEventListener("click", async () => {
    if (!(copyResult instanceof HTMLButtonElement)) return;
    const original = copyResult.textContent;
    try {
      await navigator.clipboard.writeText(resultCode.textContent ?? "");
      copyResult.textContent = "Copied";
    } catch {
      copyResult.textContent = "Failed";
    } finally {
      window.setTimeout(() => { copyResult.textContent = original; }, 1500);
    }
  });

  downloadResult.addEventListener("click", () => {
    const blob = new Blob([resultCode.textContent ?? ""], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "reverso-report.json";
    link.click();
    URL.revokeObjectURL(url);
  });
}
