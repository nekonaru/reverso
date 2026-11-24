/** Web Worker wrapper: keeps the UI responsive during analysis. */
import { runBrowserTool, type BrowserRequest } from "./index.js";

interface WorkerMessage {
  id: number;
  request: BrowserRequest;
}

interface WorkerReply {
  id: number;
  ok: boolean;
  result?: unknown;
  error?: string;
}

const scope = globalThis as unknown as {
  addEventListener: (type: "message", listener: (event: { data: WorkerMessage }) => void) => void;
  postMessage: (message: WorkerReply) => void;
};

scope.addEventListener("message", (event) => {
  const { id, request } = event.data;
  try {
    const result = runBrowserTool({
      ...request,
      bytes: new Uint8Array(request.bytes),
      otherBytes: request.otherBytes ? new Uint8Array(request.otherBytes) : undefined,
    });
    scope.postMessage({ id, ok: true, result });
  } catch (error) {
    scope.postMessage({ id, ok: false, error: (error as Error).message });
  }
});
