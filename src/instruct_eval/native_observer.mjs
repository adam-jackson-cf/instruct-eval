import { createHash } from "node:crypto";
import { lstatSync, opendirSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";

// Loaded explicitly from a read-only mount; measurements share the existing RPC stream.
export default async function observeWorkspace(api) {
  const limit = Number(process.env.INSTRUCT_EVAL_EVIDENCE_BYTES);
  const gatePort = Number(process.env.INSTRUCT_EVAL_GATE_PORT);
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new Error("Workspace observation bound is unavailable");
  }
  if (!Number.isSafeInteger(gatePort) || gatePort < 1 || gatePort > 65535) {
    throw new Error("Workspace gate port is unavailable");
  }

  const pending = new Map();
  const requested = new Map();
  const mutators = new Set(["write", "edit", "bash"]);
  let activeBash;
  let gateProtocolFailed = false;
  const emit = (event) => process.stdout.write(JSON.stringify({ ...event, origin: "runtime_observer" }) + "\n");

  function snapshot(root) {
    const files = new Map();
    const directories = [""];
    let retained = 0;
    while (directories.length) {
      const relative = directories.pop();
      const directory = opendirSync(join(root, relative));
      try {
        for (let entry; (entry = directory.readSync()) !== null;) {
          const name = relative ? `${relative}/${entry.name}` : entry.name;
          const path = join(root, name);
          const metadata = lstatSync(path);
          retained += Buffer.byteLength(name);
          if (metadata.isSymbolicLink()) throw new Error("Workspace contains a symlink");
          if (metadata.isFile()) retained += metadata.size;
          if (retained > limit) throw new Error("Workspace snapshot exceeds the evidence bound");
          if (metadata.isDirectory()) {
            directories.push(name);
          } else if (metadata.isFile()) {
            const content = readFileSync(path);
            if (content.length !== metadata.size) throw new Error("Workspace changed while snapshotting");
            files.set(name, createHash("sha256").update(content).digest("hex"));
          } else {
            throw new Error("Workspace contains an unsupported entry");
          }
        }
      } finally {
        directory.closeSync();
      }
    }
    return files;
  }

  function changedPaths(before, after) {
    const paths = new Set([...before.keys(), ...after.keys()]);
    return [...paths].filter((path) => before.get(path) !== after.get(path)).sort();
  }

  function retainedSnapshotBytes(files) {
    let retained = 0;
    for (const [path, hash] of files) retained += Buffer.byteLength(path) + Buffer.byteLength(hash);
    return retained;
  }

  function failGate(state) {
    gateProtocolFailed = true;
    if (state) state.error = state.error || new Error("Workspace gate snapshot is invalid");
  }

  const gateServer = createServer((socket) => {
    socket.unref();
    socket.setEncoding("utf8");
    let request = "";
    socket.on("data", (chunk) => {
      request += chunk;
      if (Buffer.byteLength(request) > 64 || request.split("\n").length > 2) {
        failGate(activeBash);
        socket.end("error\n");
        return;
      }
      if (!request.endsWith("\n")) return;
      let payload;
      try {
        payload = JSON.parse(request.slice(0, -1));
      } catch {
        failGate(activeBash);
        socket.end("error\n");
        return;
      }
      const state = activeBash;
      if (
        !state
        || gateProtocolFailed
        || state.error
        || request !== '{"script":"check.py"}\n'
        || !payload
        || typeof payload !== "object"
        || Array.isArray(payload)
        || Object.keys(payload).length !== 1
        || payload.script !== "check.py"
      ) {
        failGate(state);
        socket.end("error\n");
        return;
      }
      try {
        const before = snapshot(state.cwd);
        state.gateSnapshotBytes += retainedSnapshotBytes(before);
        if (state.gateSnapshotBytes > limit) throw new Error("Workspace gate snapshots exceed the evidence bound");
        state.gates.push({ script: "check.py", before });
        socket.end("ok\n");
      } catch {
        failGate(state);
        socket.end("error\n");
      }
    });
  });

  await new Promise((resolve, reject) => {
    gateServer.once("error", reject);
    gateServer.listen({ host: "127.0.0.1", port: gatePort }, () => {
      gateServer.off("error", reject);
      resolve();
    });
  });
  gateServer.unref();

  function rejectAdmission(event) {
    gateProtocolFailed = true;
    for (const state of pending.values()) failGate(state);
    requested.delete(event.toolCallId);
    emit({
      type: "instruct_eval_tool_admission",
      phase: "rejected",
      toolCallId: event.toolCallId,
      toolName: event.toolName,
    });
  }

  api.on("tool_approval_requested", (event) => {
    if (!mutators.has(event.toolName)) return;
    if (gateProtocolFailed || requested.has(event.toolCallId) || pending.has(event.toolCallId)) {
      rejectAdmission(event);
      return;
    }
    requested.set(event.toolCallId, event.toolName);
    emit({
      type: "instruct_eval_tool_admission",
      phase: "requested",
      toolCallId: event.toolCallId,
      toolName: event.toolName,
    });
  });

  api.on("tool_approval_resolved", (event, context) => {
    if (!mutators.has(event.toolName)) return;
    if (event.approved !== true || requested.get(event.toolCallId) !== event.toolName ||
        pending.size || gateProtocolFailed) {
      rejectAdmission(event);
      return;
    }
    requested.delete(event.toolCallId);
    try {
      const state = {
        tool: event.toolName,
        before: snapshot(context.cwd),
        cwd: context.cwd,
        gates: [],
        gateSnapshotBytes: 0,
      };
      pending.set(event.toolCallId, state);
      if (event.toolName === "bash") activeBash = state;
      emit({
        type: "instruct_eval_tool_admission",
        phase: "admitted",
        toolCallId: event.toolCallId,
        toolName: event.toolName,
      });
    } catch {
      rejectAdmission(event);
    }
  });
  api.on("tool_result", (event, context) => {
    if (!mutators.has(event.toolName)) return;
    const state = pending.get(event.toolCallId);
    if (!state || state.tool !== event.toolName) {
      rejectAdmission(event);
      return;
    }
    try {
      if (state.error) {
        rejectAdmission(event);
        return;
      }
      const after = snapshot(context.cwd);
      const gate_snapshots = state.gates.map(({ script, before }) => ({
        script,
        changed_paths: changedPaths(before, after),
      }));
      emit({
        type: "instruct_eval_tool_observation",
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        changed_paths: changedPaths(state.before, after),
        gate_snapshots,
      });
    } catch {
      // The native result remains authoritative; missing observation rejects its projection.
      rejectAdmission(event);
    } finally {
      if (activeBash === state) activeBash = undefined;
      pending.delete(event.toolCallId);
    }
  });
  api.on("agent_end", () => gateServer.close());
  emit({ type: "instruct_eval_observer_ready" });
}
