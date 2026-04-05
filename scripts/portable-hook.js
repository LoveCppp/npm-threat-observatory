const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const childProcess = require("node:child_process");
const net = require("node:net");
const os = require("node:os");

const eventUrl = process.env.PORTABLE_EVENT_URL;
const analysisId = process.env.ANALYSIS_ID;
const phase = process.env.PHASE || "runtime";
const sensitiveParts = [".npmrc", ".ssh", ".aws", ".git-credentials", "gcloud"];
const nativeHttpRequest = http.request.bind(http);
const nativeHttpsRequest = https.request.bind(https);
const nativeNetConnect = net.connect.bind(net);
const nativeExec = childProcess.exec.bind(childProcess);
const nativeExecFile = childProcess.execFile.bind(childProcess);
const nativeFork = childProcess.fork.bind(childProcess);
const egressMode = (process.env.EGRESS_MODE || "offline").trim().toLowerCase();
const allowedHosts = new Set(
  (process.env.ALLOWED_INTERNAL_HOSTS || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean),
);
const registryHost = (process.env.REGISTRY_HOST || "").trim().toLowerCase();

function isPrivateIp(host) {
  if (!host) return false;
  if (net.isIP(host) === 4) {
    if (host.startsWith("10.") || host.startsWith("127.") || host.startsWith("192.168.") || host.startsWith("169.254.")) {
      return true;
    }
    if (host === "169.254.169.254") {
      return true;
    }
    const second = Number(host.split(".")[1] || "0");
    if (host.startsWith("172.") && second >= 16 && second <= 31) {
      return true;
    }
    if (host.startsWith("100.") && second >= 64 && second <= 127) {
      return true;
    }
    if (host === "0.0.0.0") {
      return true;
    }
  }
  if (net.isIP(host) === 6) {
    const normalized = host.toLowerCase();
    if (normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80")) {
      return true;
    }
  }
  return false;
}

function isBlockedHost(rawHost) {
  const host = String(rawHost || "").toLowerCase();
  if (!host) return false;
  if (allowedHosts.has(host) || host === registryHost) {
    return false;
  }
  if (
    host === "localhost" ||
    host === "host.docker.internal" ||
    host === "host.containers.internal" ||
    host === "gateway.containers.internal" ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".lan") ||
    host.endsWith(".home")
  ) {
    return true;
  }
  if (isPrivateIp(host)) {
    return true;
  }
  if (egressMode === "offline") {
    return true;
  }
  if (egressMode === "registry_only") {
    return host !== registryHost && !allowedHosts.has(host);
  }
  return false;
}

function classifyHost(rawTarget) {
  if (!rawTarget) return { blocked: false, host: "" };
  if (typeof rawTarget === "string") {
    try {
      const asUrl = new URL(rawTarget);
      return { blocked: isBlockedHost(asUrl.hostname), host: asUrl.hostname };
    } catch (_) {
      return { blocked: isBlockedHost(rawTarget), host: rawTarget };
    }
  }
  const host = rawTarget.hostname || rawTarget.host || rawTarget.servername || "";
  return { blocked: isBlockedHost(host), host };
}

function postEvent(rule, severity, output, details = {}) {
  if (!eventUrl || !analysisId) {
    return;
  }

  const body = JSON.stringify({
    analysis_id: analysisId,
    phase,
    rule,
    severity,
    output,
    details: { hostname: os.hostname(), ...details },
    source: "portable",
  });

  const url = new URL(eventUrl);
  const requestImpl = url.protocol === "https:" ? nativeHttpsRequest : nativeHttpRequest;
  const req = requestImpl(
    {
      method: "POST",
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    },
    (res) => {
      res.resume();
    },
  );
  req.on("error", () => {});
  req.write(body);
  req.end();
}

function classifyProcessExecution(command, args, options) {
  const normalizedCommand = String(command || "");
  const normalizedArgs = Array.isArray(args) ? args.map((value) => String(value)) : [];
  const shellRequested =
    Boolean(options && options.shell) ||
    normalizedCommand === "sh" ||
    normalizedCommand === "bash" ||
    normalizedCommand === "/bin/sh" ||
    normalizedCommand === "/bin/bash" ||
    normalizedArgs.includes("-c");

  if (shellRequested) {
    return {
      rule: "portable lifecycle shell execution",
      severity: "medium",
      output: `shell execution observed: ${normalizedCommand} ${normalizedArgs.join(" ")}`.trim(),
    };
  }

  return {
    rule: "portable child process execution",
    severity: "medium",
    output: `child_process execution observed: ${normalizedCommand} ${normalizedArgs.join(" ")}`.trim(),
  };
}

function wrapSpawnLike(original) {
  return function wrappedSpawnLike(command, args, options) {
    const argv = Array.isArray(args) ? args.join(" ") : "";
    const classification = classifyProcessExecution(command, args, options);
    postEvent(classification.rule, classification.severity, classification.output, {
      command,
      argv,
      shell: Boolean(options && options.shell),
    });
    return original.apply(this, arguments);
  };
}

childProcess.spawn = wrapSpawnLike(childProcess.spawn);
childProcess.execFile = wrapSpawnLike(nativeExecFile);
childProcess.exec = function wrappedExec(command, options, callback) {
  postEvent("portable lifecycle shell execution", "medium", `exec observed: ${command}`, {
    command,
    shell: true,
  });
  return nativeExec(command, options, callback);
};
childProcess.fork = function wrappedFork(modulePath, args, options) {
  postEvent("portable child process execution", "medium", `fork observed: ${modulePath}`, {
    command: modulePath,
    argv: Array.isArray(args) ? args.join(" ") : "",
  });
  return nativeFork(modulePath, args, options);
};

function wrapHttpRequest(nativeImpl, protocolLabel) {
  return function wrappedRequest(...args) {
    const target = args[0];
    const { blocked, host } = classifyHost(target);
    if (blocked) {
      postEvent("portable blocked network access", "high", `blocked ${protocolLabel} request to ${host}`, {
        target: typeof target === "string" ? target : JSON.stringify(target),
        egress_mode: egressMode,
      });
      throw new Error(`Blocked local network destination: ${host}`);
    }
    const normalizedHost = String(host || "").toLowerCase();
    if (normalizedHost && normalizedHost !== registryHost && !allowedHosts.has(normalizedHost)) {
      postEvent(`portable suspicious ${protocolLabel} activity`, "medium", `${protocolLabel}.request observed`, {
        target: typeof target === "string" ? target : JSON.stringify(target),
      });
    }
    return nativeImpl(...args);
  };
}

http.request = wrapHttpRequest(nativeHttpRequest, "http");
https.request = wrapHttpRequest(nativeHttpsRequest, "https");

net.connect = function wrappedNetConnect(...args) {
  const target = args[0];
  const host =
    typeof target === "object" && target !== null
      ? target.host || target.hostname || ""
      : typeof args[1] === "string"
        ? args[1]
        : "";
  if (isBlockedHost(host)) {
    postEvent("portable blocked network access", "high", `blocked net.connect to ${host}`, {
      host,
      egress_mode: egressMode,
    });
    throw new Error(`Blocked local network destination: ${host}`);
  }
  postEvent("portable suspicious network activity", "medium", "net.connect observed", {
    target: JSON.stringify(args[0]),
  });
  return nativeNetConnect(...args);
};

const originalReadFileSync = fs.readFileSync;
fs.readFileSync = function wrappedReadFileSync(path, options) {
  const filename = String(path);
  if (sensitiveParts.some((part) => filename.includes(part))) {
    postEvent("portable sensitive credential access", "high", `readFileSync touched ${filename}`, {
      path: filename,
    });
  }
  return originalReadFileSync.call(this, path, options);
};

const originalOpenSync = fs.openSync;
fs.openSync = function wrappedOpenSync(path, flags, mode) {
  const filename = String(path);
  if (sensitiveParts.some((part) => filename.includes(part))) {
    postEvent("portable sensitive credential access", "high", `openSync touched ${filename}`, {
      path: filename,
      flags,
    });
  }
  return originalOpenSync.call(this, path, flags, mode);
};
