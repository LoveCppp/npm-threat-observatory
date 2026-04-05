const state = {
  analyses: [],
  samples: [],
  selectedAnalysisId: null,
  selectedSampleId: null,
};

const elements = {
  analysisForm: document.getElementById("analysis-form"),
  sourceType: document.getElementById("source-type"),
  registryFields: document.getElementById("registry-fields"),
  sampleFields: document.getElementById("sample-fields"),
  uploadFields: document.getElementById("upload-fields"),
  sampleList: document.getElementById("sample-list"),
  sampleId: document.getElementById("sample-id"),
  packageName: document.getElementById("package-name"),
  packageVersion: document.getElementById("package-version"),
  packageFile: document.getElementById("package-file"),
  runtimeMode: document.getElementById("runtime-mode"),
  egressMode: document.getElementById("egress-mode"),
  registryUrl: document.getElementById("registry-url"),
  submitButton: document.getElementById("submit-button"),
  submitStatus: document.getElementById("submit-status"),
  healthBadge: document.getElementById("health-badge"),
  healthStatus: document.getElementById("health-status"),
  healthDb: document.getElementById("health-db"),
  healthBackend: document.getElementById("health-backend"),
  healthFalco: document.getElementById("health-falco"),
  analysisList: document.getElementById("analysis-list"),
  analysisEmpty: document.getElementById("analysis-empty"),
  analysisDetails: document.getElementById("analysis-details"),
  selectedAnalysisId: document.getElementById("selected-analysis-id"),
  analysisPackage: document.getElementById("analysis-package"),
  analysisSource: document.getElementById("analysis-source"),
  analysisSummary: document.getElementById("analysis-summary"),
  analysisVerdict: document.getElementById("analysis-verdict"),
  analysisStatus: document.getElementById("analysis-status"),
  analysisRisk: document.getElementById("analysis-risk"),
  analysisRuntime: document.getElementById("analysis-runtime"),
  analysisEgress: document.getElementById("analysis-egress"),
  analysisCreated: document.getElementById("analysis-created"),
  analysisStarted: document.getElementById("analysis-started"),
  analysisCompleted: document.getElementById("analysis-completed"),
  analysisErrorWrap: document.getElementById("analysis-error-wrap"),
  analysisError: document.getElementById("analysis-error"),
  eventsList: document.getElementById("events-list"),
  refreshList: document.getElementById("refresh-list"),
  refreshSelected: document.getElementById("refresh-selected"),
};

function badgeClassForVerdict(value) {
  if (value === "failed") return "badge-danger";
  if (value === "malicious") return "badge-danger";
  if (value === "suspicious") return "badge-warn";
  if (value === "clean") return "badge-ok";
  return "badge-neutral";
}

function verdictClass(value) {
  if (value === "failed") return "verdict-failed";
  if (value === "malicious") return "verdict-malicious";
  if (value === "suspicious") return "verdict-suspicious";
  if (value === "clean") return "verdict-clean";
  return "verdict-neutral";
}

function effectiveVerdict(analysis) {
  return analysis.status === "failed" ? "failed" : analysis.verdict;
}

function effectiveRisk(analysis) {
  return analysis.status === "failed" ? "error" : analysis.risk_level;
}

function effectiveSummary(analysis) {
  if (analysis.status === "failed") {
    return analysis.summary || "Analysis execution failed before a verdict was produced.";
  }
  return analysis.summary || "Awaiting worker output.";
}

function sourceTypeForAnalysis(analysis) {
  return analysis.source_type || "registry";
}

function prettySourceLabel(type) {
  if (type === "upload") return "upload";
  return type === "sample" ? "sample" : "registry";
}

function prettyEgressLabel(value) {
  if (value === "registry_only") return "registry_only";
  return "offline";
}

function formatTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function renderHealth(health) {
  elements.healthStatus.textContent = health.status;
  elements.healthDb.textContent = health.database;
  elements.healthBackend.textContent = health.detection_backend;
  elements.healthFalco.textContent = health.falco_webhook;
  elements.healthBadge.className = `badge ${health.status === "ok" ? "badge-ok" : "badge-danger"}`;
  elements.healthBadge.textContent = health.status;
}

function renderAnalysisList() {
  elements.analysisList.innerHTML = "";
  if (!state.analyses.length) {
    elements.analysisList.innerHTML = '<div class="empty-state"><p>还没有分析任务，先从右侧创建一个任务。</p></div>';
    return;
  }

  state.analyses.forEach((analysis) => {
    const source = sourceTypeForAnalysis(analysis);
    const card = document.createElement("button");
    card.type = "button";
    card.className = `analysis-card ${state.selectedAnalysisId === analysis.id ? "active" : ""} ${analysis.status}`;
    card.innerHTML = `
      <div class="card-topline">
        <div>
          <strong>${analysis.package_name}@${analysis.version}</strong>
          <span class="mono subtle">${analysis.id}</span>
        </div>
        <span class="badge ${badgeClassForVerdict(effectiveVerdict(analysis))}">${effectiveVerdict(analysis)}</span>
      </div>
      <div class="card-body">${effectiveSummary(analysis)}</div>
      <div class="analysis-meta">
        <span class="pill">${prettySourceLabel(source)}</span>
        <span class="pill">${prettyEgressLabel(analysis.egress_mode)}</span>
        <span class="pill">${analysis.status}</span>
        <span class="pill">risk: ${effectiveRisk(analysis)}</span>
        <span class="pill">${formatTime(analysis.created_at)}</span>
      </div>
    `;
    card.addEventListener("click", () => selectAnalysis(analysis.id));
    elements.analysisList.appendChild(card);
  });
}

function renderSamples() {
  elements.sampleList.innerHTML = "";
  state.samples.forEach((sample) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `sample-card ${state.selectedSampleId === sample.id ? "active" : ""}`;
    button.innerHTML = `
      <div class="card-topline">
        <div>
          <strong>${sample.title}</strong>
          <span class="mono subtle">${sample.id}</span>
        </div>
        <span class="badge ${sample.id.includes("malicious") ? "badge-danger" : "badge-ok"}">${sample.runtime_mode}</span>
      </div>
      <div class="card-body">${sample.description}</div>
    `;
    button.addEventListener("click", () => {
      state.selectedSampleId = sample.id;
      elements.sampleId.value = sample.id;
      elements.runtimeMode.value = sample.runtime_mode || "require";
      renderSamples();
    });
    elements.sampleList.appendChild(button);
  });
}

function renderSelectedAnalysis(analysis, events) {
  elements.analysisEmpty.classList.add("hidden");
  elements.analysisDetails.classList.remove("hidden");

  const source = sourceTypeForAnalysis(analysis);
  elements.selectedAnalysisId.textContent = analysis.id;
  elements.analysisPackage.textContent = `${analysis.package_name}@${analysis.version}`;
  elements.analysisSource.className = `badge ${source === "sample" ? "badge-warn" : "badge-neutral"}`;
  elements.analysisSource.textContent = prettySourceLabel(source);
  elements.analysisSummary.textContent = effectiveSummary(analysis);
  elements.analysisVerdict.className = `verdict-card ${verdictClass(effectiveVerdict(analysis))}`;
  elements.analysisVerdict.textContent = effectiveVerdict(analysis);
  elements.analysisStatus.textContent = analysis.status;
  elements.analysisRisk.textContent = effectiveRisk(analysis);
  elements.analysisRuntime.textContent = analysis.runtime_mode;
  elements.analysisEgress.textContent = prettyEgressLabel(analysis.egress_mode);
  elements.analysisCreated.textContent = formatTime(analysis.created_at);
  elements.analysisStarted.textContent = formatTime(analysis.started_at);
  elements.analysisCompleted.textContent = formatTime(analysis.completed_at);

  if (analysis.error_message) {
    elements.analysisErrorWrap.classList.remove("hidden");
    elements.analysisError.textContent = analysis.error_message;
  } else {
    elements.analysisErrorWrap.classList.add("hidden");
    elements.analysisError.textContent = "";
  }

  elements.eventsList.innerHTML = "";
  if (!events.length) {
    elements.eventsList.innerHTML =
      analysis.status === "failed"
        ? '<div class="empty-state"><p>任务在生成 verdict 前失败了，所以这里只有执行错误，没有关联安全事件。</p></div>'
        : '<div class="empty-state"><p>还没有关联事件，可能任务仍在运行，或者该包比较干净。</p></div>';
    return;
  }

  events.forEach((event) => {
    const card = document.createElement("article");
    card.className = `event-card ${event.severity}`;
    card.innerHTML = `
      <div class="card-topline">
        <div>
          <strong>${event.rule}</strong>
          <div class="event-meta">
            <span class="pill">${event.severity}</span>
            <span class="pill">${event.phase || "unknown phase"}</span>
            <span class="pill">${formatTime(event.event_time)}</span>
          </div>
        </div>
      </div>
      <div class="event-body">${event.output}</div>
    `;
    elements.eventsList.appendChild(card);
  });
}

function syncSourceTypeUi() {
  const sourceType = elements.sourceType.value;
  const isSample = sourceType === "sample";
  const isUpload = sourceType === "upload";
  const isRegistry = sourceType === "registry";
  elements.registryFields.classList.toggle("hidden", !isRegistry);
  elements.sampleFields.classList.toggle("hidden", !isSample);
  elements.uploadFields.classList.toggle("hidden", !isUpload);
  elements.packageName.required = isRegistry;
  elements.packageVersion.required = isRegistry;
  elements.packageFile.required = isUpload;
  if (isRegistry && !elements.egressMode.dataset.userChanged) {
    elements.egressMode.value = "registry_only";
  }
  if (!isRegistry && !elements.egressMode.dataset.userChanged) {
    elements.egressMode.value = "offline";
  }
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }
  return response.json();
}

async function loadHealth() {
  const health = await fetchJson("/health");
  renderHealth(health);
}

async function loadSamples() {
  state.samples = await fetchJson("/samples");
  if (!state.selectedSampleId && state.samples[0]) {
    state.selectedSampleId = state.samples[0].id;
    elements.sampleId.value = state.samples[0].id;
  }
  renderSamples();
}

async function loadAnalyses() {
  const analyses = await fetchJson("/analyses");
  state.analyses = analyses;

  const hasSelected = analyses.some((item) => item.id === state.selectedAnalysisId);
  if (!hasSelected) {
    state.selectedAnalysisId = analyses[0] ? analyses[0].id : null;
  }

  renderAnalysisList();

  if (state.selectedAnalysisId) {
    await selectAnalysis(state.selectedAnalysisId, { rerenderList: false });
  }
}

async function selectAnalysis(analysisId, options = {}) {
  state.selectedAnalysisId = analysisId;
  if (options.rerenderList !== false) {
    renderAnalysisList();
  }
  const [analysis, events] = await Promise.all([
    fetchJson(`/analyses/${analysisId}`),
    fetchJson(`/analyses/${analysisId}/events`),
  ]);
  renderSelectedAnalysis(analysis, events);
}

async function submitAnalysis(event) {
  event.preventDefault();
  elements.submitButton.disabled = true;
  elements.submitStatus.textContent = "Creating task...";

  const payload = {
    runtime_mode: elements.runtimeMode.value,
    egress_mode: elements.egressMode.value,
  };

  if (elements.sourceType.value === "sample") {
    payload.sample_id = elements.sampleId.value;
  } else if (elements.sourceType.value === "registry") {
    payload.package_name = elements.packageName.value.trim();
    payload.version = elements.packageVersion.value.trim();
    if (elements.registryUrl.value.trim()) {
      payload.registry_url = elements.registryUrl.value.trim();
    }
  }

  try {
    let analysis;
    if (elements.sourceType.value === "upload") {
      const formData = new FormData();
      const file = elements.packageFile.files[0];
      if (!file) {
        throw new Error("Please choose a .tgz or .zip package first");
      }
      formData.set("file", file);
      formData.set("runtime_mode", elements.runtimeMode.value);
      formData.set("egress_mode", elements.egressMode.value);
      analysis = await fetchJson("/analyses/upload", {
        method: "POST",
        body: formData,
      });
    } else {
      analysis = await fetchJson("/analyses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    }
    elements.submitStatus.textContent = "Task queued";
    if (elements.sourceType.value !== "sample") {
      elements.analysisForm.reset();
      elements.runtimeMode.value = "require";
      elements.sourceType.value = "registry";
      elements.egressMode.value = "registry_only";
      elements.egressMode.dataset.userChanged = "";
    }
    syncSourceTypeUi();
    await loadAnalyses();
    await selectAnalysis(analysis.id);
  } catch (error) {
    elements.submitStatus.textContent = `Failed: ${error.message}`;
  } finally {
    elements.submitButton.disabled = false;
  }
}

elements.analysisForm.addEventListener("submit", submitAnalysis);
elements.sourceType.addEventListener("change", syncSourceTypeUi);
elements.egressMode.addEventListener("change", () => {
  elements.egressMode.dataset.userChanged = "true";
});
elements.refreshList.addEventListener("click", loadAnalyses);
elements.refreshSelected.addEventListener("click", async () => {
  if (state.selectedAnalysisId) {
    await selectAnalysis(state.selectedAnalysisId);
  }
});

async function bootstrap() {
  syncSourceTypeUi();
  try {
    await Promise.all([loadHealth(), loadSamples(), loadAnalyses()]);
  } catch (error) {
    elements.submitStatus.textContent = `Bootstrap failed: ${error.message}`;
  }
}

bootstrap();
setInterval(() => {
  loadHealth().catch(() => {});
  loadAnalyses().catch(() => {});
}, 8000);
