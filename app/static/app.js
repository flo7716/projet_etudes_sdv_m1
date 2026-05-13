const targetInput = document.getElementById("target-input");
const hashInput = document.getElementById("hash-input");
const outputArea = document.getElementById("output-area");
const clearButton = document.getElementById("clear-btn");
const toolButtons = document.querySelectorAll(".tool-btn");

const appendOutput = (text, type = "info") => {
  const prefix = type === "error" ? "[ERROR]" : "[INFO]";
  outputArea.textContent += `\n${prefix} ${text}`;
  outputArea.scrollTop = outputArea.scrollHeight;
};

const formatResult = (data) => {
  if (!data || typeof data !== "object") {
    return String(data);
  }

  if (data.output) {
    return data.output.trim() || "(no output)";
  }

  if (data.stdout || data.stderr) {
    let formatted = "";
    if (data.target) formatted += `Target: ${data.target}\n`;
    if (data.stdout) formatted += `\n--- STDOUT ---\n${data.stdout.trim()}\n`;
    if (data.stderr) formatted += `\n--- STDERR ---\n${data.stderr.trim()}\n`;
    formatted += `\nreturncode: ${data.returncode ?? "unknown"}`;
    return formatted.trim();
  }

  if (Array.isArray(data.open_ports)) {
    const count = data.open_ports_count ?? data.open_ports.length;
    let formatted = `Open ports: ${count}`;
    if (data.open_ports.length > 0) {
      formatted += "\n\nPORT\tSERVICE\n";
      data.open_ports.forEach((port) => {
        formatted += `${port.port}\t${port.service}\n`;
      });
    }
    return formatted;
  }

  return JSON.stringify(data, null, 2);
};

const runScan = async (endpoint) => {
  const target = targetInput.value.trim();
  const hashFile = hashInput.value.trim();

  if (endpoint === "/john") {
    if (!hashFile) {
      appendOutput("Please provide a hash file path for John.", "error");
      return;
    }
  } else {
    if (!target) {
      appendOutput("Please provide a target host or domain.", "error");
      return;
    }
  }

  appendOutput(`Running ${endpoint.replace("/", "").toUpperCase()}...`);

  const params = new URLSearchParams();
  if (endpoint === "/john") {
    params.set("hash_file", hashFile);
  } else {
    params.set("target", target);
  }

  try {
    const response = await fetch(`/api${endpoint}?${params.toString()}`);
    if (!response.ok) {
      const body = await response.text();
      appendOutput(`Server error: ${response.status} ${body}`, "error");
      return;
    }

    const data = await response.json();
    appendOutput(formatResult(data));
  } catch (error) {
    appendOutput(error.message, "error");
  }
};

toolButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const endpoint = button.getAttribute("data-endpoint");
    runScan(endpoint);
  });
});

clearButton.addEventListener("click", () => {
  outputArea.textContent = "Ready. Select a tool and enter a target.";
});
