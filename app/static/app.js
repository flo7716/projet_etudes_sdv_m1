const toolSelect = document.getElementById("tool-select");
const targetInput = document.getElementById("target-input");
const hashInput = document.getElementById("hash-input");
const wordlistInput = document.getElementById("wordlist-input");
const gobusterWordlistInput = document.getElementById("gobuster-wordlist-input");
const nmapOptionsInput = document.getElementById("nmap-options-input");
const hydraUserInput = document.getElementById("hydra-user-input");
const hydraPasslistInput = document.getElementById("hydra-passlist-input");
const outputArea = document.getElementById("output-area");
const clearButton = document.getElementById("clear-btn");
const runButton = document.getElementById("run-btn");

const fieldGroups = {
  target: document.getElementById("target-group"),
  nmapOptions: document.getElementById("nmap-options-group"),
  johnHash: document.getElementById("john-hash-group"),
  johnWordlist: document.getElementById("john-wordlist-group"),
  gobusterWordlist: document.getElementById("gobuster-wordlist-group"),
  hydraUser: document.getElementById("hydra-user-group"),
  hydraPasslist: document.getElementById("hydra-passlist-group")
};

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

const showFieldsForTool = (tool) => {
  Object.values(fieldGroups).forEach((group) => group.classList.add("hidden"));
  fieldGroups.target.classList.toggle("hidden", tool === "john");

  switch (tool) {
    case "nmap":
      fieldGroups.target.classList.remove("hidden");
      fieldGroups.nmapOptions.classList.remove("hidden");
      runButton.textContent = "Run Nmap";
      break;
    case "nikto":
      fieldGroups.target.classList.remove("hidden");
      runButton.textContent = "Run Nikto";
      break;
    case "gobuster":
      fieldGroups.target.classList.remove("hidden");
      fieldGroups.gobusterWordlist.classList.remove("hidden");
      runButton.textContent = "Run Gobuster";
      break;
    case "hydra":
      fieldGroups.target.classList.remove("hidden");
      fieldGroups.hydraUser.classList.remove("hidden");
      fieldGroups.hydraPasslist.classList.remove("hidden");
      runButton.textContent = "Run Hydra";
      break;
    case "openvas":
      fieldGroups.target.classList.remove("hidden");
      runButton.textContent = "Run OpenVAS";
      break;
    case "john":
      fieldGroups.johnHash.classList.remove("hidden");
      fieldGroups.johnWordlist.classList.remove("hidden");
      runButton.textContent = "Run John";
      break;
    default:
      runButton.textContent = "Run";
      break;
  }
};

const runScan = async () => {
  const tool = toolSelect.value;
  const target = targetInput.value.trim();
  const hashFile = hashInput.value.trim();
  const johnWordlist = wordlistInput.value.trim();
  const gobusterWordlist = gobusterWordlistInput.value.trim();
  const nmapOptions = nmapOptionsInput.value.trim();
  const hydraUser = hydraUserInput.value.trim();
  const hydraPasslist = hydraPasslistInput.value.trim();

  const endpoints = {
    nmap: "/nmap",
    openvas: "/openvas",
    nikto: "/nikto",
    gobuster: "/gobuster",
    hydra: "/hydra",
    john: "/john"
  };

  const endpoint = endpoints[tool];

  if (!endpoint) {
    appendOutput("Unknown tool selected.", "error");
    return;
  }

  if (tool === "john") {
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

  appendOutput(`Running ${tool.toUpperCase()}...`);

  const params = new URLSearchParams();
  if (tool === "john") {
    params.set("hash_file", hashFile);
    params.set("wordlist", johnWordlist || "/usr/share/john/password.lst");
  } else if (tool === "gobuster") {
    params.set("target", target);
    params.set("wordlist", gobusterWordlist || "/usr/share/wordlists/dirb/common.txt");
  } else if (tool === "nmap") {
    params.set("target", target);
    if (nmapOptions) params.set("options", nmapOptions);
  } else if (tool === "hydra") {
    params.set("target", target);
    if (hydraUser) params.set("user", hydraUser);
    if (hydraPasslist) params.set("passlist", hydraPasslist);
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

toolSelect.addEventListener("change", () => showFieldsForTool(toolSelect.value));
runButton.addEventListener("click", runScan);
clearButton.addEventListener("click", () => {
  outputArea.textContent = "Ready. Select a tool and enter a target.";
});

showFieldsForTool(toolSelect.value);
