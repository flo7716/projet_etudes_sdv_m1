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
    const response = await fetch(`${endpoint}?${params.toString()}`);
    if (!response.ok) {
      const body = await response.text();
      appendOutput(`Server error: ${response.status} ${body}`, "error");
      return;
    }

    const data = await response.json();
    appendOutput(JSON.stringify(data, null, 2));
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
