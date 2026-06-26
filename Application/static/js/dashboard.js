function updateClock() {
    const now = new Date();
    const clockElement = document.getElementById("clock");

    if (!clockElement) return;

    clockElement.textContent = now.toLocaleTimeString();
}

updateClock();
setInterval(updateClock, 1000);


const pdfReportBtn = document.getElementById("pdfReportBtn");

if (pdfReportBtn) {
    pdfReportBtn.addEventListener("click", function () {
        window.open("/download-ai-report", "_blank");
    });
}


function loadRiskTrendChart() {
    const chartElement = document.getElementById("riskTrendChart");

    if (!chartElement) return;

    fetch("/risk-history")
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            const labels = data.labels || [];
            const scores = data.scores || [];

            new Chart(chartElement, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: "Risk Score",
                            data: scores,
                            borderWidth: 3,
                            tension: 0.35,
                            pointRadius: 5,
                            pointHoverRadius: 7
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            min: 0,
                            max: 100,
                            ticks: {
                                color: "#93c5fd"
                            },
                            grid: {
                                color: "rgba(148,163,184,0.18)"
                            }
                        },
                        x: {
                            ticks: {
                                color: "#93c5fd"
                            },
                            grid: {
                                color: "rgba(148,163,184,0.10)"
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: {
                                color: "#e5e7eb"
                            }
                        }
                    }
                }
            });
        })
        .catch(function () {
            console.log("Risk trend data could not be loaded.");
        });
}

loadRiskTrendChart();


function isAnyModalOpen() {
    const chatModal = document.getElementById("aiChatModal");
    const threatModal = document.getElementById("threatModal");

    const chatOpen = chatModal && chatModal.style.display === "flex";
    const threatOpen = threatModal && threatModal.style.display === "flex";

    return chatOpen || threatOpen;
}

function autoRefreshDashboard() {
    if (isAnyModalOpen()) return;

    window.location.reload();
}

setInterval(autoRefreshDashboard, 30000);


let selectedIp = "";
let selectedPort = "";
let selectedRisk = "";

const chatModal = document.getElementById("aiChatModal");
const closeChatBtn = document.getElementById("closeChatBtn");
const sendQuestionBtn = document.getElementById("sendQuestionBtn");
const chatQuestion = document.getElementById("chatQuestion");
const chatMessages = document.getElementById("chatMessages");

const chatIp = document.getElementById("chatIp");
const chatPort = document.getElementById("chatPort");
const chatRisk = document.getElementById("chatRisk");

const threatModal = document.getElementById("threatModal");
const closeThreatBtn = document.getElementById("closeThreatBtn");
const threatTitle = document.getElementById("threatTitle");
const threatIp = document.getElementById("threatIp");
const threatLevel = document.getElementById("threatLevel");
const threatTime = document.getElementById("threatTime");
const threatExplanation = document.getElementById("threatExplanation");


function clearChatMessages() {
    if (!chatMessages) return;

    chatMessages.innerHTML = "";
}

function addChatMessage(message, type, id = "") {
    if (!chatMessages) return;

    const messageElement = document.createElement("div");
    messageElement.className = type;

    if (id) {
        messageElement.id = id;
    }

    messageElement.textContent = message;

    chatMessages.appendChild(messageElement);
    scrollChatToBottom();
}

function removeLoadingMessage() {
    const loadingMessage = document.getElementById("loadingMessage");

    if (loadingMessage) {
        loadingMessage.remove();
    }
}

function scrollChatToBottom() {
    if (!chatMessages) return;

    chatMessages.scrollTop = chatMessages.scrollHeight;
}


document.querySelectorAll(".threat-level-btn").forEach(function (button) {
    button.addEventListener("click", function () {
        if (threatTitle) threatTitle.textContent = button.dataset.title || "Threat Alert";
        if (threatIp) threatIp.textContent = button.dataset.ip || "Unknown";
        if (threatLevel) threatLevel.textContent = button.dataset.level || "Unknown";
        if (threatTime) threatTime.textContent = button.dataset.time || "Unknown";
        if (threatExplanation) threatExplanation.textContent = button.dataset.explanation || "No explanation available.";

        if (threatModal) {
            threatModal.style.display = "flex";
        }
    });
});

if (closeThreatBtn) {
    closeThreatBtn.addEventListener("click", function () {
        if (threatModal) {
            threatModal.style.display = "none";
        }
    });
}


document.querySelectorAll(".ai-risk-btn").forEach(function (button) {
    button.addEventListener("click", function () {
        selectedIp = button.dataset.ip;
        selectedPort = button.dataset.port;
        selectedRisk = button.dataset.risk;

        if (chatIp) chatIp.textContent = selectedIp;
        if (chatPort) chatPort.textContent = selectedPort;
        if (chatRisk) chatRisk.textContent = selectedRisk;

        clearChatMessages();
        addChatMessage(
            "This port is open on the selected device. Ask me what it means, why it is risky, or how to secure it.",
            "bot-message"
        );

        if (chatModal) {
            chatModal.style.display = "flex";
        }

        if (chatQuestion) {
            chatQuestion.focus();
        }
    });
});


if (closeChatBtn) {
    closeChatBtn.addEventListener("click", function () {
        if (chatModal) {
            chatModal.style.display = "none";
        }
    });
}


if (sendQuestionBtn) {
    sendQuestionBtn.addEventListener("click", sendQuestion);
}

if (chatQuestion) {
    chatQuestion.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            sendQuestion();
        }
    });
}

function sendQuestion() {
    if (!chatQuestion) return;

    const question = chatQuestion.value.trim();

    if (question === "") return;

    addChatMessage(question, "user-message");

    chatQuestion.value = "";

    addChatMessage("Thinking...", "bot-message", "loadingMessage");

    fetch("/ask-vulnerability", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            ip: selectedIp,
            port: selectedPort,
            risk_level: selectedRisk,
            question: question
        })
    })
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            removeLoadingMessage();

            addChatMessage(data.answer, "bot-message");
        })
        .catch(function () {
            removeLoadingMessage();

            addChatMessage(
                "AI assistant is not available right now. Make sure Ollama is running.",
                "bot-message"
            );
        });
}


window.addEventListener("click", function (event) {
    if (event.target === chatModal) {
        chatModal.style.display = "none";
    }

    if (event.target === threatModal) {
        threatModal.style.display = "none";
    }
});