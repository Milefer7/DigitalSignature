const API_BASE_URL = "http://localhost:8080/api";
// const API_BASE_URL = "http://localhost:8081/api";
window.onload = function () {
    // document.getElementById("server_port").addEventListener("input", updateApiBaseUrl);
    displayServerPort();
    receiveMessageSSE();
}

// Generate keys
async function generateKeys() {
    const response = await fetch(`${API_BASE_URL}/keys`);
    const data = await response.json();
    document.getElementById("public_key").value = data.public_key;
    document.getElementById("private_key").value = data.private_key;
}

// Generate hash
async function generateHash() {
    const message = document.getElementById("message").value;
    const response = await fetch(`${API_BASE_URL}/hash`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({message}),
    });
    const data = await response.json();
    document.getElementById("hash").value = data.hash;
}

// Generate signature
async function generateSignature() {
    const message = document.getElementById("message").value;
    const privateKey = document.getElementById("private_key").value;

    const response = await fetch(`${API_BASE_URL}/sign`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({message, private_key: privateKey}),
    });
    const data = await response.json();
    document.getElementById("signature").value = data.signature;
}

async function sendMessage() {
    const message = document.getElementById("message").value;
    const signature = document.getElementById("signature").value;
    const publicKey = document.getElementById("public_key").value;
    const ip = document.getElementById("ip").value;

    if (!ip) {
        alert("IP 地址不能为空");
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/send`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({message, signature, public_key: publicKey, ip}),
        });

        if (!response.ok) {
            throw new Error("发送失败");
        }

        alert("消息已发送");

    } catch (error) {
        alert(`错误: ${error.message}`);
    }
}


// Receive message SSE技术
function receiveMessageSSE() {
    const eventSource = new EventSource(`${API_BASE_URL}/sse`);

    // 添加调试日志
    eventSource.onopen = function () {
        alert("与服务器已连接")
        console.log("SSE 连接已建立");
    };

    eventSource.onmessage = function (event) {
        console.log("收到数据：", event.data);

        // 判断数据是否为空
        if (!event.data || event.data.trim() === "{}") {
            console.log("数据为空，不覆盖内容");
            return;
        }

        try {
            const data = JSON.parse(event.data);

            // 如果数据解析后为 null 或不包含必要的字段，也不更新内容
            if (!data || !data.message || !data.signature || !data.public_key) {
                console.log("数据内容不完整，不覆盖内容");
                return;
            }

            // 更新页面内容
            document.getElementById("received_message").value = data.message;
            document.getElementById("received_signature").value = data.signature;
            document.getElementById("received_public_key").value = data.public_key;
        } catch (error) {
            console.error("数据解析失败：", error);
        }
    };

    eventSource.onerror = function (error) {
        console.error("SSE 连接错误：", error);
        alert("与服务器的消息推送连接中断");
        eventSource.close();
    };
}


// Verify signature
async function verifySignature() {
    const message = document.getElementById("received_message").value;
    const signature = document.getElementById("received_signature").value;
    const publicKey = document.getElementById("received_public_key").value;

    const response = await fetch(`${API_BASE_URL}/compare`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({message, signature, public_key: publicKey}),
    });
    const data = await response.json();
    const resultElement = document.getElementById("verification_result");
    if (data.match) {
        resultElement.innerText = "验证通过：签名有效";
        resultElement.style.color = "green";
    } else {
        resultElement.innerText = "验证失败：签名无效";
        resultElement.style.color = "red";
    }
}

function displayServerPort() {
    const port = API_BASE_URL.split(":")[2].split("/")[0];
    console.log(port);
    document.getElementById("server_port").value = '服务器端口号：'+ port;
}
