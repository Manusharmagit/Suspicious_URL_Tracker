// ----------------------- SCAN FUNCTIONALITY -----------------------

async function scanURL() {
    const urlInput = document.getElementById('url').value.trim();
    const resultEl = document.getElementById('result');
    const apiKey = "6db6fbaf8f98f619ae1cc42fed3c6cc6c184f3fd1ff612e65a3ff77584a91279"; // Replace with your VirusTotal API key

    if (!urlInput) {
        alert("Please enter a valid URL or IP.");
        return;
    }

    try {
        resultEl.classList.remove('hidden');
        resultEl.innerText = "Submitting URL for scanning...";

        // Submit URL to VirusTotal
        let response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": apiKey,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(urlInput)}`
        });

        let result = await response.json();
        if (!result.data || !result.data.id) {
            resultEl.innerText = "❌ Error: Unable to submit URL.";
            return;
        }

        const scanId = result.data.id;
        resultEl.innerText = "Scanning... Please wait.";

        // Polling analysis result
        let retries = 6;
        while (retries > 0) {
            await new Promise(resolve => setTimeout(resolve, 5000)); // wait 5 sec

            response = await fetch(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
                headers: { "x-apikey": apiKey }
            });

            result = await response.json();

            if (result.data.attributes.status === "completed") {
                await displayResults(result, urlInput);
                return;
            }

            retries--;
        }

        resultEl.innerText = "⚠️ Scan is taking too long. Try again later.";
    } catch (error) {
        console.error(error);
        resultEl.innerText = "❌ Error scanning URL!";
    }
}

async function displayResults(scanData, urlInput) {
    const stats = scanData.data.attributes.stats;

    let summary = `🔍 Scan Summary:\n`;
    summary += `• Malicious: ${stats.malicious}\n`;
    summary += `• Suspicious: ${stats.suspicious}\n`;
    summary += `• Harmless: ${stats.harmless}\n`;
    summary += `• Undetected: ${stats.undetected}\n\n`;

    let details = "🛡️ Engine Results:\n";
    Object.values(scanData.data.attributes.results).forEach(entry => {
        details += `• ${entry.engine_name}: ${entry.result || "clean"}\n`;
    });

    let resultText = summary + details;

    try {
        // Fetch domain IP/location using ipinfo.io
        const domain = new URL(urlInput).hostname;
        const ipResp = await fetch(`https://ipinfo.io/${domain}/json?token=abc8d59631762f`);
        const ipData = await ipResp.json();

        resultText += `\n🌐 Server Info:\n`;
        resultText += `• IP Address: ${ipData.ip}\n`;
        resultText += `• Location: ${ipData.city}, ${ipData.region}, ${ipData.country}\n`;
        resultText += `• ISP: ${ipData.org}\n`;
    } catch (err) {
        resultText += `\n🌐 Server Info: Unable to fetch IP info.`;
    }

    document.getElementById('result').innerText = resultText;
}

// ----------------------- FORM & UI EVENT HANDLERS -----------------------

// Nav toggle for mobile
document.querySelector('.nav-toggle').addEventListener('click', () => {
    document.querySelector('nav ul').classList.toggle('active');
});

// Blog placeholder (empty blog section)
document.addEventListener('DOMContentLoaded', () => {
    const blogEl = document.querySelector('.blog-posts');
    if (blogEl) blogEl.innerHTML = '<p>No news available.</p>';
});

// Scan form submission
document.getElementById('scanForm').addEventListener('submit', function (e) {
    e.preventDefault();
    scanURL();
});

// Contact form demo
document.getElementById('contactForm').addEventListener('submit', e => {
    e.preventDefault();
    alert('✅ Message sent! (Demo only)');
    e.target.reset();
});
