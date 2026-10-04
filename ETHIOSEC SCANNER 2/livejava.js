document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('id');
    const targetUrl = urlParams.get('target');
    
    if (!scanId) {
        window.location.href = 'scanfinal.html';
        return;
    }

    if (targetUrl) {
        const tEl = document.getElementById('scanTarget');
        if (tEl) tEl.textContent = targetUrl;
    }

    const ringProgress = document.getElementById('ringProgress');
    const progressPercent = document.getElementById('progressPercent');
    const progressFill = document.getElementById('progressFill');
    const stageText = document.getElementById('stageText');
    const statusLabel = document.getElementById('statusLabel');
    const scanIdLabel = document.getElementById('scanIdLabel');
    const viewResultsBtn = document.getElementById('viewResults');
    const cancelScanBtn = document.getElementById('cancelScan');
    const elapsedEl = document.getElementById('elapsed');
    const logList = document.getElementById('log');
    
    const RING_LENGTH = 2 * Math.PI * 60;
    if (ringProgress) {
        ringProgress.style.strokeDasharray = RING_LENGTH;
        ringProgress.style.strokeDashoffset = RING_LENGTH;
    }
    
    if (scanIdLabel) scanIdLabel.textContent = scanId;
    if (viewResultsBtn) viewResultsBtn.href = `results.html?id=${encodeURIComponent(scanId)}`;

    const startTime = Date.now();
    const timerInterval = setInterval(() => {
        if (elapsedEl) {
            const secs = Math.floor((Date.now() - startTime) / 1000);
            elapsedEl.textContent = `${secs}s`;
        }
    }, 1000);

    let pollInterval;
    let loggedStages = new Set();

    function addLogEntry(stage) {
        if (!logList || !stage || loggedStages.has(stage)) return;
        loggedStages.add(stage);
        const li = document.createElement('li');
        li.textContent = `[${new Date().toLocaleTimeString()}] ${stage}`;
        logList.appendChild(li);
        logList.scrollTop = logList.scrollHeight;
    }

    async function pollStatus() {
        try {
            const token = localStorage.getItem('token');
            const res = await fetch(`http://127.0.0.1:8000/api/scans/${scanId}/status`, {
                headers: token ? { 'Authorization': `Bearer ${token}` } : {}
            });
            if (!res.ok) throw new Error('Failed to fetch status');
            
            const data = await res.json();
            
            if (data.target) {
                const targetEl = document.getElementById('scanTarget');
                if (targetEl) targetEl.textContent = data.target;
            }
            
            const p = data.progress || 0;
            if (progressPercent) progressPercent.textContent = p + '%';
            if (progressFill) progressFill.style.width = p + '%';
            if (ringProgress) ringProgress.style.strokeDashoffset = RING_LENGTH - (p / 100) * RING_LENGTH;
            
            if (stageText) stageText.textContent = data.stage || 'Running assessment pipeline…';
            if (statusLabel) statusLabel.textContent = data.status.toUpperCase();
            
            const depthLabel = document.getElementById('depthLabel');
            if (depthLabel && data.depth) {
                depthLabel.textContent = data.depth === 'deep' ? 'Deep Audit' : 'Standard Scan';
            }
            
            if (data.stage) addLogEntry(data.stage);

            // Update check dots
            if (data.checks) {
                Object.keys(data.checks).forEach(checkName => {
                    if (data.checks[checkName]) {
                        const checkEl = document.querySelector(`.check[data-check="${checkName}"]`);
                        if (checkEl) checkEl.classList.add('done');
                    }
                });
            }

            if (data.status === 'completed' || data.status === 'failed') {
                clearInterval(pollInterval);
                clearInterval(timerInterval);
                if (statusLabel) statusLabel.textContent = data.status === 'completed' ? 'COMPLETED' : 'FAILED';
                if (viewResultsBtn) {
                    viewResultsBtn.hidden = false;
                    viewResultsBtn.textContent = 'View Results →';
                }
                if (cancelScanBtn) cancelScanBtn.hidden = true;
                
                // Auto redirect to results if completed
                if (data.status === 'completed') {
                    setTimeout(() => {
                        window.location.href = `results.html?id=${encodeURIComponent(scanId)}`;
                    }, 800);
                } else {
                    if (stageText) stageText.textContent = 'Assessment Finished with Warnings';
                }
            }
        } catch (e) {
            console.error('Polling error:', e);
        }
    }

    if (cancelScanBtn) {
        cancelScanBtn.addEventListener('click', async () => {
            clearInterval(pollInterval);
            clearInterval(timerInterval);
            try {
                const token = localStorage.getItem('token');
                await fetch(`http://127.0.0.1:8000/api/scans/${scanId}/cancel`, {
                    method: 'POST',
                    headers: token ? { 'Authorization': `Bearer ${token}` } : {}
                });
            } catch (e) {
                console.error("Failed to cancel on server", e);
            }
            window.location.href = 'scanfinal.html';
        });
    }

    pollInterval = setInterval(pollStatus, 1500);
    pollStatus();
});
