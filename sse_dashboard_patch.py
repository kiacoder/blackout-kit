with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

old_html = """                html_dashboard = \"\"\"<!DOCTYPE html>
<html>
<head>
    <title>Blackout Kit Dashboard</title>
    <style>
        body { font-family: -apple-system, monospace; background: #0f172a; color: #f8fafc; padding: 2rem; }
        .card { background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; border: 1px solid #334155; }
        h1 { color: #38bdf8; }
        .badge { background: #22c55e; color: #022c22; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Blackout Kit — Network Dashboard</h1>
    <div class="card">
        <h2>System Status <span class="badge">ONLINE</span></h2>
        <p>Local REST API is active and servicing metrics.</p>
    </div>
    <div class="card">
        <h2>Quick REST Endpoints</h2>
        <ul>
            <li><a href="/api/status" style="color:#38bdf8">GET /api/status</a></li>
            <li><a href="/api/connections" style="color:#38bdf8">GET /api/connections</a></li>
            <li><a href="/api/audit" style="color:#38bdf8">GET /api/audit</a></li>
        </ul>
    </div>
</body>
</html>\"\"\""""

new_html = """                html_dashboard = \"\"\"<!DOCTYPE html>
<html>
<head>
    <title>Blackout Kit Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; margin:0; }
        .card { background: #1e293b; padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem; border: 1px solid #334155; }
        h1 { color: #38bdf8; font-size: 2rem; }
        .badge { background: #22c55e; color: #022c22; padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.9rem; font-weight: bold; }
        canvas { max-height: 250px; }
    </style>
</head>
<body>
    <h1>Blackout Kit — Live Network Dashboard <span class="badge">LIVE SSE</span></h1>
    <div class="card">
        <h2>Real-Time Active Connection Stream</h2>
        <canvas id="liveChart"></canvas>
    </div>
    <script>
        const ctx = document.getElementById('liveChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Active Sockets', data: [], borderColor: '#38bdf8', backgroundColor: 'rgba(56, 189, 248, 0.2)', fill: true, tension: 0.4 }] },
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
        const evtSource = new EventSource('/api/live-stream');
        evtSource.onmessage = function(e) {
            const data = JSON.parse(e.data);
            const timeStr = new Date(data.timestamp * 1000).toLocaleTimeString();
            if (chart.data.labels.length > 15) { chart.data.labels.shift(); chart.data.datasets[0].data.shift(); }
            chart.data.labels.push(timeStr);
            chart.data.datasets[0].data.push(data.connections);
            chart.update();
        };
    </script>
</body>
</html>\"\"\""""

if old_html in code:
    code = code.replace(old_html, new_html)
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Successfully updated web dashboard HTML in blackoutkit/tools.py")
else:
    print("Could not match old_html in blackoutkit/tools.py")
