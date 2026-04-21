// Charge le fichier report.json généré par analyzer.py
fetch('../report.json')
    .then(response => response.json())
    .then(data => {
        // Chiffres clés
        document.getElementById('total').textContent = data.total_events;
        document.getElementById('failed').textContent = data.failed_attempts;
        document.getElementById('success').textContent = data.successful_logins;
        document.getElementById('alerts-count').textContent = data.alerts.length;

        // Tableau des alertes
        const alertsTable = document.getElementById('alerts-table');
        const maxCount = Math.max(...data.alerts.map(a => a.count));
        data.alerts.forEach(alert => {
            const barWidth = Math.round((alert.count / maxCount) * 100);
            alertsTable.innerHTML += `
                <tr>
                    <td>${alert.ip}</td>
                    <td>
                        ${alert.count}
                        <div class="bar-container">
                            <div class="bar" style="width: ${barWidth}%"></div>
                        </div>
                    </td>
                    <td>${alert.users_targeted.join(', ')}</td>
                    <td><span class="badge ${alert.severity}">${alert.severity}</span></td>
                    <td>${alert.count} attempts</td>
                </tr>
            `;
        });

        // Tableau des connexions réussies
        const loginsTable = document.getElementById('logins-table');
        data.events
            .filter(e => e.type === 'SUCCESS')
            .forEach(event => {
                loginsTable.innerHTML += `
                    <tr>
                        <td>${event.timestamp}</td>
                        <td>${event.user}</td>
                        <td>${event.ip}</td>
                    </tr>
                `;
            });

        // Tableau de tous les events
        const eventsTable = document.getElementById('events-table');
        data.events.forEach(event => {
            eventsTable.innerHTML += `
                <tr>
                    <td>${event.timestamp}</td>
                    <td><span class="badge ${event.type === 'FAILED' ? 'HIGH' : ''}">${event.type}</span></td>
                    <td>${event.user}</td>
                    <td>${event.ip}</td>
                </tr>
            `;
        });
    })
    .catch(err => {
        console.error('Erreur lors du chargement du rapport :', err);
        document.body.innerHTML += '<p style="color:red;text-align:center">Erreur : lance analyzer.py dabord pour generer report.json</p>';
    });
    