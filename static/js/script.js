class NetworkSecurityApp {
    constructor() {
        this.currentScanResults = null;
        this.firewallRules = [];
        this.initEventListeners();
        this.loadFirewallRules();
    }

    initEventListeners() {
        // Scan form submission
        document.getElementById('scanForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });

        // Firewall rule form submission
        document.getElementById('firewallRuleForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.addFirewallRule();
        });

        // Packet test form submission
        document.getElementById('packetTestForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.testPacket();
        });

        // Visualization generation
        document.getElementById('generateViz').addEventListener('click', () => {
            this.generateVisualization();
        });
    }

    async startScan() {
        const target = document.getElementById('target').value;
        const scanType = document.getElementById('scanType').value;
        const ports = document.getElementById('ports').value;
        const scanBtn = document.getElementById('scanBtn');
        const scanProgress = document.getElementById('scanProgress');

        // Validate input
        if (!target) {
            this.showAlert('Please enter a target IP or hostname', 'danger');
            return;
        }

        // Show progress
        scanBtn.disabled = true;
        scanProgress.style.display = 'block';

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType,
                    ports: ports
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Scan failed');
            }

            this.currentScanResults = data;
            this.displayScanResults(data);
            this.showAlert('Scan completed successfully!', 'success');

        } catch (error) {
            console.error('Scan error:', error);
            this.showAlert('Scan failed: ' + error.message, 'danger');
        } finally {
            scanBtn.disabled = false;
            scanProgress.style.display = 'none';
        }
    }

    displayScanResults(results) {
        const resultsContainer = document.getElementById('scanResults');

        if (results.error) {
            resultsContainer.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i> ${results.error}
                </div>
            `;
            return;
        }

        let html = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                Scan completed for ${results.target}.
                Found ${results.summary.open_ports} open ports on ${results.summary.up_hosts} hosts.
            </div>
        `;

        for (const [host, info] of Object.entries(results.hosts)) {
            if (info.state === 'up') {
                html += `
                    <div class="scan-result-item">
                        <h6><i class="fas fa-desktop"></i> ${host}
                            <span class="badge bg-success">${info.hostname || 'No hostname'}</span>
                        </h6>
                `;

                for (const [protocol, ports] of Object.entries(info.protocols)) {
                    if (Object.keys(ports).length > 0) {
                        html += `
                            <table class="table table-sm table-hover mt-2">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Service</th>
                                        <th>State</th>
                                        <th>Version</th>
                                    </tr>
                                </thead>
                                <tbody>
                        `;

                        for (const [port, portInfo] of Object.entries(ports)) {
                            html += `
                                <tr>
                                    <td>${port}/${protocol}</td>
                                    <td>${portInfo.service}</td>
                                    <td><span class="badge bg-success">${portInfo.state}</span></td>
                                    <td>${portInfo.product} ${portInfo.version}</td>
                                </tr>
                            `;
                        }

                        html += `</tbody></table>`;
                    }
                }

                html += `</div>`;
            }
        }

        resultsContainer.innerHTML = html;
    }

    async addFirewallRule() {
        const formData = {
            name: document.getElementById('ruleName').value,
            action: document.getElementById('ruleAction').value,
            source_ip: document.getElementById('sourceIP').value || 'any',
            destination_ip: document.getElementById('destinationIP').value || 'any',
            protocol: document.getElementById('protocol').value,
            port: document.getElementById('port').value || 'any'
        };

        try {
            const response = await fetch('/firewall/rules', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to add rule');
            }

            this.showAlert('Firewall rule added successfully!', 'success');
            document.getElementById('firewallRuleForm').reset();
            this.loadFirewallRules();

        } catch (error) {
            console.error('Rule addition error:', error);
            this.showAlert('Failed to add rule: ' + error.message, 'danger');
        }
    }

    async loadFirewallRules() {
        try {
            const response = await fetch('/firewall/rules');
            this.firewallRules = await response.json();
            this.displayFirewallRules();
        } catch (error) {
            console.error('Error loading rules:', error);
        }
    }

displayFirewallRules() {
    const container = document.getElementById('firewallRules');

    if (this.firewallRules.length === 0) {
        container.innerHTML = '<p class="text-muted text-center">No firewall rules defined. Add your first rule above.</p>';
        return;
    }

    let html = '<h6>Current Rules:</h6>';

    this.firewallRules.forEach(rule => {
        const ruleClass = rule.action === 'allow' ? 'rule-allow' : 'rule-deny';
        const badgeClass = rule.action === 'allow' ? 'bg-success' : 'bg-danger';

        // Format the rule display
        const sourceDisplay = rule.source_ip === 'any' ? 'Any' : rule.source_ip;
        const destDisplay = rule.destination_ip === 'any' ? 'Any' : rule.destination_ip;
        const portDisplay = rule.port === 'any' ? 'Any' : rule.port;
        const protocolDisplay = rule.protocol === 'any' ? 'Any' : rule.protocol.toUpperCase();

        html += `
            <div class="rule-item ${ruleClass}">
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <div class="d-flex align-items-center mb-1">
                            <span class="badge ${badgeClass} rule-badge">${rule.action.toUpperCase()}</span>
                            <strong>${rule.name}</strong>
                        </div>
                        <div class="rule-details">
                            <i class="fas fa-arrow-right"></i>
                            ${sourceDisplay}:${portDisplay} (${protocolDisplay}) → ${destDisplay}
                        </div>
                    </div>
                    <button class="btn btn-sm btn-outline-danger ms-2" onclick="app.deleteRule(${rule.id})" title="Delete Rule">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

    async deleteRule(ruleId) {
        if (!confirm('Are you sure you want to delete this rule?')) {
            return;
        }

        try {
            const response = await fetch(`/firewall/rules?id=${ruleId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showAlert('Rule deleted successfully!', 'success');
                this.loadFirewallRules();
            } else {
                throw new Error('Failed to delete rule');
            }
        } catch (error) {
            console.error('Rule deletion error:', error);
            this.showAlert('Failed to delete rule: ' + error.message, 'danger');
        }
    }

    async testPacket() {
        const testData = {
            source_ip: document.getElementById('testSourceIP').value,
            destination_ip: document.getElementById('testDestIP').value,
            protocol: document.getElementById('testProtocol').value,
            port: parseInt(document.getElementById('testPort').value)
        };

        try {
            const response = await fetch('/firewall/evaluate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(testData)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Evaluation failed');
            }

            this.displayPacketTestResult(result);

        } catch (error) {
            console.error('Packet test error:', error);
            this.showAlert('Packet test failed: ' + error.message, 'danger');
        }
    }

    displayPacketTestResult(result) {
        const container = document.getElementById('packetTestResult');
        const actionClass = result.action === 'allow' ? 'packet-allowed' : 'packet-denied';

        let html = `
            <div class="alert ${result.action === 'allow' ? 'alert-success' : 'alert-danger'}">
                <i class="fas fa-${result.action === 'allow' ? 'check' : 'ban'}"></i>
                Packet from ${result.source_ip}:${result.port} to ${result.destination_ip} would be <span class="${actionClass}">${result.action.toUpperCase()}</span>
        `;

        if (result.matched_rule) {
            html += ` by rule: <strong>${result.matched_rule}</strong>`;
        }

        html += `</div>`;

        container.innerHTML = html;
    }

    async generateVisualization() {
        const container = document.getElementById('visualizationContainer');
        container.innerHTML = '<div class="text-center"><div class="spinner-border text-primary"></div><p>Generating visualization...</p></div>';

        try {
            const response = await fetch('/visualization/network');
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Visualization failed');
            }

            container.innerHTML = `
                <img src="${data.image}" alt="Network Visualization" class="visualization-img">
            `;

        } catch (error) {
            console.error('Visualization error:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    Visualization failed: ${error.message}
                </div>
            `;
        }
    }

    showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentElement) {
                alertDiv.remove();
            }
        }, 5000);
    }
}

// Initialize the application when the page loads
document.addEventListener('DOMContentLoaded', function() {
    window.app = new NetworkSecurityApp();
});