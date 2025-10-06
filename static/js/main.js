// Initialize Socket.io connection
const socket = io();

// Notification handling
function showNotification(message, level = 'info') {
    const container = document.getElementById('notificationContainer');
    if (!container) return;
    
    const notification = document.createElement('div');
    notification.className = `notification animate__animated animate__fadeInRight ${level}`;
    notification.innerHTML = `
        <div class="notification-icon">
            ${level === 'warning' ? '<i class="fas fa-exclamation-triangle"></i>' : '<i class="fas fa-info-circle"></i>'}
        </div>
        <div class="notification-content">
            <p>${message}</p>
            <small>Just now</small>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('animate__fadeOutRight');
        setTimeout(() => notification.remove(), 500);
    }, 5000);
}

// Request notification permission
document.addEventListener('DOMContentLoaded', () => {
    if ('Notification' in window) {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                console.log('Notification permission granted');
            }
        });
    }
});

// Handle battery updates from server
socket.on('battery_update', function(data) {
    const voltage = Number(data.voltage ?? data.battery_voltage ?? 0);
    const current = Number(data.current ?? 0);
    const power = Number(data.power ?? 0);
    const temperature = data.temperature != null ? Number(data.temperature) : 0;
    const soc = data.soc != null ? Number(data.soc) : 0;
    const status = String(data.status ?? 'unknown');

    const voltageEl = document.getElementById('voltageValue');
    if (voltageEl) voltageEl.textContent = voltage.toFixed(2) + ' V';

    const currentEl = document.getElementById('currentValue');
    if (currentEl) currentEl.textContent = current.toFixed(2) + ' A';

    const powerEl = document.getElementById('powerValue');
    if (powerEl) powerEl.textContent = power.toFixed(2) + ' W';

    const tempEl = document.getElementById('temperatureValue');
    if (tempEl) tempEl.textContent = temperature.toFixed(2) + ' °C';

    const socEl = document.getElementById('socValue');
    if (socEl) socEl.textContent = soc.toFixed(2) + ' %';

    // Update ESP32 connection indicator
    const esp32Indicator = document.getElementById('esp32Indicator');
    if (esp32Indicator) {
        if (data.source === 'esp32') {
            esp32Indicator.className = 'connection-indicator connected';
            esp32Indicator.title = 'ESP32 Connected';
        } else {
            esp32Indicator.className = 'connection-indicator disconnected';
            esp32Indicator.title = 'ESP32 Disconnected';
        }
    }

    // Update status indicators with correct thresholds
    updateStatusIndicator('voltage', voltage >= 7.0);
    updateStatusIndicator('current', current <= 2.0);
    updateStatusIndicator('temperature', temperature <= 40);
    updateStatusIndicator('soc', soc >= 20 && soc <= 100);
    updateSystemStatus(status === 'normal');

    // Eco Mode: Enabled when SOC drops below 35%
    const ecoModeIndicator = document.getElementById('ecoModeIndicator');
    if (ecoModeIndicator) {
        if (soc < 35 && soc > 0) {
            ecoModeIndicator.style.display = 'flex';
        } else {
            ecoModeIndicator.style.display = 'none';
        }
    }

    // Thermal Protection: Enabled when temperature exceeds 40°C
    const thermalProtectionIndicator = document.getElementById('thermalProtectionIndicator');
    if (thermalProtectionIndicator) {
        if (temperature > 40) {
            thermalProtectionIndicator.style.display = 'flex';
        } else {
            thermalProtectionIndicator.style.display = 'none';
        }
    }

    if (status !== 'normal') {
        const lastAnomaly = document.getElementById('lastAnomaly');
        if (lastAnomaly) lastAnomaly.textContent = `${data.timestamp} (${status.replace('_', ' ')})`;
    }

    if (window.combinedChart && window.tempChart) {
        addChartData(window.combinedChart, [voltage, current]);
        addChartData(window.tempChart, [temperature]);
    }
});

// Handle notifications from server
socket.on('notification', function(notification) {
    showNotification(notification.message, notification.level);
    
    // Show browser notification if permission is granted
    if (Notification.permission === 'granted') {
        new Notification('BMS Alert', {
            body: notification.message,
            icon: '/static/images/battery-icon.png'
        });
    }
});

// removed unused updateDashboard helper

function updateStatusIndicator(metric, isNormal) {
    const elements = document.querySelectorAll(`.metric-card .status`);
    if (!elements.length) return;
    
    elements.forEach(el => {
        const label = el.previousElementSibling?.textContent?.toLowerCase() || '';
        if (label.includes(metric)) {
            el.className = isNormal ? 'status good' : 'status bad';
            el.textContent = isNormal ? 'Normal' : 'Warning';
        }
    });
}

function updateSystemStatus(isNormal) {
    const indicator = document.querySelector('.status-indicator');
    const statusText = document.querySelector('.system-status span');
    
    if (indicator) {
        indicator.className = isNormal ? 'status-indicator status-good' : 'status-indicator status-warning';
    }
    
    if (statusText) {
        statusText.textContent = `System Status: ${isNormal ? 'Normal' : 'Warning'}`;
    }
}

function addChartData(chart, newData) {
    if (chart.data.datasets.length > 1) {
        // For combined chart
        chart.data.datasets[0].data.push(newData[0]);
        chart.data.datasets[1].data.push(newData[1]);
    } else {
        // For single dataset charts
        chart.data.datasets[0].data.push(newData[0]);
    }
    
    chart.data.labels.push('');
    
    // Limit data points to 20
    if (chart.data.datasets[0].data.length > 20) {
        chart.data.datasets.forEach(dataset => {
            dataset.data.shift();
        });
        chart.data.labels.shift();
    }
    
    chart.update();
}

// Initialize time selector buttons
document.addEventListener('DOMContentLoaded', () => {
    const timeButtons = document.querySelectorAll('.time-selector button');
    timeButtons.forEach(button => {
        button.addEventListener('click', function() {
            timeButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            // Here you would typically fetch new data for the selected time range
        });
    });
});