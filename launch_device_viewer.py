#!/usr/bin/env python3
"""
Web-based Multi-vendor Network Device Chassis Inventory Tool using SNMP
Flask web application with SQLite database
"""

from flask import Flask, render_template_string, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from pysnmp.hlapi import *
from datetime import datetime
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(100), nullable=False)
    community = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, default=161)
    version = db.Column(db.Integer, default=2)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='Not Scanned')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'community': self.community,
            'port': self.port,
            'version': self.version,
            'status': self.status,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None
        }

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    hostname = db.Column(db.String(100))
    system_description = db.Column(db.Text)
    uptime = db.Column(db.String(100))
    inventory_data = db.Column(db.Text)  # JSON string
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    device = db.relationship('Device', backref=db.backref('inventories', lazy=True))

# ENTITY-MIB OIDs
ENTITY_MIB_OIDS = {
    'entPhysicalDescr': '1.3.6.1.2.1.47.1.1.1.1.2',
    'entPhysicalClass': '1.3.6.1.2.1.47.1.1.1.1.5',
    'entPhysicalName': '1.3.6.1.2.1.47.1.1.1.1.7',
    'entPhysicalSerialNum': '1.3.6.1.2.1.47.1.1.1.1.11',
    'entPhysicalModelName': '1.3.6.1.2.1.47.1.1.1.1.13',
}

SYSTEM_MIB_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'sysUpTime': '1.3.6.1.2.1.1.3.0',
}

PHYSICAL_CLASS = {
    1: 'other', 2: 'unknown', 3: 'chassis', 4: 'backplane',
    5: 'container', 6: 'powerSupply', 7: 'fan', 8: 'sensor',
    9: 'module', 10: 'port', 11: 'stack', 12: 'cpu'
}

# SNMP Functions
def snmp_get(host, oid, community='public', port=161):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return str(varBind[1])
    except:
        return None

def snmp_walk(host, oid, community='public', port=161):
    results = {}
    try:
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication or errorStatus:
                break
            for varBind in varBinds:
                index = str(varBind[0]).split('.')[-1]
                results[index] = str(varBind[1])
        return results
    except:
        return {}

def scan_device(device):
    """Scan device and collect inventory"""
    try:
        # Get system info
        sys_name = snmp_get(device.host, SYSTEM_MIB_OIDS['sysName'], device.community, device.port)
        sys_descr = snmp_get(device.host, SYSTEM_MIB_OIDS['sysDescr'], device.community, device.port)
        sys_uptime = snmp_get(device.host, SYSTEM_MIB_OIDS['sysUpTime'], device.community, device.port)
        
        if not sys_name:
            return None, "Unable to connect via SNMP"
        
        # Get entity inventory
        entity_data = {}
        for key, base_oid in ENTITY_MIB_OIDS.items():
            entity_data[key] = snmp_walk(device.host, base_oid, device.community, device.port)
        
        inventory_items = []
        if entity_data.get('entPhysicalDescr'):
            for index in entity_data['entPhysicalDescr'].keys():
                phys_class_num = entity_data.get('entPhysicalClass', {}).get(index, '2')
                try:
                    phys_class = PHYSICAL_CLASS.get(int(phys_class_num), 'unknown')
                except:
                    phys_class = 'unknown'
                
                if phys_class not in ['sensor', 'unknown', 'other']:
                    inventory_items.append({
                        'index': index,
                        'name': entity_data.get('entPhysicalName', {}).get(index, 'N/A'),
                        'description': entity_data.get('entPhysicalDescr', {}).get(index, 'N/A'),
                        'class': phys_class,
                        'serial_number': entity_data.get('entPhysicalSerialNum', {}).get(index, 'N/A'),
                        'model': entity_data.get('entPhysicalModelName', {}).get(index, 'N/A'),
                    })
        
        inventory_items.sort(key=lambda x: int(x['index']))
        
        return {
            'hostname': sys_name,
            'system_description': sys_descr,
            'uptime': sys_uptime,
            'inventory_items': inventory_items
        }, None
        
    except Exception as e:
        return None, str(e)

# HTML Templates
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Network Device Inventory Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #333; margin-bottom: 30px; font-size: 28px; }
        h2 { color: #555; margin: 30px 0 15px 0; font-size: 22px; }
        .card { background: white; padding: 25px; margin-bottom: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 600; color: #555; }
        input[type="text"], input[type="number"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .form-row { display: grid; grid-template-columns: 2fr 2fr 1fr 1fr; gap: 15px; }
        button { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.3s; }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .btn-small { padding: 6px 12px; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; color: #555; }
        tr:hover { background: #f8f9fa; }
        .status-success { color: #28a745; font-weight: 600; }
        .status-failed { color: #dc3545; font-weight: 600; }
        .status-pending { color: #ffc107; font-weight: 600; }
        .inventory-section { margin-top: 20px; }
        .component-group { margin-bottom: 20px; }
        .component-group h3 { color: #666; font-size: 16px; margin-bottom: 10px; padding: 8px; background: #f0f0f0; border-radius: 4px; }
        .component-item { padding: 10px; margin: 5px 0; background: #fafafa; border-left: 3px solid #007bff; border-radius: 3px; }
        .component-item strong { color: #333; }
        .loading { text-align: center; padding: 20px; color: #666; }
        .alert { padding: 12px 20px; margin-bottom: 20px; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .actions { display: flex; gap: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Network Device Inventory Manager</h1>
        
        <div class="card">
            <h2>Add New Device</h2>
            <form method="POST" action="/add_device">
                <div class="form-row">
                    <div class="form-group">
                        <label>Device Name</label>
                        <input type="text" name="name" placeholder="Core-SW-01" required>
                    </div>
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" name="host" placeholder="192.168.1.1" required>
                    </div>
                    <div class="form-group">
                        <label>SNMP Community</label>
                        <input type="text" name="community" placeholder="public" required>
                    </div>
                    <div class="form-group">
                        <label>SNMP Port</label>
                        <input type="number" name="port" value="161" required>
                    </div>
                </div>
                <button type="submit" class="btn-primary">Add Device</button>
            </form>
        </div>

        <div class="card">
            <h2>Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>Community</th>
                        <th>Status</th>
                        <th>Last Scanned</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for device in devices %}
                    <tr>
                        <td><strong>{{ device.name }}</strong></td>
                        <td>{{ device.host }}</td>
                        <td>{{ device.community }}</td>
                        <td>
                            {% if device.status == 'Success' %}
                            <span class="status-success">✓ {{ device.status }}</span>
                            {% elif device.status == 'Not Scanned' %}
                            <span class="status-pending">⏳ {{ device.status }}</span>
                            {% else %}
                            <span class="status-failed">✗ Failed</span>
                            {% endif %}
                        </td>
                        <td>{{ device.last_scanned.strftime('%Y-%m-%d %H:%M') if device.last_scanned else 'Never' }}</td>
                        <td>
                            <div class="actions">
                                <form method="POST" action="/scan_device/{{ device.id }}" style="display: inline;">
                                    <button type="submit" class="btn-success btn-small">Scan</button>
                                </form>
                                <a href="/view_inventory/{{ device.id }}">
                                    <button class="btn-primary btn-small">View Inventory</button>
                                </a>
                                <form method="POST" action="/delete_device/{{ device.id }}" style="display: inline;" 
                                      onsubmit="return confirm('Delete this device?');">
                                    <button type="submit" class="btn-danger btn-small">Delete</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% if not devices %}
            <p style="text-align: center; color: #999; padding: 20px;">No devices added yet. Add your first device above!</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

INVENTORY_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Device Inventory - {{ device.name }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        h1 { color: #333; font-size: 28px; }
        .back-btn { padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 4px; }
        .back-btn:hover { background: #5a6268; }
        .card { background: white; padding: 25px; margin-bottom: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .info-item { padding: 15px; background: #f8f9fa; border-radius: 4px; }
        .info-item label { display: block; font-weight: 600; color: #666; margin-bottom: 5px; font-size: 12px; text-transform: uppercase; }
        .info-item .value { color: #333; font-size: 14px; }
        .component-group { margin-bottom: 30px; }
        .component-header { padding: 12px 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 6px; margin-bottom: 15px; font-size: 16px; font-weight: 600; }
        .component-list { display: grid; gap: 10px; }
        .component-card { padding: 15px; background: #fafafa; border-left: 4px solid #667eea; border-radius: 4px; }
        .component-card .title { font-weight: 600; color: #333; margin-bottom: 8px; font-size: 15px; }
        .component-card .details { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; font-size: 13px; }
        .component-card .detail-item { color: #666; }
        .component-card .detail-item span { color: #333; font-weight: 500; }
        .no-inventory { text-align: center; padding: 40px; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📦 {{ device.name }} - Chassis Inventory</h1>
            <a href="/" class="back-btn">← Back to Devices</a>
        </div>

        {% if inventory %}
        <div class="card">
            <div class="info-grid">
                <div class="info-item">
                    <label>Hostname</label>
                    <div class="value">{{ inventory.hostname or 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <label>IP Address</label>
                    <div class="value">{{ device.host }}</div>
                </div>
                <div class="info-item">
                    <label>System Uptime</label>
                    <div class="value">{{ inventory.uptime or 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <label>Last Scanned</label>
                    <div class="value">{{ inventory.scanned_at.strftime('%Y-%m-%d %H:%M:%S') }}</div>
                </div>
            </div>
            <div class="info-item" style="margin-top: 10px;">
                <label>System Description</label>
                <div class="value">{{ inventory.system_description or 'N/A' }}</div>
            </div>
        </div>

        {% set inventory_items = inventory.inventory_data | from_json %}
        {% set grouped = {} %}
        {% for item in inventory_items %}
            {% set _ = grouped.update({item.class: grouped.get(item.class, []) + [item]}) %}
        {% endfor %}

        {% for class_name in ['chassis', 'module', 'powerSupply', 'fan', 'port'] %}
            {% if class_name in grouped %}
            <div class="card">
                <div class="component-group">
                    <div class="component-header">
                        {% if class_name == 'chassis' %}🖥️ CHASSIS
                        {% elif class_name == 'module' %}🔌 MODULES
                        {% elif class_name == 'powerSupply' %}⚡ POWER SUPPLIES
                        {% elif class_name == 'fan' %}🌀 FANS
                        {% elif class_name == 'port' %}🔗 PORTS (First 10)
                        {% endif %}
                    </div>
                    <div class="component-list">
                        {% for item in grouped[class_name][:10 if class_name == 'port' else 999] %}
                        <div class="component-card">
                            <div class="title">{{ item.name if item.name != 'N/A' else item.description[:50] }}</div>
                            <div class="details">
                                <div class="detail-item"><strong>Description:</strong> <span>{{ item.description[:60] }}</span></div>
                                <div class="detail-item"><strong>Model:</strong> <span>{{ item.model }}</span></div>
                                <div class="detail-item"><strong>Serial:</strong> <span>{{ item.serial_number }}</span></div>
                            </div>
                        </div>
                        {% endfor %}
                        {% if class_name == 'port' and grouped[class_name]|length > 10 %}
                        <div style="text-align: center; padding: 10px; color: #666;">
                            ... and {{ grouped[class_name]|length - 10 }} more ports
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>
            {% endif %}
        {% endfor %}

        {% else %}
        <div class="card">
            <div class="no-inventory">
                <h2>No inventory data available</h2>
                <p style="margin-top: 10px;">Click "Scan" on the devices page to collect inventory.</p>
            </div>
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    devices = Device.query.all()
    return render_template_string(HTML_TEMPLATE, devices=devices)

@app.route('/add_device', methods=['POST'])
def add_device():
    name = request.form.get('name')
    host = request.form.get('host')
    community = request.form.get('community')
    port = int(request.form.get('port', 161))
    
    device = Device(name=name, host=host, community=community, port=port)
    db.session.add(device)
    db.session.commit()
    
    return redirect(url_for('index'))

@app.route('/scan_device/<int:device_id>', methods=['POST'])
def scan_device_route(device_id):
    device = Device.query.get_or_404(device_id)
    
    result, error = scan_device(device)
    
    if result:
        # Save inventory
        inventory = Inventory(
            device_id=device.id,
            hostname=result['hostname'],
            system_description=result['system_description'],
            uptime=result['uptime'],
            inventory_data=json.dumps(result['inventory_items'])
        )
        db.session.add(inventory)
        
        device.status = 'Success'
        device.last_scanned = datetime.utcnow()
    else:
        device.status = f'Failed: {error}'
    
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/view_inventory/<int:device_id>')
def view_inventory(device_id):
    device = Device.query.get_or_404(device_id)
    inventory = Inventory.query.filter_by(device_id=device_id).order_by(Inventory.scanned_at.desc()).first()
    
    return render_template_string(INVENTORY_TEMPLATE, device=device, inventory=inventory)

@app.route('/delete_device/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    Inventory.query.filter_by(device_id=device_id).delete()
    db.session.delete(device)
    db.session.commit()
    return redirect(url_for('index'))

@app.template_filter('from_json')
def from_json_filter(value):
    return json.loads(value) if value else []

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("="*80)
    print("Network Device Inventory Manager - Web Application")
    print("="*80)
    print("Starting server at http://127.0.0.1:5000")
    print("Press CTRL+C to stop")
    print("="*80)
    app.run(debug=True, host='0.0.0.0', port=5000)
