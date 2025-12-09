from flask import Flask, render_template, request, jsonify, session
from scanner.network_scanner import NetworkScanner
from scanner.firewall_simulator import FirewallSimulator, RuleAction, Protocol
from scanner.visualization import NetworkVisualizer
import json
from threading import Lock

app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')

# Initialize components
scanner = NetworkScanner()
firewall = FirewallSimulator()
visualizer = NetworkVisualizer()
scan_lock = Lock()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_network():
    if scan_lock.locked():
        return jsonify({'error': 'Scan already in progress'}), 429

    try:
        with scan_lock:
            data = request.get_json()
            target = data.get('target', '')
            scan_type = data.get('scan_type', 'tcp_syn')
            ports = data.get('ports', '1-1000')

            if not target:
                return jsonify({'error': 'Target is required'}), 400

            results = scanner.scan_target(target, scan_type, ports)

            if 'error' in results:
                return jsonify({'error': results['error']}), 500

            # Store results in session for visualization
            session['last_scan'] = results

            return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500


@app.route('/firewall/rules', methods=['GET', 'POST', 'DELETE'])
def manage_firewall_rules():
    if request.method == 'GET':
        return jsonify(firewall.get_rules())

    elif request.method == 'POST':
        data = request.get_json()

        try:
            rule = firewall.add_rule(
                name=data['name'],
                action=RuleAction(data['action']),
                source_ip=data.get('source_ip', 'any'),
                destination_ip=data.get('destination_ip', 'any'),
                protocol=Protocol(data.get('protocol', 'any')),
                port=data.get('port', 'any'),
                priority=data.get('priority', len(firewall.rules) + 1)
            )

            return jsonify({'message': 'Rule added successfully', 'rule': {
                'id': rule.id,
                'name': rule.name,
                'action': rule.action.value,
                'source_ip': rule.source_ip,
                'destination_ip': rule.destination_ip,
                'protocol': rule.protocol.value,
                'port': rule.port,
                'priority': rule.priority
            }})

        except Exception as e:
            return jsonify({'error': f'Failed to add rule: {str(e)}'}), 400

    elif request.method == 'DELETE':
        rule_id = request.args.get('id')
        if rule_id:
            firewall.remove_rule(int(rule_id))
            return jsonify({'message': 'Rule deleted successfully'})
        else:
            return jsonify({'error': 'Rule ID is required'}), 400


@app.route('/firewall/evaluate', methods=['POST'])
def evaluate_packet():
    data = request.get_json()

    try:
        result = firewall.evaluate_packet(
            source_ip=data.get('source_ip', '192.168.1.100'),
            destination_ip=data.get('destination_ip', '192.168.1.1'),
            protocol=data.get('protocol', 'tcp'),
            port=int(data.get('port', 80))
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Evaluation failed: {str(e)}'}), 400


@app.route('/visualization/network')
def get_network_visualization():
    scan_results = session.get('last_scan', {})
    firewall_rules = firewall.get_rules()

    if not scan_results:
        return jsonify({'error': 'No scan results available'}), 400

    try:
        image_data = visualizer.create_network_graph(scan_results, firewall_rules)
        return jsonify({'image': image_data})
    except Exception as e:
        return jsonify({'error': f'Visualization failed: {str(e)}'}), 500


@app.route('/firewall/visualization')
def get_firewall_visualization():
    # This would typically get from a stored history
    sample_decisions = [
        {
            'source_ip': '192.168.1.100',
            'destination_ip': '8.8.8.8',
            'protocol': 'tcp',
            'port': 80,
            'action': 'allow',
            'matched_rule': 'Allow HTTP'
        }
    ]

    try:
        image_data = visualizer.create_firewall_flow_chart(sample_decisions)
        return jsonify({'image': image_data})
    except Exception as e:
        return jsonify({'error': f'Visualization failed: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)