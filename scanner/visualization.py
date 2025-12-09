import matplotlib

matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import networkx as nx
from io import BytesIO
import base64
from typing import Dict, List, Any


class NetworkVisualizer:
    def __init__(self):
        self.graph = nx.DiGraph()

    def create_network_graph(self, scan_results: Dict[str, Any], firewall_rules: List[Dict[str, Any]]) -> str:
        """Create a network visualization graph"""
        plt.figure(figsize=(12, 8))
        self.graph.clear()

        # Add nodes for scanned hosts
        for host, info in scan_results.get('hosts', {}).items():
            if info['state'] == 'up':
                self.graph.add_node(host, type='host', state=info['state'])

        # Add firewall node
        self.graph.add_node('Firewall', type='firewall')

        # Add edges for network traffic
        for host in scan_results.get('hosts', {}).keys():
            if scan_results['hosts'][host]['state'] == 'up':
                self.graph.add_edge('Internet', host, label='traffic')
                self.graph.add_edge(host, 'Firewall', label='traffic')

        # Position nodes
        pos = nx.spring_layout(self.graph, k=3, iterations=50)

        # Draw nodes
        node_colors = []
        for node in self.graph.nodes():
            if self.graph.nodes[node].get('type') == 'firewall':
                node_colors.append('red')
            else:
                node_colors.append('lightblue')

        nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors,
                               node_size=2000, alpha=0.9)

        # Draw edges
        nx.draw_networkx_edges(self.graph, pos, edge_color='gray',
                               arrows=True, arrowsize=20)

        # Draw labels
        nx.draw_networkx_labels(self.graph, pos, font_size=10,
                                font_weight='bold')

        edge_labels = nx.get_edge_attributes(self.graph, 'label')
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels)

        plt.title("Network Security Visualization")
        plt.axis('off')

        # Save to base64 string
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()

        return f"data:image/png;base64,{image_base64}"

    def create_firewall_flow_chart(self, packet_decisions: List[Dict[str, Any]]) -> str:
        """Create a flowchart showing firewall decision process"""
        fig, ax = plt.subplots(figsize=(10, 6))

        # Simple text-based visualization
        y_pos = 0.9
        ax.text(0.1, 1.0, "Firewall Traffic Flow", fontsize=16, fontweight='bold')

        for i, decision in enumerate(packet_decisions[-10:]):  # Show last 10 decisions
            color = 'green' if decision['action'] == 'allow' else 'red'
            text = f"{decision['source_ip']}:{decision['port']} -> {decision['destination_ip']} : {decision['action'].upper()}"
            if decision['matched_rule']:
                text += f" (Rule: {decision['matched_rule']})"

            ax.text(0.1, y_pos, text, fontsize=10, color=color)
            y_pos -= 0.08

        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')

        # Save to base64 string
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()

        return f"data:image/png;base64,{image_base64}"