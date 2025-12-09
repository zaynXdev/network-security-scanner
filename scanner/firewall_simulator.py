from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class RuleAction(Enum):
    ALLOW = "allow"
    DENY = "deny"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


@dataclass
class FirewallRule:
    id: int
    name: str
    action: RuleAction
    source_ip: str
    destination_ip: str
    protocol: Protocol
    port: str
    priority: int
    enabled: bool = True


class FirewallSimulator:
    def __init__(self):
        self.rules: List[FirewallRule] = []
        self.rule_counter = 0
        self.default_action = RuleAction.ALLOW

    def add_rule(self, name: str, action: RuleAction, source_ip: str = "any",
                 destination_ip: str = "any", protocol: Protocol = Protocol.ANY,
                 port: str = "any", priority: int = None) -> FirewallRule:
        """Add a new firewall rule"""
        if priority is None:
            priority = len(self.rules) + 1

        rule = FirewallRule(
            id=self.rule_counter,
            name=name,
            action=action,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            priority=priority
        )

        self.rules.append(rule)
        self.rule_counter += 1
        self._sort_rules()
        return rule

    def _sort_rules(self):
        """Sort rules by priority (higher priority first)"""
        self.rules.sort(key=lambda x: x.priority, reverse=True)

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by ID"""
        self.rules = [rule for rule in self.rules if rule.id != rule_id]
        return True

    def evaluate_packet(self, source_ip: str, destination_ip: str,
                        protocol: str, port: int) -> Dict[str, Any]:
        """Evaluate if a packet should be allowed or denied"""
        packet_info = {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'protocol': protocol,
            'port': port,
            'action': self.default_action.value,
            'matched_rule': None,
            'rules_checked': []
        }

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check if rule matches
            if self._rule_matches(rule, source_ip, destination_ip, protocol, port):
                packet_info['action'] = rule.action.value
                packet_info['matched_rule'] = rule.name
                break

            packet_info['rules_checked'].append(rule.name)

        return packet_info

    def _rule_matches(self, rule: FirewallRule, source_ip: str, destination_ip: str,
                      protocol: str, port: int) -> bool:
        """Check if a rule matches the packet parameters"""
        # Check source IP
        if rule.source_ip != "any" and rule.source_ip != source_ip:
            return False

        # Check destination IP
        if rule.destination_ip != "any" and rule.destination_ip != destination_ip:
            return False

        # Check protocol
        if rule.protocol != Protocol.ANY and rule.protocol.value != protocol.lower():
            return False

        # Check port
        if rule.port != "any":
            if '-' in rule.port:
                # Port range
                start_port, end_port = map(int, rule.port.split('-'))
                if not (start_port <= port <= end_port):
                    return False
            else:
                # Single port
                if int(rule.port) != port:
                    return False

        return True

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules as dictionaries"""
        return [
            {
                'id': rule.id,
                'name': rule.name,
                'action': rule.action.value,
                'source_ip': rule.source_ip,
                'destination_ip': rule.destination_ip,
                'protocol': rule.protocol.value,
                'port': rule.port,
                'priority': rule.priority,
                'enabled': rule.enabled
            }
            for rule in self.rules
        ]