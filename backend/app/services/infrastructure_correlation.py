import networkx as nx
import json
from typing import List, Dict, Any

class InfrastructureCorrelationService:
    @staticmethod
    def build_correlation_graph(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Builds a NetworkX graph correlating IPs, domains, and sender addresses across multiple cases.
        Returns graph data formatted for a frontend visualization library (like React Force Graph).
        """
        G = nx.Graph()
        
        # Nodes: Cases, IPs, Domains, Senders
        # Edges: Case -> IP, Case -> Domain, Case -> Sender
        
        for case in cases:
            case_id = f"Case_{case.get('id')}"
            G.add_node(case_id, type="case", name=f"Case #{case.get('id')}", classification=case.get('ai_classification'))
            
            sender = case.get('sender_email')
            if sender:
                sender_id = f"Sender_{sender}"
                G.add_node(sender_id, type="sender", name=sender)
                G.add_edge(case_id, sender_id)
                
            ip = case.get('source_ip')
            if ip:
                ip_id = f"IP_{ip}"
                G.add_node(ip_id, type="ip", name=ip, asn=case.get('asn_info'))
                G.add_edge(case_id, ip_id)
                
            # Parse extracted URLs/Domains (stored as JSON string or comma-separated in the DB)
            raw_domains = case.get('suspicious_domains')
            if raw_domains:
                try:
                    domains = json.loads(raw_domains)
                    for d in domains:
                        domain_name = d.get('domain')
                        if domain_name:
                            domain_id = f"Domain_{domain_name}"
                            G.add_node(domain_id, type="domain", name=domain_name)
                            G.add_edge(case_id, domain_id)
                except:
                    pass
                    
        # Find components (clusters of related activity)
        components = list(nx.connected_components(G))
        campaigns = []
        for i, component in enumerate(components):
            if len(component) > 2: # More than just one case and one attribute
                campaigns.append({
                    "campaign_id": i + 1,
                    "node_count": len(component),
                    "nodes": list(component)
                })
                
        # Format for frontend
        nodes = []
        for node, data in G.nodes(data=True):
            nodes.append({"id": node, **data})
            
        links = []
        for source, target in G.edges():
            links.append({"source": source, "target": target})
            
        return {
            "graph_data": {
                "nodes": nodes,
                "links": links
            },
            "campaigns": campaigns
        }
