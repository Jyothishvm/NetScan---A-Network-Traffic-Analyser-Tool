def generate_graph(report):
    """
    Parses the full analysis report and extracts Nodes (IPs, Domains)
    and Edges (Connections/Threats) for the React Flow frontend mapping.
    """
    nodes = []
    edges = []
    
    # Track unique node IDs to avoid duplicates
    seen_nodes = set()
    node_id_counter = 1
    edge_id_counter = 1
    
    # Store a mapping of string values (like an IP) to its React Flow node ID
    val_to_id = {}
    
    def add_node(val, n_type, label=None):
        nonlocal node_id_counter
        val_str = str(val)
        if val_str not in seen_nodes:
            node_id = f"node-{node_id_counter}"
            node_id_counter += 1
            
            # Determine visual styling based on node type
            bg_color = "#3b82f6" # Default Blue
            if n_type == "Victim":
                bg_color = "#ef4444" # Red
            elif n_type == "C2":
                bg_color = "#8b5cf6" # Purple
            elif n_type == "Internal":
                bg_color = "#10b981" # Green
            elif n_type == "Attacker":
                bg_color = "#f59e0b" # Orange
                
            nodes.append({
                "id": node_id,
                "data": {"label": label or val_str, "type": n_type},
                "position": {"x": 0, "y": 0}, # React Flow handles layout via a plugin like dagre, or we can randomise slightly
                "style": {"backgroundColor": bg_color, "color": "white", "border": "1px solid rgba(255,255,255,0.2)", "borderRadius": "8px", "padding": "10px", "fontWeight": "bold"}
            })
            seen_nodes.add(val_str)
            val_to_id[val_str] = node_id
            return node_id
        return val_to_id[val_str]

    def add_edge(src_id, dst_id, label, animated=False):
        nonlocal edge_id_counter
        # Avoid self-loops for graphical clarity if they accidentally occour
        if src_id == dst_id:
            return
            
        edge_id = f"e-{edge_id_counter}"
        edge_id_counter += 1
        edges.append({
            "id": edge_id,
            "source": src_id,
            "target": dst_id,
            "label": label,
            "animated": animated,
            "style": {"stroke": "#94a3b8", "strokeWidth": 2},
            "type": "smoothstep"
        })

    # 1. Add Victim Node first if identified (Anchor Node)
    victim_ip = None
    if report.get("victim") and report["victim"].get("most_compromised_host"):
        victim_ip = report["victim"]["most_compromised_host"]
        add_node(victim_ip, "Victim", label=f"🛡️ Victim\n{victim_ip}")
        
    # Helper to resolve IP to a generic type if not explicitly Victim or C2 yet
    def get_generic_type(ip):
        if ip == victim_ip:
            return "Victim"
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
            return "Internal"
        return "External"

    # 2. Extract C2 Relationships
    c2_data = report.get("c2", {}).get("findings", [])
    for c2 in c2_data:
        v_ip = c2.get("victim_ip")
        c2_ip = c2.get("c2_ip")
        if v_ip and c2_ip:
            v_id = add_node(v_ip, get_generic_type(v_ip))
            # C2 is explicitly marked Attacker metadata
            c2_id = add_node(c2_ip, "C2", label=f"☠️ C2 Server\n{c2_ip}")
            add_edge(v_id, c2_id, "Beaconing", animated=True)
            
    # 3. Extract Lateral Movement
    lateral_data = report.get("lateral", {}).get("findings", [])
    for lat in lateral_data:
        src = lat.get("source_ip")
        dst = lat.get("target_ip")
        if src and dst:
            src_id = add_node(src, get_generic_type(src))
            dst_id = add_node(dst, get_generic_type(dst))
            port = lat.get("port", "445")
            add_edge(src_id, dst_id, f"Scan {port}", animated=False)
            
    # 4. Extract DNS / DGA queries
    dns_data = report.get("dns", {}).get("findings", [])
    for d in dns_data:
        qry = d.get("query")
        if qry and victim_ip:
            # We assume victim made the query if unspecified by the basic reporter
            v_id = add_node(victim_ip, "Victim")
            dns_id = add_node(qry, "External", label=f"🌍 DNS\n{qry[:15]}...")
            add_edge(v_id, dns_id, d.get("type", "DNS Request"), animated=False)
            
    # 5. Extract Exfiltration
    exfil_data = report.get("exfil", {}).get("findings", [])
    for ex in exfil_data:
        src = ex.get("source_ip", victim_ip)
        dst = ex.get("destination_ip")
        if src and dst:
            src_id = add_node(src, get_generic_type(src))
            dst_id = add_node(dst, "Attacker", label=f"📦 Drop Zone\n{dst}")
            add_edge(src_id, dst_id, "High Vol Transfer", animated=True)
            
    # 6. Extract External Scans (Port Scans inbound/outbound)
    scan_data = report.get("port_scan", {}).get("findings", [])
    for sc in scan_data:
        src = sc.get("source_ip")
        if src:
            src_id = add_node(src, get_generic_type(src))
            # For massive port scans, we don't map every dest to avoid clutter. 
            # We map to a conceptual "Network" node.
            net_id = add_node(f"net_{src}", "Internal", label="Mass Network Scan")
            add_edge(src_id, net_id, "Port Sweep", animated=False)

    return {
        "nodes": nodes,
        "edges": edges
    }
