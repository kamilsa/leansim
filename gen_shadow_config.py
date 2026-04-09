import json
import random
import sys

def generate_config(num_nodes):
    SUBNETS = 1
    VALIDATORS_PER_SUBNET = num_nodes
    LOCAL_AGGREGATORS_PER_SUBNET = max(1, num_nodes // 10)
    
    config = {
        "general": {
            "stop_time": "60s"
        },
        "network": {
            "graph": {
                "type": "gml",
                "file": {
                    "path": "topology.gml"
                }
            }
        },
        "hosts": {}
    }

    nodes = []
    for s in range(SUBNETS):
        for i in range(VALIDATORS_PER_SUBNET):
            node_id = s * VALIDATORS_PER_SUBNET + i
            is_aggregator = i < LOCAL_AGGREGATORS_PER_SUBNET
            role = "local_aggregator" if is_aggregator else "validator"
            nodes.append({"id": node_id, "role": role, "subnet": s, "ip": f"10.{s}.{i//254}.{i%254 + 1}"})

    for node in nodes:
        peers = []
        subnet_nodes = [n for n in nodes if n["subnet"] == node["subnet"] and n["id"] != node["id"]]
        if subnet_nodes:
            peers.extend(random.sample(subnet_nodes, min(len(subnet_nodes), 8)))

        peer_addrs = [f"{p['ip']}:8080" for p in peers]
        
        # Use --use-optimized as a flag (no 'true')
        config["hosts"][f"node-{node['id']}"] = {
            "network_node_id": 0,
            "ip_addr": node["ip"],
            "bandwidth_down": "100 Mbit",
            "bandwidth_up": "100 Mbit",
            "processes": [{
                "path": "target/release/leansim",
                "args": f"--id {node['id']} --role {node['role']} --subnet {node['subnet']} --addr {node['ip']}:8080 --peers {','.join(peer_addrs)} --validators-per-subnet {VALIDATORS_PER_SUBNET} --use-optimized",
                "start_time": "1s"
            }]
        }

    with open("shadow.json", "w") as f:
        json.dump(config, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        generate_config(int(sys.argv[1]))
    else:
        generate_config(32)
