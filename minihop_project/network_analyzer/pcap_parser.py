import tempfile
from collections import Counter

import pyshark


def parse_pcap(uploaded_file):
    # Save uploaded file to a temp location
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        for chunk in uploaded_file.chunks():
            temp_file.write(chunk)
        temp_path = temp_file.name

    # Turn off summary to access packet layers
    capture = pyshark.FileCapture(temp_path, only_summaries=False)

    src_ips = Counter()
    dst_ips = Counter()
    protocols = Counter()

    for pkt in capture:
        try:
            print(f"Packet layers: {[layer.layer_name for layer in pkt.layers]}")

            if "IP" in pkt:
                src = pkt.ip.src
                dst = pkt.ip.dst
                src_ips[src] += 1
                dst_ips[dst] += 1
            elif "IPv6" in pkt:
                src = pkt.ipv6.src
                dst = pkt.ipv6.dst
                src_ips[src] += 1
                dst_ips[dst] += 1

            # Detect protocol
            proto = (
                pkt.transport_layer
                if hasattr(pkt, "transport_layer")
                else pkt.highest_layer
            )
            if proto:
                protocols[proto] += 1
        except AttributeError:
            print(f"Skipping a packet due to error: {e}")
            continue  # Skip packets without IP layer

    capture.close()

    return {
        "src_ips": src_ips.most_common(5),
        "dst_ips": dst_ips.most_common(5),
        "protocols": protocols.most_common(),
    }
