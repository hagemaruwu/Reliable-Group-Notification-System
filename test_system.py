"""
Author: Aks Raj Singh
Description:
This script tests the reliability of a UDP-based notification system
by simulating packet loss and measuring delivery performance, latency, 
and plotting comparative statistics against a Best-Effort UDP baseline.

Key Contributions:
- Implemented retry-based subscription handling
- Designed performance metrics (delivery rate, retransmissions, latency)
- Integrated visualization using matplotlib
"""

import time
import threading

# Safe matplotlib import
import math

try:
    import matplotlib.pyplot as plt
    PLOTTING_ENABLED = True
except ImportError:
    print("[WARNING] matplotlib not installed. Graphs won't be saved. Run: pip install matplotlib")
    PLOTTING_ENABLED = False

from server import NotificationServer
from client import NotificationClient
from plain_udp import PlainNotificationServer, PlainNotificationClient


def run_test(loss_rate, port, mode="reliable", num_clients=3, num_notifications=5):
    print(f"\n--- Running Test ({mode.upper()}): Loss Rate = {loss_rate*100:.0f}% on port {port} ---")

    # Initialize server
    if mode == "reliable":
        server = NotificationServer(port=port, loss_rate=loss_rate)
        server_thread = threading.Thread(target=server.listen, daemon=True)
        retrans_thread = threading.Thread(target=server.retransmission_thread, daemon=True)
        server_thread.start()
        retrans_thread.start()
    else:
        server = PlainNotificationServer(port=port, loss_rate=loss_rate)
        server_thread = threading.Thread(target=server.listen, daemon=True)
        server_thread.start()

    # Create and start clients
    clients = []
    for i in range(num_clients):
        try:
            if mode == "reliable":
                client = NotificationClient(server_port=port, loss_rate=loss_rate, verbose=False)
                t = threading.Thread(target=client.listen, daemon=True)
                t.start()
                heartbeat_t = threading.Thread(target=client.heartbeat_loop, daemon=True)
                heartbeat_t.start()
            else:
                client = PlainNotificationClient(server_port=port, loss_rate=loss_rate)
                t = threading.Thread(target=client.listen, daemon=True)
                t.start()

            client.subscribe()
            clients.append(client)
        except Exception as e:
            print(f"[ERROR] Client init failed: {e}")

    # Wait for subscriptions
    print("Waiting for all clients to subscribe...")
    start_wait = time.time()
    while len(server.subscribers) < num_clients and time.time() - start_wait < 5:
        for c in clients:
            try:
                if len(server.subscribers) < num_clients:
                    c.subscribe()
            except Exception:
                pass
        time.sleep(1)

    if len(server.subscribers) < num_clients:
        print(f"Warning: Only {len(server.subscribers)}/{num_clients} clients subscribed.")
    else:
        print("All clients subscribed. Starting broadcast.")

    # Broadcast test messages
    for i in range(num_notifications):
        try:
            server.broadcast(f"Test message {i+1}")
        except Exception as e:
            print(f"[ERROR] Broadcast failed: {e}")
        time.sleep(0.5)

    if mode == "reliable":
        time.sleep(5) # wait for retransmissions
    else:
        time.sleep(1)

    # Calculate metrics
    total_expected = num_clients * num_notifications
    total_received = sum(len(c.received_seqs) for c in clients)
    delivery_rate = (total_received / total_expected) * 100 if total_expected > 0 else 0

    retransmissions = getattr(server, "retransmission_count", 0)

    # Calculate average latency across all clients
    all_latencies = []
    for c in clients:
        if hasattr(c, 'latencies'):
            all_latencies.extend(c.latencies)
            
    avg_latency = float(sum(all_latencies) / len(all_latencies)) if all_latencies else 0.0

    print(f"Results for {mode.upper()} @ {loss_rate*100}% Loss:")
    print(f"  Delivery Rate: {delivery_rate:.2f}%")
    print(f"  Retransmissions: {retransmissions}")
    print(f"  Average Latency: {avg_latency*1000:.2f} ms")

    # Cleanup
    server.running = False
    for c in clients:
        try:
            if hasattr(c, 'unsubscribe'):
                c.unsubscribe()
            c.running = False
            c.client_socket.close()
        except Exception:
            pass
    try:
        if server.server_socket:
            server.server_socket.close()
    except Exception:
        pass

    return delivery_rate, retransmissions, avg_latency


if __name__ == "__main__":
    loss_rates = [0.0, 0.1, 0.2, 0.3]

    rel_delivery = []
    rel_retrans = []
    rel_latency = []
    
    plain_delivery = []
    plain_latency = []

    # Run tests for both modes
    for i, lr in enumerate(loss_rates):
        port_rel = 5000 + i*2
        port_plain = 5000 + i*2 + 1
        
        # Reliable Test
        dr, rc, lat = run_test(lr, port_rel, mode="reliable")
        rel_delivery.append(dr)
        rel_retrans.append(rc)
        rel_latency.append(lat * 1000) # Convert to ms
        
        # Best-Effort Test
        dr_p, _, lat_p = run_test(lr, port_plain, mode="plain")
        plain_delivery.append(dr_p)
        plain_latency.append(lat_p * 1000) # Convert to ms

    if PLOTTING_ENABLED:
        # Plot comparative results
        try:
            fig, axes = plt.subplots(1, 3, figsize=(18, 5))

            # 1. Delivery Rate Comp
            axes[0].plot(loss_rates, rel_delivery, marker='o', label='Reliable UDP', color='blue')
            axes[0].plot(loss_rates, plain_delivery, marker='x', label='Plain UDP', color='red', linestyle='--')
            axes[0].set_xlabel('Packet Loss Rate')
            axes[0].set_ylabel('Delivery Rate (%)')
            axes[0].set_title('Delivery Rate Comparison')
            axes[0].set_ylim(0, 105)
            axes[0].legend()

            # 2. Latency Comp
            axes[1].plot(loss_rates, rel_latency, marker='o', label='Reliable UDP', color='blue')
            axes[1].plot(loss_rates, plain_latency, marker='x', label='Plain UDP', color='red', linestyle='--')
            axes[1].set_xlabel('Packet Loss Rate')
            axes[1].set_ylabel('Average Latency (ms)')
            axes[1].set_title('Average Latency Comparison')
            axes[1].legend()

            # 3. Retransmissions (Reliable Only)
            axes[2].bar(loss_rates, rel_retrans, width=0.04, color='orange', alpha=0.7)
            axes[2].set_xlabel('Packet Loss Rate')
            axes[2].set_ylabel('Total Retransmissions')
            axes[2].set_title('Reliable UDP Retransmission Overhead')

            plt.suptitle('Reliable vs Best-Effort UDP Context Notification')
            plt.tight_layout()
            plt.savefig('performance_results.png')
            print("\nTest completed. Results saved to 'performance_results.png'.")

        except Exception as e:
            print(f"[WARNING] Plotting failed: {e}")
    else:
        print("\nTest completed. (Skipped saving graph since matplotlib is not installed).")