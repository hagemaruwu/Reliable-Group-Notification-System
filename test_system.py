"""
================================================================================
TEST_SYSTEM.PY - Performance Testing and Comparison Framework
================================================================================

Author: Aks Raj Singh

Purpose:
Compare reliability and performance of two UDP notification approaches:
1. RELIABLE MODE: ACK-based with retransmissions (guaranteed delivery)
2. PLAIN MODE: Best-effort, fire-and-forget (lower latency)

Key Metrics:
- Delivery Rate: % of messages received by clients (reliability measure)
- Retransmissions: Number of retry attempts (overhead measure)
- Latency: End-to-end time from server send to client receive

Test Methodology:
- Varying packet loss rates: 0%, 10%, 20%, 30%
- Multiple clients receiving broadcasts: 3 clients
- Fixed number of notifications: 5 messages per test
- Measures cumulative performance across all clients

Key Features:
- Simulated packet loss testing
- Multi-threaded client/server execution
- Latency measurement via embedded timestamps
- Matplotlib visualization of comparative results
"""

import time
import threading

# Import standard libraries
import math

# Try to import matplotlib for visualization (optional)
try:
    import matplotlib.pyplot as plt
    PLOTTING_ENABLED = True
except ImportError:
    print("[WARNING] matplotlib not installed. Graphs won't be saved. Run: pip install matplotlib")
    PLOTTING_ENABLED = False

# Import notification system implementations
from server import NotificationServer  # Reliable server with ACK and retransmission
from client import NotificationClient  # Reliable client with ACK and heartbeat
from plain_udp import PlainNotificationServer, PlainNotificationClient  # Best-effort baseline


def run_test(loss_rate, port, mode="reliable", num_clients=3, num_notifications=5):
    """
    Run a single test scenario comparing client/server notification delivery.
    
    Test Setup:
    - Creates server (reliable or best-effort)
    - Spawns multiple client instances
    - Broadcasts notifications
    - Measures delivery rate, retransmissions, and latency
    
    Args:
        loss_rate: Simulated packet loss (0.0 = 0%, 0.3 = 30%)
        port: UDP port for this test run
        mode: "reliable" or "plain" (best-effort)
        num_clients: Number of client instances to spawn
        num_notifications: Number of broadcasts to send
    
    Returns:
        (delivery_rate %, retransmission_count, avg_latency_seconds)
    """
    print(f"\n--- Running Test ({mode.upper()}): Loss Rate = {loss_rate*100:.0f}% on port {port} ---")

    # ===== INITIALIZE SERVER =====
    if mode == "reliable":
        # Reliable server with ACK handling and retransmission
        server = NotificationServer(port=port, loss_rate=loss_rate)
        # Start listen thread (handles SUBSCRIBE, ACK, HEARTBEAT)
        server_thread = threading.Thread(target=server.listen, daemon=True)
        # Start retransmission thread (handles timeouts and client eviction)
        retrans_thread = threading.Thread(target=server.retransmission_thread, daemon=True)
        server_thread.start()
        retrans_thread.start()
    else:
        # Best-effort server (simple, no reliability)
        server = PlainNotificationServer(port=port, loss_rate=loss_rate)
        # Start only listen thread (no retransmission needed)
        server_thread = threading.Thread(target=server.listen, daemon=True)
        server_thread.start()

    # ===== CREATE AND START CLIENT INSTANCES =====
    clients = []
    for i in range(num_clients):
        try:
            if mode == "reliable":
                # Reliable client with ACK and heartbeat
                client = NotificationClient(server_port=port, loss_rate=loss_rate, verbose=False)
                # Start listener thread (receives notifications, sends ACKs)
                t = threading.Thread(target=client.listen, daemon=True)
                t.start()
                # Start heartbeat thread (keeps-alive subscription)
                heartbeat_t = threading.Thread(target=client.heartbeat_loop, daemon=True)
                heartbeat_t.start()
            else:
                # Best-effort client (no ACK, no heartbeat)
                client = PlainNotificationClient(server_port=port, loss_rate=loss_rate)
                # Start listener thread only (receives but doesn't ACK)
                t = threading.Thread(target=client.listen, daemon=True)
                t.start()

            # Send subscription request
            client.subscribe()
            clients.append(client)
        except Exception as e:
            print(f"[ERROR] Client init failed: {e}")

    # ===== WAIT FOR ALL CLIENTS TO CONNECT AND SUBSCRIBE =====
    print("Waiting for all clients to subscribe...")
    start_wait = time.time()
    while len(server.subscribers) < num_clients and time.time() - start_wait < 5:
        # Retry subscription for clients that may have had packets dropped
        for c in clients:
            try:
                if len(server.subscribers) < num_clients:
                    c.subscribe()  # Retry subscription
            except Exception:
                pass
        time.sleep(1)

    # Check subscription success
    if len(server.subscribers) < num_clients:
        print(f"Warning: Only {len(server.subscribers)}/{num_clients} clients subscribed.")
    else:
        print("All clients subscribed. Starting broadcast.")

    # ===== BROADCAST TEST MESSAGES =====
    for i in range(num_notifications):
        try:
            # Send message to all subscribed clients
            server.broadcast(f"Test message {i+1}")
        except Exception as e:
            print(f"[ERROR] Broadcast failed: {e}")
        # Space out broadcasts to avoid network congestion
        time.sleep(0.5)

    # ===== WAIT FOR RETRANSMISSIONS (if reliable mode) =====
    if mode == "reliable":
        # Allow time for retransmission thread to retry unacked packets
        print("Waiting for retransmissions to complete...")
        time.sleep(5)  # Wait for 2+ retransmission cycles
    else:
        # Best-effort: just let packets settle
        time.sleep(1)

    # ===== CALCULATE PERFORMANCE METRICS =====
    # Expected: if num_clients=3 and num_notifications=5, expect 15 total deliveries
    total_expected = num_clients * num_notifications
    # Actual: count unique sequence numbers received across all clients
    total_received = sum(len(c.received_seqs) for c in clients)
    # Delivery Rate: % of messages successfully received
    delivery_rate = (total_received / total_expected) * 100 if total_expected > 0 else 0

    # Retransmissions: count of retry attempts (reliable mode only)
    retransmissions = getattr(server, "retransmission_count", 0)

    # ===== CALCULATE LATENCY STATISTICS =====
    # Collect latency measurements from all clients
    all_latencies = []
    for c in clients:
        if hasattr(c, 'latencies'):
            all_latencies.extend(c.latencies)
    # Average latency in seconds (will convert to ms for display)    
    avg_latency = float(sum(all_latencies) / len(all_latencies)) if all_latencies else 0.0

    # ===== PRINT TEST RESULTS =====
    print(f"Results for {mode.upper()} @ {loss_rate*100}% Loss:")
    print(f"  Delivery Rate: {delivery_rate:.2f}% ({total_received}/{total_expected})")
    print(f"  Retransmissions: {retransmissions}")
    print(f"  Average Latency: {avg_latency*1000:.2f} ms")

    # ===== CLEANUP =====
    # Stop server
    server.running = False
    # Stop and close all clients
    for c in clients:
        try:
            # Graceful unsubscribe if available
            if hasattr(c, 'unsubscribe'):
                c.unsubscribe()
            # Stop listener
            c.running = False
            # Close socket
            c.client_socket.close()
        except Exception:
            pass
    # Close server socket
    try:
        if server.server_socket:
            server.server_socket.close()
    except Exception:
        pass

    # Return metrics as tuple for graphing
    return delivery_rate, retransmissions, avg_latency


# Entry point for running all tests
if __name__ == "__main__":
    # ===== TEST CONFIGURATION =====
    # Packet loss rates to test: 0%, 10%, 20%, 30%
    loss_rates = [0.0, 0.1, 0.2, 0.3]

    # Collectors for metrics from reliable mode
    rel_delivery = []  # Delivery rate % for each loss rate
    rel_retrans = []   # Retransmission count for each loss rate
    rel_latency = []   # Average latency in ms for each loss rate
    
    # Collectors for metrics from best-effort mode
    plain_delivery = []  # Delivery rate % for each loss rate
    plain_latency = []   # Average latency in ms for each loss rate

    # ===== RUN TESTS FOR BOTH MODES ACROSS ALL LOSS RATES =====
    for i, lr in enumerate(loss_rates):
        # Use different ports to avoid address conflicts
        port_rel = 5000 + i*2         # 5000, 5002, 5004, 5006
        port_plain = 5000 + i*2 + 1   # 5001, 5003, 5005, 5007
        
        # ===== Test Reliable Mode =====
        print(f"\n========== TESTING RELIABLE MODE (Loss={lr*100:.0f}%) ==========")
        dr, rc, lat = run_test(lr, port_rel, mode="reliable")
        rel_delivery.append(dr)
        rel_retrans.append(rc)
        rel_latency.append(lat * 1000)  # Convert seconds to milliseconds
        
        # ===== Test Best-Effort Mode =====
        print(f"\n========== TESTING BEST-EFFORT MODE (Loss={lr*100:.0f}%) ==========")
        dr_p, _, lat_p = run_test(lr, port_plain, mode="plain")
        plain_delivery.append(dr_p)
        plain_latency.append(lat_p * 1000)  # Convert seconds to milliseconds

    # ===== VISUALIZE RESULTS =====
    if PLOTTING_ENABLED:
        # Plot comparative results
        try:
            # Create figure with 3 subplots
            fig, axes = plt.subplots(1, 3, figsize=(18, 5))

            # ===== Plot 1: Delivery Rate Comparison =====
            # Shows impact of reliability mechanisms on delivery guarantees
            axes[0].plot(loss_rates, rel_delivery, marker='o', label='Reliable UDP', color='blue', linewidth=2)
            axes[0].plot(loss_rates, plain_delivery, marker='x', label='Plain UDP', color='red', linestyle='--', linewidth=2)
            axes[0].set_xlabel('Packet Loss Rate')
            axes[0].set_ylabel('Delivery Rate (%)')
            axes[0].set_title('Delivery Rate Comparison\n(Higher = More Reliable)')
            axes[0].set_ylim(0, 105)
            axes[0].grid(True, alpha=0.3)
            axes[0].legend()

            # ===== Plot 2: Latency Comparison =====
            # Shows tradeoff: reliability adds latency (due to ACKs/retransmits)
            axes[1].plot(loss_rates, rel_latency, marker='o', label='Reliable UDP', color='blue', linewidth=2)
            axes[1].plot(loss_rates, plain_latency, marker='x', label='Plain UDP', color='red', linestyle='--', linewidth=2)
            axes[1].set_xlabel('Packet Loss Rate')
            axes[1].set_ylabel('Average Latency (ms)')
            axes[1].set_title('Average Latency Comparison\n(Lower = Faster Delivery)')
            axes[1].grid(True, alpha=0.3)
            axes[1].legend()

            # ===== Plot 3: Retransmission Overhead (Reliable Only) =====
            # Shows cost of reliability: number of retry attempts
            axes[2].bar(loss_rates, rel_retrans, width=0.04, color='orange', alpha=0.7)
            axes[2].set_xlabel('Packet Loss Rate')
            axes[2].set_ylabel('Total Retransmissions')
            axes[2].set_title('Reliable UDP Retransmission Overhead\n(Higher Loss = More Retries)')
            axes[2].grid(True, alpha=0.3, axis='y')

            # Overall title
            plt.suptitle('Reliable vs Best-Effort UDP Notification System', fontsize=14, fontweight='bold')
            plt.tight_layout()
            # Save results to file
            plt.savefig('performance_results.png', dpi=150)
            print("\n" + "="*70)
            print("Test completed. Results saved to 'performance_results.png'.")
            print("="*70)

        except Exception as e:
            print(f"[WARNING] Plotting failed: {e}")
    else:
        print("\n" + "="*70)
        print("Test completed. (Skipped saving graph since matplotlib is not installed).")
        print("Install matplotlib with: pip install matplotlib")
        print("="*70)