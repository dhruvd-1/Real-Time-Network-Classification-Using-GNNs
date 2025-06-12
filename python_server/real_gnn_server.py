import asyncio
import websockets
import json
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch_geometric.data import Data
from torch_geometric.nn import GATConv
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.impute import SimpleImputer
from datetime import datetime
import socket
import pickle
import joblib
import os


# Your exact GNN Model from training code
class GNN_Model(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes):
        super(GNN_Model, self).__init__()
        self.conv1 = GATConv(input_dim, hidden_dim, heads=4, concat=True)
        self.conv2 = GATConv(hidden_dim * 4, hidden_dim, heads=4, concat=True)
        self.conv3 = GATConv(hidden_dim * 4, hidden_dim, heads=1, concat=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = torch.relu(x)
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        x = torch.relu(x)
        x = self.dropout(x)
        x = self.conv3(x, edge_index)
        x = torch.relu(x)
        x = self.fc(x)
        return x


class RealGNNModel:
    def __init__(self, model_path="../models/gnn_intrusion_detection_model.pth"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.scaler = None
        self.label_encoders = {}
        self.feature_columns = self.get_nslkdd_features()
        self.categorical_cols = ["protocol_type", "service", "flag"]
        self.numeric_cols = [
            col for col in self.feature_columns if col not in self.categorical_cols
        ]
        self.input_dim = 123  # Will be updated after loading preprocessors

        self.load_model_and_preprocessors(model_path)

    def get_nslkdd_features(self):
        """NSL-KDD dataset feature names (41 features)"""
        return [
            "duration",
            "protocol_type",
            "service",
            "flag",
            "src_bytes",
            "dst_bytes",
            "land",
            "wrong_fragment",
            "urgent",
            "hot",
            "num_failed_logins",
            "logged_in",
            "num_compromised",
            "root_shell",
            "su_attempted",
            "num_root",
            "num_file_creations",
            "num_shells",
            "num_access_files",
            "num_outbound_cmds",
            "is_host_login",
            "is_guest_login",
            "count",
            "srv_count",
            "serror_rate",
            "srv_serror_rate",
            "rerror_rate",
            "srv_rerror_rate",
            "same_srv_rate",
            "diff_srv_rate",
            "srv_diff_host_rate",
            "dst_host_count",
            "dst_host_srv_count",
            "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate",
            "dst_host_serror_rate",
            "dst_host_srv_serror_rate",
            "dst_host_rerror_rate",
            "dst_host_srv_rerror_rate",
        ]

    def load_model_and_preprocessors(self, model_path):
        """Load trained model and preprocessors"""
        try:
            # Try to load preprocessing info first
            if os.path.exists("../models/preprocessing_info.pkl"):
                with open("../models/preprocessing_info.pkl", "rb") as f:
                    preprocessing_info = pickle.load(f)
                self.input_dim = preprocessing_info["input_dim"]
                print(f"✅ Loaded preprocessing info - Input dim: {self.input_dim}")

            # Load the trained model
            self.model = GNN_Model(
                input_dim=self.input_dim, hidden_dim=128, num_classes=2
            )

            if os.path.exists(model_path):
                self.model.load_state_dict(
                    torch.load(model_path, map_location=self.device)
                )
                print("✅ GNN Model loaded successfully")
            else:
                print(f"⚠️ Model file not found: {model_path}")
                print("Creating default model for demo...")

            self.model.to(self.device)
            self.model.eval()

            # Try to load saved preprocessors
            if os.path.exists("../models/scaler.pkl"):
                self.scaler = joblib.load("../models/scaler.pkl")
                print("✅ Scaler loaded")
            else:
                print("⚠️ Scaler not found, creating new one")
                self.setup_preprocessors()

        except Exception as e:
            print(f"❌ Error loading model: {e}")
            print("Creating default preprocessors...")
            self.setup_preprocessors()

    def setup_preprocessors(self):
        """Setup preprocessors matching training code"""
        self.scaler = StandardScaler()

        # Initialize label encoders for categorical features
        self.label_encoders = {
            "protocol_type": LabelEncoder(),
            "service": LabelEncoder(),
            "flag": LabelEncoder(),
        }

        # Fit encoders with NSL-KDD values
        protocols = ["tcp", "udp", "icmp"]
        services = [
            "http",
            "ftp",
            "telnet",
            "smtp",
            "dns",
            "ssh",
            "pop3",
            "imap",
            "https",
            "snmp",
            "finger",
            "nntp",
            "whois",
            "netbios_ns",
            "netbios_ssn",
            "netbios_dgm",
            "private",
            "pop_2",
            "ftp_data",
            "rje",
            "daytime",
            "ntp_u",
            "remote_job",
            "gopher",
            "uucp_path",
            "ldap",
            "sql_net",
            "vmnet",
            "bgp",
            "slp",
            "echo",
            "discard",
            "systat",
            "supdup",
            "iso_tsap",
            "hostnames",
            "csnet_ns",
            "pop_3",
            "sunrpc",
            "uucp",
            "netstat",
            "nnsp",
            "link",
            "X11",
            "IRC",
            "Z39_50",
            "printer",
            "domain_u",
            "klogin",
            "kshell",
            "login",
            "shell",
            "exec",
            "auth",
            "imap4",
            "efs",
            "name",
            "ecr_i",
            "tim_i",
        ]
        flags = [
            "SF",
            "S0",
            "REJ",
            "RSTR",
            "RSTO",
            "SH",
            "S1",
            "S2",
            "S3",
            "OTH",
            "RSTOS0",
        ]

        self.label_encoders["protocol_type"].fit(protocols)
        self.label_encoders["service"].fit(services)
        self.label_encoders["flag"].fit(flags)

        print("✅ Preprocessors initialized")

    def preprocess_esp32_data(self, esp32_data):
        """Convert ESP32 data to match training preprocessing exactly"""
        try:
            # Create feature dictionary matching NSL-KDD format
            features = {}

            # Map ESP32 data to NSL-KDD features
            for col_name in self.feature_columns:
                if col_name in esp32_data:
                    features[col_name] = esp32_data[col_name]
                else:
                    # Set intelligent default values for missing features
                    defaults = {
                        "duration": esp32_data.get("duration", 1),
                        "src_bytes": esp32_data.get("src_bytes", 100),
                        "dst_bytes": esp32_data.get("dst_bytes", 100),
                        "count": esp32_data.get("count", 1),
                        "srv_count": esp32_data.get("srv_count", 1),
                        "serror_rate": esp32_data.get("serror_rate", 0.0),
                        "srv_serror_rate": esp32_data.get("srv_serror_rate", 0.0),
                        "rerror_rate": esp32_data.get("rerror_rate", 0.0),
                        "srv_rerror_rate": esp32_data.get("srv_rerror_rate", 0.0),
                        "same_srv_rate": esp32_data.get("same_srv_rate", 1.0),
                        "diff_srv_rate": esp32_data.get("diff_srv_rate", 0.0),
                        "protocol_type": esp32_data.get("protocol_type", "tcp"),
                        "service": esp32_data.get("service", "http"),
                        "flag": esp32_data.get("flag", "SF"),
                        "dst_host_count": esp32_data.get("dst_host_count", 1),
                    }
                    features[col_name] = defaults.get(col_name, 0)

            # Create DataFrame
            df = pd.DataFrame([features])

            # Handle categorical columns - encode them first
            for col in self.categorical_cols:
                if col in df.columns:
                    try:
                        # Transform using fitted encoder
                        df[col] = self.label_encoders[col].transform(
                            df[col].astype(str)
                        )
                    except (ValueError, KeyError):
                        # Handle unknown categories
                        df[col] = 0

            # Separate numeric and categorical for processing
            numeric_data = df[self.numeric_cols].astype(float)
            categorical_data = df[self.categorical_cols]

            # Apply one-hot encoding to categorical features
            categorical_encoded = pd.get_dummies(
                categorical_data, dummy_na=False, drop_first=False
            )

            # Combine processed features
            processed_df = pd.concat([numeric_data, categorical_encoded], axis=1)

            # Apply scaling to numeric columns only
            numeric_col_names = self.numeric_cols
            if hasattr(self.scaler, "transform") and len(numeric_col_names) > 0:
                try:
                    # Create a copy for scaling
                    scaled_numeric = self.scaler.transform(numeric_data)
                    processed_df[numeric_col_names] = scaled_numeric
                except Exception as e:
                    print(f"⚠️ Scaling failed: {e}")

            # Ensure we have the right number of features
            feature_vector = processed_df.values[0]

            # Pad or truncate to match expected input dimension
            if len(feature_vector) < self.input_dim:
                # Pad with zeros
                padded_vector = np.zeros(self.input_dim)
                padded_vector[: len(feature_vector)] = feature_vector
                feature_vector = padded_vector
            elif len(feature_vector) > self.input_dim:
                # Truncate
                feature_vector = feature_vector[: self.input_dim]

            return feature_vector

        except Exception as e:
            print(f"❌ Error preprocessing data: {e}")
            # Return default feature vector
            return np.zeros(self.input_dim)

    def predict_anomaly(self, esp32_data_list):
        """Run GNN inference on processed ESP32 data"""
        try:
            if len(esp32_data_list) < 3:
                print("⚠️ Need at least 3 nodes for graph construction")
                return [0] * len(esp32_data_list), [0.1] * len(esp32_data_list)

            # Preprocess all node data
            processed_features = []
            for data in esp32_data_list:
                features = self.preprocess_esp32_data(data)
                processed_features.append(features)

            # Convert to tensor
            x = torch.tensor(processed_features, dtype=torch.float32).to(self.device)

            # Create KNN graph structure
            edge_index = self.create_knn_graph(processed_features)
            edge_index = edge_index.to(self.device)

            # Create PyG Data object
            graph_data = Data(x=x, edge_index=edge_index)

            # Run inference
            self.model.eval()
            with torch.no_grad():
                output = self.model(graph_data)
                probabilities = torch.softmax(output, dim=1)
                predictions = torch.argmax(output, dim=1)

            # Convert to CPU and return
            pred_probs = probabilities[:, 1].cpu().numpy()  # Anomaly probabilities
            pred_labels = predictions.cpu().numpy()

            return pred_labels, pred_probs

        except Exception as e:
            print(f"❌ Error in GNN prediction: {e}")
            # Fallback to simple rule-based detection
            return self.fallback_detection(esp32_data_list)

    def fallback_detection(self, esp32_data_list):
        """Simple rule-based fallback when GNN fails"""
        predictions = []
        probabilities = []

        for data in esp32_data_list:
            score = 0

            # Simple anomaly scoring
            if data.get("count", 0) > 100:
                score += 0.3
            if data.get("srv_count", 0) > 100:
                score += 0.3
            if data.get("serror_rate", 0) > 0.5:
                score += 0.2
            if data.get("dst_host_count", 0) > 50:
                score += 0.2
            if data.get("num_failed_logins", 0) > 3:
                score += 0.3
            if data.get("root_shell", 0) == 1:
                score += 0.5
            if data.get("flag") == "REJ":
                score += 0.2

            is_anomaly = 1 if score > 0.6 else 0
            predictions.append(is_anomaly)
            probabilities.append(min(score, 1.0))

        return predictions, probabilities

    def create_knn_graph(self, features, k=5):
        """Create KNN graph structure matching training approach"""
        try:
            n_nodes = len(features)
            k = min(k, n_nodes - 1)

            if k <= 0:
                return torch.empty((2, 0), dtype=torch.long)

            # Use KNN to create graph
            knn = NearestNeighbors(n_neighbors=k + 1)
            knn.fit(features)
            distances, indices = knn.kneighbors(features)

            # Create edge pairs (skip self-connections)
            edges = []
            for i in range(n_nodes):
                for j in range(1, len(indices[i])):  # Skip first (self)
                    edges.append([i, indices[i][j]])

            if edges:
                edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
            else:
                edge_index = torch.empty((2, 0), dtype=torch.long)

            return edge_index

        except Exception as e:
            print(f"❌ Error creating graph: {e}")
            # Fallback: simple chain graph
            n_nodes = len(features)
            edges = [[i, (i + 1) % n_nodes] for i in range(n_nodes - 1)]
            if edges:
                return torch.tensor(edges, dtype=torch.long).t().contiguous()
            else:
                return torch.empty((2, 0), dtype=torch.long)


# Global data storage
connected_nodes = {}
anomaly_alerts = []
all_data_history = []
node_statistics = {}

# Initialize GNN model
print("🧠 Initializing Real GNN Model...")
try:
    gnn_model = RealGNNModel("../models/gnn_intrusion_detection_model.pth")
    print("✅ GNN Model initialized successfully")
except Exception as e:
    print(f"❌ Error initializing GNN model: {e}")
    gnn_model = None


# NEW (FIXED) VERSION:
async def handle_esp32(websocket):
    client_ip = websocket.remote_address[0]
    print(f"🔌 ESP32 connected: {client_ip}")

    try:
        async for message in websocket:
            try:
                data = json.loads(message)

                # Handle different message types
                if data.get("type") == "init":
                    node_id = data.get("node_id", "unknown")
                    print(f"🆔 Node {node_id} initialized")
                    continue

                node_id = data.get("node_id", "unknown")

                # Store node data
                connected_nodes[node_id] = {
                    "data": data,
                    "timestamp": datetime.now(),
                    "websocket": websocket,
                    "ip": client_ip,
                }

                # Update statistics
                if node_id not in node_statistics:
                    node_statistics[node_id] = {
                        "total_packets": 0,
                        "anomaly_count": 0,
                        "last_seen": datetime.now(),
                    }

                node_statistics[node_id]["total_packets"] += 1
                node_statistics[node_id]["last_seen"] = datetime.now()

                # Add to history
                all_data_history.append(
                    {
                        **data,
                        "received_time": datetime.now().isoformat(),
                        "client_ip": client_ip,
                    }
                )

                # Keep only last 200 records
                if len(all_data_history) > 200:
                    all_data_history.pop(0)

                print(
                    f"📡 Data from Node {node_id} - {data.get('attack_type', 'normal')}"
                )

                # Run GNN anomaly detection when we have enough nodes
                if len(connected_nodes) >= 3 and gnn_model is not None:
                    await run_gnn_detection()

            except json.JSONDecodeError:
                print("❌ Invalid JSON received")
            except Exception as e:
                print(f"❌ Error processing message: {e}")

    except websockets.exceptions.ConnectionClosed:
        print(f"🔌 ESP32 disconnected: {client_ip}")
        # Remove disconnected node
        for node_id, info in list(connected_nodes.items()):
            if info["ip"] == client_ip:
                del connected_nodes[node_id]
                print(f"🗑️ Removed node {node_id}")
                break
    except Exception as e:
        print(f"❌ Connection error: {e}")


async def run_gnn_detection():
    """Run GNN model on current connected nodes"""
    try:
        # Get data from all connected nodes
        node_data_list = []
        node_ids = []

        for node_id, info in connected_nodes.items():
            node_data_list.append(info["data"])
            node_ids.append(node_id)

        if len(node_data_list) < 3:
            return

        # Run GNN prediction
        predictions, probabilities = gnn_model.predict_anomaly(node_data_list)

        # Process results
        for i, node_id in enumerate(node_ids):
            is_anomaly = predictions[i] == 1
            confidence = probabilities[i]

            # Update statistics
            if is_anomaly:
                node_statistics[node_id]["anomaly_count"] += 1

            # Alert threshold
            if is_anomaly and confidence > 0.7:
                alert = {
                    "node_id": node_id,
                    "confidence": float(confidence),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "data": connected_nodes[node_id]["data"],
                    "alert_time": datetime.now().isoformat(),
                    "detection_method": "GNN_Model",
                    "attack_type": connected_nodes[node_id]["data"].get(
                        "attack_type", "unknown"
                    ),
                }

                anomaly_alerts.append(alert)
                if len(anomaly_alerts) > 100:
                    anomaly_alerts.pop(0)

                print(f"🚨 GNN ANOMALY DETECTED: Node {node_id}")
                print(f"   Attack Type: {alert['attack_type']}")
                print(f"   Confidence: {confidence:.3f}")

                # Send alert back to ESP32
                alert_response = {
                    "type": "gnn_anomaly_alert",
                    "confidence": float(confidence),
                    "attack_type": alert["attack_type"],
                    "message": f"GNN detected {alert['attack_type']} with {confidence:.1%} confidence",
                }

                websocket = connected_nodes[node_id]["websocket"]
                try:
                    await websocket.send(json.dumps(alert_response))
                except Exception as e:
                    print(f"❌ Failed to send alert to Node {node_id}: {e}")

    except Exception as e:
        print(f"❌ Error in GNN detection: {e}")


async def send_status_requests():
    """Periodically request status from all nodes"""
    while True:
        try:
            await asyncio.sleep(30)  # Every 30 seconds

            if connected_nodes:
                status_request = {"type": "status_request"}
                status_msg = json.dumps(status_request)

                for node_id, info in connected_nodes.items():
                    try:
                        await info["websocket"].send(status_msg)
                    except:
                        pass  # Node might be disconnected

        except Exception as e:
            print(f"❌ Error in status requests: {e}")


def find_available_port(start_port=8080, max_attempts=10):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            # Test if port is available
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind(("0.0.0.0", port))
            test_socket.close()
            return port
        except OSError:
            continue
    return None


async def start_websocket_server():
    """Start the WebSocket server with automatic port finding"""
    print("🚀 Starting Real GNN-IDS WebSocket server...")

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"💻 Server IP: {local_ip}")

    # Find available port
    port = find_available_port(8081, 20)
    if port is None:
        print("❌ Could not find available port!")
        return

    print(f"🔌 Using port: {port}")
    print(f'📝 Update ESP32 code: const char* server_ip = "{local_ip}";')
    print(f"📝 Update ESP32 code: const int server_port = {port};")

    try:
        # Start WebSocket server
        start_server = websockets.serve(handle_esp32, "0.0.0.0", 8081)

        # Start status request task
        status_task = asyncio.create_task(send_status_requests())

        print(f"✅ Real GNN-IDS WebSocket server started on port {port}!")

        await start_server
        await status_task

    except Exception as e:
        print(f"❌ Failed to start server on port {port}: {e}")
        print("💡 Try running as Administrator or check Windows Firewall settings")


def run_server():
    """Run the server with proper asyncio setup"""
    try:
        asyncio.run(start_websocket_server())
    except KeyboardInterrupt:
        print("\n👋 Real GNN-IDS Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")


if __name__ == "__main__":
    print("=" * 70)
    print("🛡️  REAL GNN-IDS SERVER STARTED")
    print("=" * 70)
    print("🧠 Using your trained GNN model for anomaly detection")
    print("📊 NSL-KDD feature processing active")
    print("🔗 Graph construction with KNN (k=5)")
    print("⚡ Real-time WebSocket communication")
    print("📈 Advanced statistics and monitoring")
    print("=" * 70)
    print("Next steps:")
    print("1. Update ESP32 code with the IP address and port shown below")
    print("2. Program and power on ESP32 devices")
    print("3. Run: streamlit run dashboard.py")
    print("4. Open: http://localhost:8501")
    print("=" * 70)

    # Run the server
    run_server()
