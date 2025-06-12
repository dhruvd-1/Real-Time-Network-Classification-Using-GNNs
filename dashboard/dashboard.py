import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import time
import json
import random
import numpy as np

# Page configuration
st.set_page_config(
    page_title="Real GNN-IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize session state for simulated data
if "connected_nodes" not in st.session_state:
    st.session_state.connected_nodes = {}
if "anomaly_alerts" not in st.session_state:
    st.session_state.anomaly_alerts = []
if "all_data_history" not in st.session_state:
    st.session_state.all_data_history = []
if "node_statistics" not in st.session_state:
    st.session_state.node_statistics = {}
if "total_packets" not in st.session_state:
    st.session_state.total_packets = 0
if "start_time" not in st.session_state:
    st.session_state.start_time = datetime.now()

# Enhanced Custom CSS for futuristic styling
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
    
    .main-header {
        font-family: 'Orbitron', monospace;
        font-size: 3rem;
        font-weight: 900;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(45deg, #00ff88, #0099ff, #ff0099, #ffaa00);
        background-size: 400% 400%;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: gradientShift 3s ease-in-out infinite;
        text-shadow: 0 0 30px rgba(0, 255, 136, 0.5);
    }
    
    @keyframes gradientShift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    .cyber-subtitle {
        font-family: 'Orbitron', monospace;
        text-align: center;
        color: #00ff88;
        font-size: 1.2rem;
        margin-bottom: 2rem;
        text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
    }
    
    .metric-card {
        background: linear-gradient(135deg, rgba(0, 255, 136, 0.1), rgba(0, 153, 255, 0.1));
        padding: 1.5rem;
        border-radius: 15px;
        border: 2px solid rgba(0, 255, 136, 0.3);
        box-shadow: 0 8px 32px rgba(0, 255, 136, 0.2);
        backdrop-filter: blur(10px);
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 40px rgba(0, 255, 136, 0.4);
        border-color: rgba(0, 255, 136, 0.6);
    }
    
    .anomaly-alert {
        background: linear-gradient(135deg, rgba(255, 0, 153, 0.2), rgba(255, 68, 54, 0.2));
        border: 2px solid #ff0099;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 0.5rem 0;
        box-shadow: 0 8px 32px rgba(255, 0, 153, 0.3);
        backdrop-filter: blur(10px);
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { box-shadow: 0 8px 32px rgba(255, 0, 153, 0.3); }
        50% { box-shadow: 0 8px 32px rgba(255, 0, 153, 0.6); }
        100% { box-shadow: 0 8px 32px rgba(255, 0, 153, 0.3); }
    }
    
    .normal-status {
        background: linear-gradient(135deg, rgba(0, 255, 136, 0.2), rgba(76, 175, 80, 0.2));
        border: 2px solid #00ff88;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 0.5rem 0;
        box-shadow: 0 8px 32px rgba(0, 255, 136, 0.3);
        backdrop-filter: blur(10px);
    }
    
    .stMetric {
        background: linear-gradient(135deg, rgba(0, 153, 255, 0.1), rgba(0, 255, 136, 0.1));
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid rgba(0, 255, 136, 0.3);
        backdrop-filter: blur(5px);
    }
    
    .cyber-grid {
        background-image: 
            linear-gradient(rgba(0, 255, 136, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 255, 136, 0.1) 1px, transparent 1px);
        background-size: 20px 20px;
    }
    
    .status-online {
        color: #00ff88;
        text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
        font-weight: bold;
    }
    
    .status-critical {
        color: #ff0099;
        text-shadow: 0 0 10px rgba(255, 0, 153, 0.5);
        font-weight: bold;
    }
    
    .node-card {
        background: linear-gradient(135deg, rgba(0, 153, 255, 0.1), rgba(0, 255, 136, 0.1));
        border: 2px solid rgba(0, 153, 255, 0.3);
        border-radius: 15px;
        padding: 1rem;
        margin: 0.5rem 0;
        backdrop-filter: blur(10px);
        transition: all 0.3s ease;
    }
    
    .node-card:hover {
        border-color: rgba(0, 153, 255, 0.6);
        transform: scale(1.02);
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(0, 153, 255, 0.1));
        backdrop-filter: blur(10px);
    }
    
    /* Matrix rain effect */
    .matrix-bg {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        z-index: -1;
        opacity: 0.05;
    }
</style>
""",
    unsafe_allow_html=True,
)


# Simulation functions
def generate_esp32_data(node_id, is_anomaly=False):
    """Generate realistic ESP32 network data"""
    attack_types = ["dos", "portscan", "r2l", "u2r", "probe", "normal"]

    if is_anomaly:
        attack_type = random.choice(attack_types[:-1])  # Exclude 'normal'
        base_multiplier = random.uniform(3, 10)
    else:
        attack_type = "normal"
        base_multiplier = 1

    data = {
        "node_id": node_id,
        "duration": random.randint(1, 300) * base_multiplier,
        "protocol_type": random.choice(["tcp", "udp", "icmp"]),
        "service": random.choice(["http", "ftp", "smtp", "telnet", "ssh", "dns"]),
        "flag": random.choice(["SF", "S0", "REJ", "RSTR", "SH"]),
        "src_bytes": random.randint(0, 10000) * base_multiplier,
        "dst_bytes": random.randint(0, 10000) * base_multiplier,
        "count": random.randint(1, 100) * base_multiplier,
        "srv_count": random.randint(1, 50) * base_multiplier,
        "serror_rate": random.uniform(0, 0.5) * base_multiplier,
        "same_srv_rate": random.uniform(0.5, 1.0),
        "dst_host_count": random.randint(1, 255),
        "num_failed_logins": random.randint(0, 5) * base_multiplier
        if is_anomaly
        else 0,
        "root_shell": 1 if is_anomaly and random.random() > 0.7 else 0,
        "wifi_rssi": random.randint(-80, -30),
        "is_anomaly": is_anomaly,
        "attack_type": attack_type,
        "received_time": datetime.now().isoformat(),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }
    return data


def update_simulation():
    """Update the simulation with new data"""
    # Simulate 3-5 ESP32 nodes
    node_ids = ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004", "ESP32_005"]

    # Add new data points periodically
    for node_id in node_ids:
        # 20% chance of anomaly
        is_anomaly = random.random() < 0.2

        # Generate new data
        new_data = generate_esp32_data(node_id, is_anomaly)

        # Update connected nodes
        st.session_state.connected_nodes[node_id] = {
            "data": new_data,
            "timestamp": datetime.now(),
        }

        # Add to history
        st.session_state.all_data_history.append(new_data)

        # Update node statistics
        if node_id not in st.session_state.node_statistics:
            st.session_state.node_statistics[node_id] = {
                "total_packets": 0,
                "anomaly_count": 0,
            }

        st.session_state.node_statistics[node_id]["total_packets"] += 1
        if is_anomaly:
            st.session_state.node_statistics[node_id]["anomaly_count"] += 1

            # Add anomaly alert
            alert = {
                "node_id": node_id,
                "confidence": random.uniform(0.7, 0.99),
                "attack_type": new_data["attack_type"],
                "alert_time": datetime.now().isoformat(),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
            st.session_state.anomaly_alerts.append(alert)

        st.session_state.total_packets += 1

    # Keep only last 1000 data points to prevent memory issues
    if len(st.session_state.all_data_history) > 1000:
        st.session_state.all_data_history = st.session_state.all_data_history[-1000:]

    # Keep only last 50 alerts
    if len(st.session_state.anomaly_alerts) > 50:
        st.session_state.anomaly_alerts = st.session_state.anomaly_alerts[-50:]


# Matrix rain background effect
st.markdown(
    """
    <div class="matrix-bg">
        <canvas id="matrixCanvas"></canvas>
    </div>
    <script>
        const canvas = document.getElementById('matrixCanvas');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const katakana = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッン';
        const latin = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const nums = '0123456789';
        const alphabet = katakana + latin + nums;
        
        const fontSize = 16;
        const columns = canvas.width/fontSize;
        const rainDrops = [];
        
        for( let x = 0; x < columns; x++ ) {
            rainDrops[x] = 1;
        }
        
        const draw = () => {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.fillStyle = '#0F3';
            ctx.font = fontSize + 'px monospace';
            
            for(let i = 0; i < rainDrops.length; i++) {
                const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                ctx.fillText(text, i*fontSize, rainDrops[i]*fontSize);
                
                if(rainDrops[i]*fontSize > canvas.height && Math.random() > 0.975){
                    rainDrops[i] = 0;
                }
                rainDrops[i]++;
            }
        };
        
        setInterval(draw, 30);
    </script>
    """,
    unsafe_allow_html=True,
)

# Title and header with enhanced styling
st.markdown(
    '<h1 class="main-header">🛡️ CYBER-GNN DEFENSE MATRIX</h1>', unsafe_allow_html=True
)
st.markdown(
    '<p class="cyber-subtitle">⚡ REAL-TIME QUANTUM NEURAL NETWORK INTRUSION DETECTION ⚡</p>',
    unsafe_allow_html=True,
)

# Sidebar controls with enhanced styling
with st.sidebar:
    st.markdown("### ⚙️ CONTROL MATRIX")

    # Auto-refresh settings
    auto_refresh = st.checkbox("🔄 NEURAL SYNC", value=True)
    refresh_rate = st.selectbox("Sync Frequency (seconds)", [1, 2, 5, 10], index=1)

    st.divider()

    # Filter controls
    st.markdown("### 🔍 THREAT FILTERS")
    show_only_anomalies = st.checkbox("⚠️ Anomalies Only", value=False)

    # Attack type filter
    if st.session_state.all_data_history:
        attack_types = list(
            set(
                [
                    d.get("attack_type", "normal")
                    for d in st.session_state.all_data_history
                ]
            )
        )
        selected_attack_types = st.multiselect(
            "Attack Vectors", attack_types, default=attack_types
        )
    else:
        selected_attack_types = []

    st.divider()

    # System status with enhanced visuals
    st.markdown("### 📊 SYSTEM STATUS")
    uptime = datetime.now() - st.session_state.start_time
    uptime_str = str(uptime).split(".")[0]

    st.markdown(
        f'<p class="status-online">✅ MATRIX ONLINE</p>', unsafe_allow_html=True
    )
    st.metric("🔗 Neural Nodes", len(st.session_state.connected_nodes))
    st.metric("⚠️ Threat Alerts", len(st.session_state.anomaly_alerts))
    st.metric("📊 Data Points", len(st.session_state.all_data_history))
    st.metric("⏱️ Uptime", uptime_str)

    # Threat level indicator
    recent_anomalies = len(
        [
            a
            for a in st.session_state.anomaly_alerts
            if datetime.fromisoformat(a["alert_time"])
            > datetime.now() - timedelta(minutes=5)
        ]
    )

    if recent_anomalies >= 3:
        threat_level = "🔴 CRITICAL"
        threat_color = "status-critical"
    elif recent_anomalies >= 1:
        threat_level = "🟠 ELEVATED"
        threat_color = "status-critical"
    else:
        threat_level = "🟢 SECURE"
        threat_color = "status-online"

    st.markdown(
        f'<p class="{threat_color}">🛡️ THREAT LEVEL: {threat_level}</p>',
        unsafe_allow_html=True,
    )

    st.divider()

    # Manual controls
    st.markdown("### 🎛️ MANUAL OVERRIDE")
    if st.button("🔄 FORCE SYNC"):
        update_simulation()
        st.rerun()

    if st.button("🧹 PURGE DATA"):
        st.session_state.anomaly_alerts.clear()
        st.session_state.all_data_history.clear()
        st.success("Data purged!")
        time.sleep(1)
        st.rerun()

# Update simulation data
update_simulation()

# Auto-refresh logic
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()

# Enhanced metrics row with futuristic cards
st.markdown("### 🎯 REAL-TIME METRICS")
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        label="🔗 Active Nodes",
        value=len(st.session_state.connected_nodes),
        delta=f"+{len(st.session_state.connected_nodes)}",
    )

with col2:
    recent_anomalies = len(
        [
            a
            for a in st.session_state.anomaly_alerts
            if datetime.fromisoformat(a["alert_time"])
            > datetime.now() - timedelta(minutes=5)
        ]
    )
    st.metric(
        label="🚨 Active Threats",
        value=recent_anomalies,
        delta=f"+{recent_anomalies}" if recent_anomalies > 0 else None,
    )

with col3:
    if st.session_state.all_data_history:
        normal_count = len(
            [
                d
                for d in st.session_state.all_data_history
                if not d.get("is_anomaly", False)
            ]
        )
        detection_rate = (
            (len(st.session_state.all_data_history) - normal_count)
            / len(st.session_state.all_data_history)
            * 100
        )
        st.metric(
            label="🎯 Detection Rate",
            value=f"{detection_rate:.1f}%",
            delta=f"{detection_rate:.1f}%",
        )
    else:
        st.metric(label="🎯 Detection Rate", value="0%")

with col4:
    if st.session_state.node_statistics:
        avg_packets = sum(
            [
                stats["total_packets"]
                for stats in st.session_state.node_statistics.values()
            ]
        ) / len(st.session_state.node_statistics)
        st.metric(
            label="📊 Avg Packets/Node",
            value=f"{avg_packets:.0f}",
            delta=f"+{avg_packets:.0f}",
        )
    else:
        st.metric(label="📊 Avg Packets/Node", value="0")

with col5:
    current_time = datetime.now().strftime("%H:%M:%S")
    st.metric(label="🕐 System Time", value=current_time)

st.divider()

# Main content area with enhanced visuals
left_col, right_col = st.columns([2, 1])

with left_col:
    st.markdown("### 📡 ESP32 NEURAL NETWORK STATUS")

    if st.session_state.connected_nodes:
        for node_id, info in st.session_state.connected_nodes.items():
            data = info["data"]
            last_update = info["timestamp"].strftime("%H:%M:%S")

            # Determine node status
            is_anomaly = data.get("is_anomaly", False)
            attack_type = data.get("attack_type", "normal")

            if is_anomaly:
                status_emoji = "🔴"
                status_text = f"THREAT DETECTED - {attack_type.upper()}"
                card_class = "anomaly-alert"
            else:
                status_emoji = "🟢"
                status_text = "SECURE"
                card_class = "normal-status"

            # Create enhanced node card
            with st.expander(
                f"{status_emoji} {node_id} - {status_text}", expanded=is_anomaly
            ):
                # Node metrics in columns with enhanced styling
                n1, n2, n3, n4 = st.columns(4)

                with n1:
                    st.metric("⏱️ Duration", f"{data.get('duration', 0)}s")
                    st.metric("📡 Protocol", data.get("protocol_type", "tcp").upper())

                with n2:
                    st.metric("📤 Src Bytes", f"{data.get('src_bytes', 0):,}")
                    st.metric("📥 Dst Bytes", f"{data.get('dst_bytes', 0):,}")

                with n3:
                    st.metric("🔗 Connections", data.get("count", 0))
                    st.metric("🛠️ Services", data.get("srv_count", 0))

                with n4:
                    st.metric("⚠️ Error Rate", f"{data.get('serror_rate', 0):.2%}")
                    st.metric("📶 WiFi RSSI", f"{data.get('wifi_rssi', 0)} dBm")

                # Enhanced anomaly details
                if is_anomaly:
                    st.markdown("**🔍 THREAT ANALYSIS:**")
                    detail_cols = st.columns(3)

                    with detail_cols[0]:
                        st.write(
                            f"**🎯 Target Service:** {data.get('service', 'unknown')}"
                        )
                        st.write(
                            f"**🚩 Connection Flag:** {data.get('flag', 'unknown')}"
                        )

                    with detail_cols[1]:
                        st.write(
                            f"**🔐 Failed Logins:** {data.get('num_failed_logins', 0)}"
                        )
                        st.write(
                            f"**👑 Root Access:** {'YES' if data.get('root_shell', 0) else 'NO'}"
                        )

                    with detail_cols[2]:
                        st.write(f"**🖥️ Host Count:** {data.get('dst_host_count', 0)}")
                        st.write(
                            f"**📊 Service Rate:** {data.get('same_srv_rate', 0):.2%}"
                        )

                # Enhanced node statistics
                if node_id in st.session_state.node_statistics:
                    stats = st.session_state.node_statistics[node_id]
                    st.markdown("**📈 NODE ANALYTICS:**")
                    stat_cols = st.columns(3)

                    with stat_cols[0]:
                        st.write(f"📊 Total Packets: **{stats['total_packets']}**")
                    with stat_cols[1]:
                        st.write(f"⚠️ Threats Found: **{stats['anomaly_count']}**")
                    with stat_cols[2]:
                        threat_ratio = (
                            (stats["anomaly_count"] / stats["total_packets"] * 100)
                            if stats["total_packets"] > 0
                            else 0
                        )
                        st.write(f"🎯 Threat Ratio: **{threat_ratio:.1f}%**")
    else:
        st.info("🔌 Initializing ESP32 Neural Network...")

with right_col:
    st.markdown("### 🚨 THREAT FEED")

    if st.session_state.anomaly_alerts:
        # Show recent alerts with enhanced styling
        recent_alerts = sorted(
            st.session_state.anomaly_alerts, key=lambda x: x["alert_time"], reverse=True
        )[:10]

        for alert in recent_alerts:
            confidence = alert["confidence"]
            node_id = alert["node_id"]
            timestamp = alert["timestamp"]
            attack_type = alert.get("attack_type", "unknown")

            # Enhanced color coding
            if confidence > 0.9:
                alert_color = "🔴"
                severity = "CRITICAL"
                severity_color = "#ff0099"
            elif confidence > 0.7:
                alert_color = "🟠"
                severity = "HIGH"
                severity_color = "#ff6600"
            else:
                alert_color = "🟡"
                severity = "MEDIUM"
                severity_color = "#ffaa00"

            # Enhanced attack type emojis
            attack_emojis = {
                "dos": "💥 DDoS",
                "portscan": "🔍 Port Scan",
                "r2l": "🚪 Remote Access",
                "u2r": "⬆️ Privilege Escalation",
                "probe": "📡 Network Probe",
                "normal": "✅ Normal",
            }

            attack_display = attack_emojis.get(attack_type, f"⚠️ {attack_type.upper()}")

            with st.container():
                st.markdown(
                    f"""
                    <div class="anomaly-alert">
                        <strong>{alert_color} {node_id}</strong><br>
                        <strong>🎯 Attack:</strong> {attack_display}<br>
                        <strong>⚡ Severity:</strong> <span style="color: {severity_color}">{severity}</span><br>
                        <strong>🧠 AI Confidence:</strong> {confidence:.1%}<br>
                        <strong>⏰ Time:</strong> {timestamp}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
    else:
        st.markdown(
            """
            <div class="normal-status">
                <strong>🛡️ ALL SYSTEMS SECURE</strong><br>
                <em>Neural network monitoring active...</em>
            </div>
            """,
            unsafe_allow_html=True,
        )

# Enhanced Analytics Section
st.divider()
st.markdown("### 📊 ADVANCED NEURAL ANALYTICS")

if st.session_state.all_data_history:
    # Filter data
    filtered_data = st.session_state.all_data_history

    if show_only_anomalies:
        filtered_data = [d for d in filtered_data if d.get("is_anomaly", False)]

    if selected_attack_types:
        filtered_data = [
            d
            for d in filtered_data
            if d.get("attack_type", "normal") in selected_attack_types
        ]

    if filtered_data:
        df = pd.DataFrame(filtered_data)

        # Enhanced chart tabs
        chart_tab1, chart_tab2, chart_tab3, chart_tab4, chart_tab5 = st.tabs(
            [
                "📈 Temporal Analysis",
                "🥧 Threat Distribution",
                "📊 Node Performance",
                "🔥 Heat Matrix",
                "🧠 AI Insights",
            ]
        )

        with chart_tab1:
            st.markdown("**🌊 Network Activity Waveform**")

            if len(df) > 1:
                df["received_time"] = pd.to_datetime(df["received_time"])
                df_ts = df.set_index("received_time").sort_index()

                # Create enhanced time series
                fig = make_subplots(
                    rows=2,
                    cols=2,
                    subplot_titles=[
                        "🔗 Connection Density",
                        "📊 Service Activity",
                        "⚠️ Error Patterns",
                        "💾 Data Flow",
                    ],
                    specs=[
                        [{"secondary_y": False}, {"secondary_y": False}],
                        [{"secondary_y": False}, {"secondary_y": False}],
                    ],
                )

                # Enhanced plotting with better colors
                colors = ["#00ff88", "#0099ff", "#ff0099", "#ffaa00", "#aa00ff"]

                for i, node_id in enumerate(df["node_id"].unique()):
                    node_data = df_ts[df_ts["node_id"] == node_id].tail(50)
                    color = colors[i % len(colors)]

                    if len(node_data) > 0:
                        fig.add_trace(
                            go.Scatter(
                                x=node_data.index,
                                y=node_data.get("count", 0),
                                name=f"{node_id}",
                                mode="lines+markers",
                                line=dict(color=color, width=3),
                                marker=dict(size=6, symbol="circle"),
                            ),
                            row=1,
                            col=1,
                        )

                        fig.add_trace(
                            go.Scatter(
                                x=node_data.index,
                                y=node_data.get("srv_count", 0),
                                name=f"{node_id}",
                                mode="lines+markers",
                                showlegend=False,
                                line=dict(color=color, width=3),
                                marker=dict(size=6, symbol="diamond"),
                            ),
                            row=1,
                            col=2,
                        )

                        fig.add_trace(
                            go.Scatter(
                                x=node_data.index,
                                y=node_data.get("serror_rate", 0),
                                name=f"{node_id}",
                                mode="lines+markers",
                                showlegend=False,
                                line=dict(color=color, width=3),
                                marker=dict(size=6, symbol="square"),
                            ),
                            row=2,
                            col=1,
                        )

                        fig.add_trace(
                            go.Scatter(
                                x=node_data.index,
                                y=node_data.get("src_bytes", 0),
                                name=f"{node_id}",
                                mode="lines+markers",
                                showlegend=False,
                                line=dict(color=color, width=3),
                                marker=dict(size=6, symbol="triangle-up"),
                            ),
                            row=2,
                            col=2,
                        )

                    fig.update_layout(
                        height=600,
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#00ff88"),
                        showlegend=True,
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("🔄 Collecting neural data patterns...")

        with chart_tab2:
            st.markdown("**🎯 Cyber Threat Landscape**")

            # Enhanced pie chart
            attack_counts = df["attack_type"].value_counts()

            colors = ["#00ff88", "#ff0099", "#0099ff", "#ffaa00", "#aa00ff", "#ff6600"]

            fig = px.pie(
                values=attack_counts.values,
                names=attack_counts.index,
                title="🌐 Attack Vector Distribution",
                color_discrete_sequence=colors,
                hole=0.4,
            )

            fig.update_traces(
                textposition="inside",
                textinfo="percent+label",
                textfont_size=12,
                marker=dict(line=dict(color="#000000", width=2)),
            )

            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#00ff88", size=14),
            )

            st.plotly_chart(fig, use_container_width=True)

            # Attack timeline
            # Attack timeline
            col1, col2 = st.columns(2)

            with col1:
                if "received_time" in df.columns:
                    df["hour"] = pd.to_datetime(df["received_time"]).dt.hour
                    hourly_attacks = (
                        df.groupby(["hour", "attack_type"]).size().unstack(fill_value=0)
                    )

                    # Fix: Convert the pivot table to long format for Plotly
                    hourly_attacks_melted = hourly_attacks.reset_index().melt(
                        id_vars=["hour"], var_name="attack_type", value_name="count"
                    )

                    fig2 = px.bar(
                        hourly_attacks_melted,
                        x="hour",
                        y="count",
                        color="attack_type",
                        title="⏰ Hourly Threat Pattern",
                        labels={"hour": "Hour", "count": "Threat Count"},
                        color_discrete_sequence=colors,
                    )

                    fig2.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#00ff88"),
                    )

                    st.plotly_chart(fig2, use_container_width=True)

            with col2:
                # Node threat distribution - Also fix this one
                node_threats = (
                    df.groupby(["node_id", "attack_type"]).size().unstack(fill_value=0)
                )

                # Fix: Convert to long format
                node_threats_melted = node_threats.reset_index().melt(
                    id_vars=["node_id"], var_name="attack_type", value_name="count"
                )

                fig3 = px.bar(
                    node_threats_melted,
                    x="node_id",
                    y="count",
                    color="attack_type",
                    title="🔗 Node Threat Matrix",
                    labels={"node_id": "Node ID", "count": "Threat Count"},
                    color_discrete_sequence=colors,
                )

                fig3.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#00ff88"),
                )

                st.plotly_chart(fig3, use_container_width=True)

        with chart_tab3:
            st.markdown("**⚡ Neural Node Performance Matrix**")

            # Enhanced node comparison
            node_comparison = (
                df.groupby("node_id")
                .agg(
                    {
                        "count": "mean",
                        "srv_count": "mean",
                        "src_bytes": "mean",
                        "dst_bytes": "mean",
                        "serror_rate": "mean",
                        "is_anomaly": "sum",
                    }
                )
                .round(2)
            )

            node_comparison.columns = [
                "Avg Connections",
                "Avg Services",
                "Avg Src Bytes",
                "Avg Dst Bytes",
                "Avg Error Rate",
                "Total Threats",
            ]

            # Enhanced radar chart
            if len(node_comparison) > 1:
                fig = go.Figure()

                colors = ["#00ff88", "#0099ff", "#ff0099", "#ffaa00", "#aa00ff"]

                for i, node_id in enumerate(node_comparison.index):
                    values = node_comparison.loc[node_id].values.tolist()
                    max_vals = node_comparison.max().values
                    normalized_values = [
                        v / m if m > 0 else 0 for v, m in zip(values, max_vals)
                    ]

                    fig.add_trace(
                        go.Scatterpolar(
                            r=normalized_values,
                            theta=node_comparison.columns.tolist(),
                            fill="toself",
                            name=f"{node_id}",
                            line_color=colors[i % len(colors)],
                            fillcolor=colors[i % len(colors)],
                            opacity=0.6,
                        )
                    )

                fig.update_layout(
                    polar=dict(
                        radialaxis=dict(
                            visible=True,
                            range=[0, 1],
                            gridcolor="rgba(0,255,136,0.3)",
                            linecolor="rgba(0,255,136,0.5)",
                        ),
                        angularaxis=dict(
                            gridcolor="rgba(0,255,136,0.3)",
                            linecolor="rgba(0,255,136,0.5)",
                        ),
                    ),
                    showlegend=True,
                    title="🕷️ Multi-Dimensional Node Analysis",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#00ff88"),
                )

                st.plotly_chart(fig, use_container_width=True)

            # Performance metrics table
            st.markdown("**📊 Detailed Performance Metrics**")
            st.dataframe(
                node_comparison.style.background_gradient(
                    cmap="viridis", subset=["Total Threats"]
                ).format(precision=2),
                use_container_width=True,
            )

        with chart_tab4:
            st.markdown("**🔥 Cyber Activity Heat Matrix**")

            if len(df) > 10:
                df["received_time"] = pd.to_datetime(df["received_time"])
                df["hour"] = df["received_time"].dt.hour
                df["day"] = df["received_time"].dt.day_name()

                # Activity heatmap
                heatmap_data = df.pivot_table(
                    index="day",
                    columns="hour",
                    values="is_anomaly",
                    aggfunc="sum",
                    fill_value=0,
                )

                if not heatmap_data.empty:
                    fig = px.imshow(
                        heatmap_data,
                        title="🌡️ Threat Activity Heat Map",
                        labels=dict(x="Hour", y="Day", color="Threat Count"),
                        color_continuous_scale="plasma",
                    )

                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#00ff88"),
                    )

                    st.plotly_chart(fig, use_container_width=True)

                # Protocol vs Service heatmap
                protocol_service_data = df.pivot_table(
                    index="protocol_type",
                    columns="service",
                    values="is_anomaly",
                    aggfunc="sum",
                    fill_value=0,
                )

                if not protocol_service_data.empty:
                    fig2 = px.imshow(
                        protocol_service_data,
                        title="🌐 Protocol-Service Threat Matrix",
                        labels=dict(x="Service", y="Protocol", color="Threat Count"),
                        color_continuous_scale="inferno",
                    )

                    fig2.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#00ff88"),
                    )

                    st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("🔄 Generating heat matrix data...")

        with chart_tab5:
            st.markdown("**🧠 AI Neural Network Insights**")

            # AI confidence distribution
            if st.session_state.anomaly_alerts:
                confidence_data = [
                    alert["confidence"] for alert in st.session_state.anomaly_alerts
                ]

                fig = px.histogram(
                    x=confidence_data,
                    nbins=20,
                    title="🎯 AI Confidence Distribution",
                    labels={"x": "Confidence Score", "y": "Alert Count"},
                    color_discrete_sequence=["#00ff88"],
                )

                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#00ff88"),
                )

                st.plotly_chart(fig, use_container_width=True)

            # Feature importance simulation
            features = [
                "Duration",
                "Src Bytes",
                "Dst Bytes",
                "Error Rate",
                "Service Count",
            ]
            importance = np.random.dirichlet(np.ones(len(features))) * 100

            fig2 = px.bar(
                x=features,
                y=importance,
                title="🧬 Neural Network Feature Importance",
                labels={"x": "Network Features", "y": "Importance (%)"},
                color=importance,
                color_continuous_scale="viridis",
            )

            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#00ff88"),
            )

            st.plotly_chart(fig2, use_container_width=True)

            # Real-time metrics
            col1, col2, col3 = st.columns(3)

            with col1:
                avg_confidence = np.mean(confidence_data) if confidence_data else 0
                st.metric("🎯 Avg AI Confidence", f"{avg_confidence:.1%}")

            with col2:
                processing_speed = len(st.session_state.all_data_history) / max(
                    1, (datetime.now() - st.session_state.start_time).seconds
                )
                st.metric("⚡ Processing Speed", f"{processing_speed:.1f}/sec")

            with col3:
                accuracy_sim = random.uniform(0.92, 0.98)
                st.metric("🎯 Model Accuracy", f"{accuracy_sim:.1%}")
    else:
        st.info("🔍 No data matches current neural filters")
else:
    st.info("🧠 Neural network initializing... Stand by for threat analysis")

    # Enhanced System Statistics
    st.divider()
    st.markdown("### 📈 QUANTUM NEURAL STATISTICS")

    stats_col1, stats_col2, stats_col3 = st.columns(3)

    with stats_col1:
        st.markdown("**🎯 THREAT DETECTION MATRIX**")
    if st.session_state.all_data_history:
        total_data = len(st.session_state.all_data_history)
        anomaly_data = len(
            [d for d in st.session_state.all_data_history if d.get("is_anomaly", False)]
        )
        normal_data = total_data - anomaly_data

        st.metric("📊 Total Scans", total_data, delta=f"+{total_data}")
        st.metric("✅ Clean Traffic", normal_data, delta=f"+{normal_data}")
        st.metric("⚠️ Threats Found", anomaly_data, delta=f"+{anomaly_data}")

        if total_data > 0:
            threat_ratio = (anomaly_data / total_data) * 100
            st.metric(
                "🎯 Threat Ratio", f"{threat_ratio:.1f}%", delta=f"{threat_ratio:.1f}%"
            )
    else:
        st.info("📊 Awaiting neural data...")

    with stats_col2:
        st.markdown("**🔗 NODE PERFORMANCE**")
    if st.session_state.node_statistics:
        total_packets = sum(
            [
                stats["total_packets"]
                for stats in st.session_state.node_statistics.values()
            ]
        )
        total_anomalies = sum(
            [
                stats["anomaly_count"]
                for stats in st.session_state.node_statistics.values()
            ]
        )

        st.metric("📡 Total Packets", total_packets, delta=f"+{total_packets}")
        st.metric("⚠️ Anomalies", total_anomalies, delta=f"+{total_anomalies}")
        st.metric(
            "🔗 Active Nodes",
            len(st.session_state.node_statistics),
            delta=f"+{len(st.session_state.node_statistics)}",
        )

        if total_packets > 0:
            detection_efficiency = (total_anomalies / total_packets) * 100
            st.metric(
                "⚡ Detection Rate",
                f"{detection_efficiency:.2f}%",
                delta=f"{detection_efficiency:.2f}%",
            )
    else:
        st.info("🔗 Nodes initializing...")

    with stats_col3:
        st.markdown("**⚡ SYSTEM PERFORMANCE**")

    uptime_seconds = (datetime.now() - st.session_state.start_time).total_seconds()

    if st.session_state.all_data_history:
        recent_data = [
            d
            for d in st.session_state.all_data_history
            if datetime.fromisoformat(d["received_time"])
            > datetime.now() - timedelta(minutes=5)
        ]

        st.metric("📊 Recent Activity", len(recent_data), delta=f"+{len(recent_data)}")

        if recent_data:
            processing_rate = len(recent_data) / 5
            st.metric(
                "⚡ Process Rate",
                f"{processing_rate:.1f}/min",
                delta=f"+{processing_rate:.1f}",
            )

        # Neural network status
        nn_efficiency = random.uniform(0.94, 0.99)
        st.metric(
            "🧠 Neural Efficiency",
            f"{nn_efficiency:.1%}",
            delta=f"+{nn_efficiency:.1%}",
        )

        memory_usage = len(st.session_state.all_data_history) * 0.1  # Simulated
        st.metric(
            "💾 Memory Usage", f"{memory_usage:.1f} MB", delta=f"+{memory_usage:.1f}"
        )
    else:
        st.info("⚡ System warming up...")

    # Enhanced Footer
    st.divider()
    st.markdown("---")

    footer_col1, footer_col2, footer_col3, footer_col4 = st.columns(4)

    with footer_col1:
        st.markdown("**🛡️ CYBER-GNN MATRIX**")
        st.caption("Quantum Neural Defense System")

    with footer_col2:
        st.markdown("**🧠 AI CORE**")
        st.caption("Graph Attention Network v4.0")

    with footer_col3:
        st.markdown("**📡 SENSOR NETWORK**")
        st.caption("ESP32 Quantum Sensors")

    with footer_col4:
        st.markdown("**⚡ STATUS**")
        st.caption("FULLY OPERATIONAL")

    # Enhanced Debug Panel
    if st.sidebar.checkbox("🐛 NEURAL DEBUG MATRIX", value=False):
        st.divider()
        st.markdown("### 🐛 QUANTUM DEBUG INTERFACE")

    debug_col1, debug_col2 = st.columns(2)

    with debug_col1:
        st.markdown("**🔗 Node Telemetry:**")
        if st.session_state.connected_nodes:
            for node_id, info in list(st.session_state.connected_nodes.items())[:2]:
                with st.expander(f"📡 {node_id} Telemetry"):
                    st.json(info["data"])
        else:
            st.write("🔄 Nodes initializing...")

    with debug_col2:
        st.markdown("**📊 Data Stream:**")
        if st.session_state.all_data_history:
            st.markdown(
                f"**Latest Data Points:** {len(st.session_state.all_data_history[-5:])}"
            )
            for i, data in enumerate(st.session_state.all_data_history[-3:]):
                with st.expander(
                    f"Data Point #{len(st.session_state.all_data_history) - 2 + i}"
                ):
                    st.json(data)
        else:
            st.write("📊 Awaiting data stream...")

    # System metrics
    st.markdown("**🔧 System Diagnostics:**")
    diag_col1, diag_col2, diag_col3 = st.columns(3)

    with diag_col1:
        st.metric("🔄 Refresh Rate", f"{refresh_rate}s")
        st.metric("📊 Data Buffer", len(st.session_state.all_data_history))

    with diag_col2:
        st.metric("⚠️ Alert Buffer", len(st.session_state.anomaly_alerts))
        st.metric(
            "🧠 Memory Usage",
            f"{len(str(st.session_state.all_data_history)) / 1024:.1f}KB",
        )

    with diag_col3:
        cpu_sim = random.uniform(15, 45)
        network_sim = random.uniform(5, 25)
        st.metric("💻 CPU Usage", f"{cpu_sim:.1f}%")
        st.metric("🌐 Network Load", f"{network_sim:.1f}%")

    # Floating status indicator
    st.markdown(
        """
    <div style="position: fixed; top: 20px; right: 20px; z-index: 999; 
                background: linear-gradient(135deg, rgba(0, 255, 136, 0.9), rgba(0, 153, 255, 0.9)); 
                color: black; padding: 10px 15px; border-radius: 25px; font-weight: bold;
                box-shadow: 0 4px 15px rgba(0, 255, 136, 0.4);">
        🛡️ NEURAL MATRIX ONLINE
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Auto-refresh status
    if auto_refresh:
        st.sidebar.markdown(
            f"""
        <div style="text-align: center; padding: 10px; 
                    background: linear-gradient(135deg, rgba(0, 255, 136, 0.2), rgba(0, 153, 255, 0.2));
                    border-radius: 10px; margin-top: 20px;">
            <strong>🔄 NEURAL SYNC ACTIVE</strong><br>
            <em>Refreshing every {refresh_rate} seconds</em>
        </div>
        """,
            unsafe_allow_html=True,
        )
