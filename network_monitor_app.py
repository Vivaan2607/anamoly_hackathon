import streamlit as st
import scapy.all as scapy
from network_monitor import NetworkMonitor
import time
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime

def create_traffic_chart(packet_sizes, packet_counts):
    # Create time series chart for packet sizes
    fig1 = go.Figure()
    fig1.add_trace(go.Scatter(y=packet_sizes, mode='lines', name='Packet Sizes'))
    fig1.update_layout(title='Packet Sizes Over Time',
                      xaxis_title='Packets',
                      yaxis_title='Size (bytes)')
    
    # Create bar chart for top IPs
    top_ips = dict(sorted(packet_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    fig2 = go.Figure(data=[
        go.Bar(x=list(top_ips.keys()), y=list(top_ips.values()))
    ])
    fig2.update_layout(title='Top 5 IP Sources',
                      xaxis_title='IP Address',
                      yaxis_title='Packet Count')
    
    return fig1, fig2

def main():
    st.set_page_config(page_title="Network Traffic Monitor", layout="wide")
    st.title("Network Traffic Monitor")
    
    # Enable libpcap correctly
    scapy.conf.use_pcap = True
    
    # Initialize session state
    if 'monitor' not in st.session_state:
        st.session_state.monitor = NetworkMonitor()
        st.session_state.is_monitoring = False
        st.session_state.packet_sizes_history = []
        st.session_state.baseline_established = False
    
    # Sidebar controls
    st.sidebar.header("Controls")
    available_interfaces = scapy.get_if_list()
    selected_interface = st.sidebar.selectbox("Select Network Interface", available_interfaces, index=available_interfaces.index("lo0") if "lo0" in available_interfaces else 0)
    
    col1, col2 = st.columns(2)
    
    with col1:
        if not st.session_state.baseline_established:
            if st.button("Establish Baseline"):
                with st.spinner("Establishing baseline..."):
                    st.session_state.monitor.establish_baseline(interface=selected_interface, duration=30)
                    st.session_state.baseline_established = True
                st.success("Baseline established!")
    
    with col2:
        if st.session_state.baseline_established:
            if not st.session_state.is_monitoring:
                if st.button("Start Monitoring"):
                    st.session_state.is_monitoring = True
            else:
                if st.button("Stop Monitoring"):
                    st.session_state.is_monitoring = False
    
    # Create placeholder for charts with unique keys
    chart_placeholder = st.empty()
    stats_placeholder = st.empty()
    
    # Add logging section below the charts
    st.markdown("---")  # Add a divider
    st.header("Anomaly Logs")
    
    # Create two columns for log filters
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        show_all = st.checkbox("Show All Logs", value=False)
    with filter_col2:
        max_logs = st.slider("Number of Logs to Show", 1, 50, 10)
    
    # Display logs in an expander
    with st.expander("View Logs", expanded=True):
        if st.session_state.monitor.anomaly_logs:
            df = pd.DataFrame(st.session_state.monitor.anomaly_logs)
            
            if not show_all:
                df = df.tail(max_logs)
            
            for _, log in df.iterrows():
                with st.container():
                    # Show the explanation
                    st.markdown(f"""
                    ### 🚨 Anomaly Alert - {log['severity']}
                    **Time**: {log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
                    
                    {log['explanation']}
                    
                    **Technical Details:**
                    - Anomaly Score (Z-Score): {log['z_score']} (threshold: 2.0)
                    - Total Packets Analyzed: {log['packet_count']}
                    """)
                    
                    # Show the top IPs
                    st.markdown("**Most Active IP Addresses:**")
                    for ip, count in log['top_ips'].items():
                        st.markdown(f"- {ip}: {count} packets {'(Potential source of anomalous traffic)' if count > 3 else ''}")
                    
                    # Show AI Analysis without using an expander
                    st.markdown("### 🤖 AI Analysis & Recommendations")
                    if 'ai_analysis' in log:
                        st.markdown(log['ai_analysis'])
                    else:
                        st.info("AI analysis not available for this anomaly")
                    
                    st.markdown("---")
        else:
            st.info("No anomalies detected yet.")
    
    # Monitoring loop
    if st.session_state.is_monitoring:
        while st.session_state.is_monitoring:
            try:
                # Capture packets without monitor mode
                st.session_state.monitor.capture_packets(interface=selected_interface, duration=5)
                
                # Update charts
                if st.session_state.monitor.packet_sizes:
                    fig1, fig2 = create_traffic_chart(
                        st.session_state.monitor.packet_sizes,
                        st.session_state.monitor.packet_counts
                    )
                    
                    with chart_placeholder.container():
                        col1, col2 = st.columns(2)
                        with col1:
                            st.plotly_chart(fig1, use_container_width=True, key=f"packet_sizes_{int(time.time())}")
                        with col2:
                            st.plotly_chart(fig2, use_container_width=True, key=f"ip_sources_{int(time.time())}")
                    
                    # Check for anomalies
                    is_anomaly = st.session_state.monitor.detect_anomalies(st.session_state.monitor.packet_sizes)
                    
                    with stats_placeholder.container():
                        st.subheader("Network Statistics")
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric(
                                label="Total Packets",
                                value=len(st.session_state.monitor.packet_sizes)
                            )
                        with col2:
                            st.metric(
                                label="Unique IPs",
                                value=len(st.session_state.monitor.packet_counts)
                            )
                        with col3:
                            if is_anomaly:
                                st.error("⚠️ ANOMALY DETECTED!")
                            else:
                                st.success("Network behavior normal")
                    
                    # Display logs with unique keys
                    if st.session_state.monitor.anomaly_logs:
                        with st.container():
                            df = pd.DataFrame(st.session_state.monitor.anomaly_logs)
                            if not show_all:
                                df = df.tail(max_logs)
                            
                            for idx, log in df.iterrows():
                                with st.container():
                                    # First show the explanation
                                    st.markdown(f"""
                                    ### 🚨 Anomaly Alert - {log['severity']}
                                    **Time**: {log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
                                    
                                    {log['explanation']}
                                    
                                    **Technical Details:**
                                    - Anomaly Score (Z-Score): {log['z_score']} (threshold: 2.0)
                                    - Total Packets Analyzed: {log['packet_count']}
                                    """)
                                    
                                    # Show the top IPs in a more context-rich way
                                    st.markdown("**Most Active IP Addresses:**")
                                    for ip, count in log['top_ips'].items():
                                        st.markdown(f"- {ip}: {count} packets {'(Potential source of anomalous traffic)' if count > 3 else ''}")
                                    
                                    # Add AI Analysis section
                                    with st.expander("🤖 AI Analysis & Recommendations", expanded=True):
                                        if 'ai_analysis' in log:
                                            st.markdown(log['ai_analysis'])
                                        else:
                                            st.info("AI analysis not available for this anomaly")
                                    
                                    st.markdown("---")
            except Exception as e:
                st.error(f"Error capturing packets: {e}")
                st.session_state.is_monitoring = False
                break
            time.sleep(1)

if __name__ == "__main__":
    main() 