"""
Security Monitoring Dashboard - Streamlit App
Visualisasi real-time monitoring alert dan risk patterns
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import io

# ==================== PAGE CONFIG ====================
st.set_page_config(
    page_title="Security Monitoring Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM CSS ====================
st.markdown("""
    <style>
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            color: white;
            text-align: center;
        }
        .critical-alert {
            background-color: #ffebee;
            border-left: 4px solid #f44336;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
        .high-alert {
            background-color: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
    </style>
""", unsafe_allow_html=True)

# ==================== LOAD DATA ====================
@st.cache_data
def load_data():
    """Load data dari CSV dan JSONL"""
    try:
        df_users = pd.read_csv('users.csv')
        df_assets = pd.read_csv('assets.csv')
        df_stream = pd.read_json('stream_events.jsonl', lines=True)
        
        # Convert event_time to datetime
        df_stream['event_time'] = pd.to_datetime(df_stream['event_time'])
        
        return df_users, df_assets, df_stream
    except FileNotFoundError as e:
        st.error(f"❌ File tidak ditemukan: {e}")
        st.stop()

# ==================== SECURITY ALERT FUNCTION ====================
def security_alert(event):
    """
    Menentukan level alert keamanan berdasarkan atribut event.
    Return: LOW, MEDIUM, HIGH, atau CRITICAL
    """
    score = 0

    # Faktor 1: Risk score bawaan
    risk = event.get('risk_score', 0)
    if risk >= 80:
        score += 4
    elif risk >= 50:
        score += 3
    elif risk >= 20:
        score += 2
    else:
        score += 1

    # Faktor 2: Aksi sensitif
    action = event.get('action', '')
    if action in ['permission_change', 'delete']:
        score += 3
    elif action in ['download', 'upload']:
        score += 2
    elif action in ['query', 'schema_discovery']:
        score += 1

    # Faktor 3: Klasifikasi data
    classification = event.get('data_classification', '')
    if classification == 'confidential':
        score += 3
    elif classification == 'restricted':
        score += 2
    elif classification == 'internal':
        score += 1

    # Faktor 4: Status gagal
    if event.get('status', '') == 'failed':
        score += 2

    # Faktor 5: Bytes out tinggi (> 500KB)
    if event.get('bytes_out', 0) > 500000:
        score += 2

    # Tentukan level alert
    if score >= 12:
        return 'CRITICAL'
    elif score >= 9:
        return 'HIGH'
    elif score >= 6:
        return 'MEDIUM'
    else:
        return 'LOW'

# ==================== IDENTIFY RISK PATTERNS ====================
def identify_risk_patterns(df_stream, df_users):
    """Identifikasi 3 pola risiko utama"""
    df_merged = df_stream.merge(df_users[['user_id', 'status']], 
                                on='user_id', how='left', suffixes=('', '_user'))
    
    # Risk Pattern 1: Terminated User Access
    pattern1 = df_merged[df_merged['status_user'] == 'terminated'].copy()
    
    # Risk Pattern 2: Large Download Sensitive Data
    p95_bytes = df_stream['bytes_out'].quantile(0.95)
    pattern2 = df_stream[
        (df_stream['action'] == 'download') &
        (df_stream['data_classification'].isin(['confidential', 'restricted'])) &
        (df_stream['bytes_out'] > p95_bytes)
    ].copy()
    
    # Risk Pattern 3: Permission Change from External IP
    pattern3 = df_stream[
        (df_stream['action'] == 'permission_change') &
        (~df_stream['source_ip'].str.startswith('10.'))
    ].copy()
    
    return {
        'Terminated User Access': len(pattern1),
        'Large Sensitive Download': len(pattern2),
        'External Permission Change': len(pattern3)
    }, pattern1, pattern2, pattern3

# ==================== MAIN APP ====================
def main():
    # Load data
    df_users, df_assets, df_stream = load_data()
    
    # Add alert level
    df_stream['alert_level'] = df_stream.apply(lambda row: security_alert(row.to_dict()), axis=1)
    
    # ==================== HEADER ====================
    st.markdown("# 🛡️ SECURITY MONITORING DASHBOARD")
    st.markdown("**Real-time threat detection & risk pattern monitoring**")
    st.divider()
    
    # ==================== FILTERS (SIDEBAR) ====================
    with st.sidebar:
        st.header("⚙️ Filters")
        
        # Date range filter
        date_range = st.date_input(
            "📅 Select Date Range",
            value=(df_stream['event_time'].min().date(), df_stream['event_time'].max().date()),
            min_value=df_stream['event_time'].min().date(),
            max_value=df_stream['event_time'].max().date()
        )
        
        # User filter
        user_filter = st.multiselect(
            "👤 Select Users",
            options=sorted(df_stream['user_id'].unique()),
            help="Leave empty to include all users"
        )
        
        # Alert level filter
        alert_levels = st.multiselect(
            "⚠️ Select Alert Levels",
            options=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            default=['MEDIUM', 'HIGH', 'CRITICAL'],
            help="Filter by alert severity"
        )
        
        # Apply filters
        df_filtered = df_stream.copy()
        
        if len(date_range) == 2:
            start_date = pd.to_datetime(date_range[0])
            end_date = pd.to_datetime(date_range[1])
            df_filtered = df_filtered[
                (df_filtered['event_time'] >= start_date) & 
                (df_filtered['event_time'] <= end_date)
            ]
        
        if user_filter:
            df_filtered = df_filtered[df_filtered['user_id'].isin(user_filter)]
        
        if alert_levels:
            df_filtered = df_filtered[df_filtered['alert_level'].isin(alert_levels)]
    
    # ==================== SUMMARY CARDS ====================
    st.subheader("📊 Summary Metrics")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Events",
            f"{len(df_filtered):,}",
            delta=f"{len(df_filtered) - len(df_stream)} vs all data",
            help="Total security events in selected period"
        )
    
    with col2:
        alert_count = len(df_filtered[df_filtered['alert_level'].isin(['HIGH', 'CRITICAL'])])
        st.metric(
            "⚠️ Alerts (H+C)",
            alert_count,
            help="High + Critical severity alerts"
        )
    
    with col3:
        critical_count = len(df_filtered[df_filtered['alert_level'] == 'CRITICAL'])
        st.metric(
            "🔴 Critical",
            critical_count,
            help="Critical severity alerts"
        )
    
    with col4:
        anomaly_count = len(df_filtered[df_filtered['label'] == 'anomaly'])
        st.metric(
            "🤖 Anomalies",
            anomaly_count,
            help="ML-detected anomalies"
        )
    
    st.divider()
    
    # ==================== VISUALIZATIONS SECTION 1 ====================
    st.subheader("📈 Alert Distribution & Risk Patterns")
    col1, col2 = st.columns(2)
    
    with col1:
        # Alert Level Distribution (Pie Chart)
        alert_dist = df_filtered['alert_level'].value_counts()
        colors_map = {'CRITICAL': '#f44336', 'HIGH': '#ff9800', 'MEDIUM': '#ffc107', 'LOW': '#4caf50'}
        colors = [colors_map.get(level, '#999999') for level in alert_dist.index]
        
        fig_pie = go.Figure(data=[go.Pie(
            labels=alert_dist.index,
            values=alert_dist.values,
            marker=dict(colors=colors),
            textposition='inside',
            textinfo='label+percent'
        )])
        fig_pie.update_layout(
            title="Alert Level Distribution",
            height=400,
            showlegend=True
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Risk Patterns Count (Bar Chart)
        risk_patterns, _, _, _ = identify_risk_patterns(df_filtered, df_users)
        
        fig_bar = go.Figure(data=[go.Bar(
            x=list(risk_patterns.keys()),
            y=list(risk_patterns.values()),
            marker=dict(color=['#e74c3c', '#e67e22', '#3498db'])
        )])
        fig_bar.update_layout(
            title="Top 3 Risk Patterns Count",
            xaxis_title="Risk Pattern",
            yaxis_title="Count",
            height=400,
            showlegend=False
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    
    st.divider()
    
    # ==================== VISUALIZATIONS SECTION 2 ====================
    st.subheader("👥 User Risk Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        # User Risk Scoring
        user_risk = df_filtered.groupby('user_id').agg({
            'alert_level': lambda x: (x == 'CRITICAL').sum() * 4 + (x == 'HIGH').sum() * 3 + (x == 'MEDIUM').sum() * 2 + (x == 'LOW').sum(),
            'event_id': 'count'
        }).rename(columns={'alert_level': 'risk_score', 'event_id': 'event_count'})
        user_risk = user_risk.sort_values('risk_score', ascending=False).head(10)
        
        fig_user = go.Figure(data=[go.Bar(
            x=user_risk.index,
            y=user_risk['risk_score'],
            marker=dict(color=user_risk['risk_score'], colorscale='Reds', showscale=True)
        )])
        fig_user.update_layout(
            title="Top 10 Users by Risk Score",
            xaxis_title="User ID",
            yaxis_title="Risk Score",
            height=400,
            xaxis_tickangle=-45
        )
        st.plotly_chart(fig_user, use_container_width=True)
    
    with col2:
        # Time-series Alert Trends
        df_time = df_filtered.copy()
        df_time['date'] = df_time['event_time'].dt.date
        alert_trend = df_time.groupby(['date', 'alert_level']).size().unstack(fill_value=0)
        
        fig_trend = go.Figure()
        colors_map = {'CRITICAL': '#f44336', 'HIGH': '#ff9800', 'MEDIUM': '#ffc107', 'LOW': '#4caf50'}
        
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if level in alert_trend.columns:
                fig_trend.add_trace(go.Scatter(
                    x=alert_trend.index,
                    y=alert_trend[level],
                    name=level,
                    mode='lines+markers',
                    line=dict(color=colors_map.get(level, '#999999'), width=2)
                ))
        
        fig_trend.update_layout(
            title="Alert Trends Over Time",
            xaxis_title="Date",
            yaxis_title="Alert Count",
            height=400,
            hovermode='x unified'
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    
    st.divider()
    
    # ==================== ASSET ACCESS HEATMAP ====================
    st.subheader("🗺️ Asset Access Heatmap")
    
    # Create heatmap: Top users vs Top assets
    top_users_list = df_filtered['user_id'].value_counts().head(10).index
    top_assets_list = df_filtered['asset_id'].value_counts().head(10).index
    
    heatmap_data = pd.crosstab(
        df_filtered[df_filtered['user_id'].isin(top_users_list)]['user_id'],
        df_filtered[df_filtered['asset_id'].isin(top_assets_list)]['asset_id']
    )
    
    fig_heatmap = go.Figure(data=go.Heatmap(
        z=heatmap_data.values,
        x=heatmap_data.columns,
        y=heatmap_data.index,
        colorscale='YlOrRd'
    ))
    fig_heatmap.update_layout(
        title="Top 10 Users vs Top 10 Assets Access Count",
        xaxis_title="Asset ID",
        yaxis_title="User ID",
        height=500
    )
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    st.divider()
    
    # ==================== REAL-TIME STREAM SIMULATION ====================
    st.subheader("🔴 Real-time Security Alert Stream")
    
    # Sample dari filtered data untuk simulasi
    sample_size = min(20, len(df_filtered))
    sample_events = df_filtered.sample(n=sample_size, random_state=42).sort_values('event_time', ascending=False)
    
    alert_container = st.container()
    
    with alert_container:
        for idx, event in sample_events.iterrows():
            alert_level = event['alert_level']
            
            # Color mapping
            if alert_level == 'CRITICAL':
                emoji = '🔴'
                color = '#f44336'
            elif alert_level == 'HIGH':
                emoji = '🟠'
                color = '#ff9800'
            elif alert_level == 'MEDIUM':
                emoji = '🟡'
                color = '#ffc107'
            else:
                emoji = '🟢'
                color = '#4caf50'
            
            alert_html = f"""
            <div style="background-color: {color}22; border-left: 4px solid {color}; padding: 12px; margin: 5px 0; border-radius: 5px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-size: 18px; margin-right: 10px;">{emoji}</span>
                        <b>{alert_level}</b> | 
                        <span style="color: #666;">{event['event_time'].strftime('%Y-%m-%d %H:%M:%S')}</span>
                    </div>
                    <div style="text-align: right; color: #666; font-size: 12px;">
                        {event['event_id']}
                    </div>
                </div>
                <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid {color}44; font-size: 12px;">
                    User: <b>{event['user_id']}</b> | 
                    Action: <b>{event['action']}</b> | 
                    Asset: <b>{event['asset_id']}</b> | 
                    Classification: <b>{event['data_classification']}</b> | 
                    Risk Score: <b>{event['risk_score']}</b>/100
                </div>
            </div>
            """
            st.markdown(alert_html, unsafe_allow_html=True)
    
    st.divider()
    
    # ==================== DETAILED DATA TABLE ====================
    st.subheader("📋 Detailed Alert Log")
    
    display_columns = ['event_id', 'event_time', 'user_id', 'action', 'asset_id', 
                       'data_classification', 'risk_score', 'alert_level', 'label']
    
    df_display = df_filtered[display_columns].sort_values('event_time', ascending=False).head(50)
    
    st.dataframe(
        df_display,
        use_container_width=True,
        height=400,
        hide_index=True
    )
    
    st.divider()
    
    # ==================== EXPORT SECTION ====================
    st.subheader("📥 Export & Download")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Export to CSV
        csv_data = df_filtered[display_columns].to_csv(index=False)
        st.download_button(
            label="📥 Download Alert Data (CSV)",
            data=csv_data,
            file_name=f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            help="Download filtered alert data as CSV"
        )
    
    with col2:
        # Export to Excel
        try:
            import openpyxl
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                df_filtered[display_columns].to_excel(writer, sheet_name='Alerts', index=False)
                
                # Summary sheet
                summary_df = pd.DataFrame({
                    'Metric': ['Total Events', 'Critical Alerts', 'High Alerts', 'Anomalies'],
                    'Count': [
                        len(df_filtered),
                        len(df_filtered[df_filtered['alert_level'] == 'CRITICAL']),
                        len(df_filtered[df_filtered['alert_level'] == 'HIGH']),
                        len(df_filtered[df_filtered['label'] == 'anomaly'])
                    ]
                })
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            excel_buffer.seek(0)
            st.download_button(
                label="📥 Download Report (Excel)",
                data=excel_buffer.getvalue(),
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                help="Download complete report with summary as Excel"
            )
        except ImportError:
            st.warning("⚠️ openpyxl not installed. Install it with: pip install openpyxl")
    
    st.divider()
    
    # ==================== FOOTER ====================
    st.markdown("""
    ---
    **Security Monitoring Dashboard** | Last updated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
    
    💡 **Tips:**
    - Use filters to focus on specific time periods, users, or alert levels
    - High-risk patterns are highlighted in the Risk Patterns chart
    - Export data regularly for compliance and audit trails
    - Monitor the Real-time Stream section for critical alerts
    """)

if __name__ == "__main__":
    main()
