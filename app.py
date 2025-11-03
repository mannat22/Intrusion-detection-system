import streamlit as st
import pandas as pd
import joblib

# Load saved model and preprocessing tools
model = joblib.load("intrusion_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
label_encoders = joblib.load("label_encoders.pkl")

st.title("🛡️ AI-Based Intrusion Detection System")
st.write("Detect suspicious network activities using AI")

# ---- Protocol Mapping (User-friendly → Model format) ----
# Adjust the right-side values ("tcp", "udp", "icmp") to match label_encoders['protocol_type'].classes_
protocol_map = {
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp"
}

# ---- User Inputs ----
protocol = st.selectbox("Protocol Type", list(protocol_map.keys()))
encryption = st.selectbox("Encryption Used", list(label_encoders['encryption_used'].classes_))
browser = st.selectbox("Browser Type", list(label_encoders['browser_type'].classes_))
packet_size = st.number_input("Network Packet Size", min_value=0)
login_attempts = st.number_input("Login Attempts", min_value=0)
session_duration = st.number_input("Session Duration (sec)", min_value=0.0)
ip_score = st.number_input("IP Reputation Score (0-1)", min_value=0.0, max_value=1.0)
failed_logins = st.number_input("Failed Logins", min_value=0)

# ---- Encode inputs safely ----
try:
    encoded_protocol = label_encoders['protocol_type'].transform([protocol_map[protocol]])[0]
except ValueError:
    st.error("⚠️ The selected protocol type is not recognized by the model.")
    st.stop()

encoded_encryption = label_encoders['encryption_used'].transform([encryption])[0]
encoded_browser = label_encoders['browser_type'].transform([browser])[0]

# ---- Create input dataframe ----
input_data = pd.DataFrame({
    'network_packet_size': [packet_size],
    'protocol_type': [encoded_protocol],
    'login_attempts': [login_attempts],
    'session_duration': [session_duration],
    'encryption_used': [encoded_encryption],
    'ip_reputation_score': [ip_score],
    'failed_logins': [failed_logins],
    'browser_type': [encoded_browser]
})

# ---- Scale and Predict ----
input_scaled = scaler.transform(input_data)

if st.button("🔍 Detect"):
    prediction = model.predict(input_scaled)[0]
    if prediction == 1:
        st.error("⚠️ Suspicious Activity Detected!")
    else:
        st.success("✅ Normal Activity.")
