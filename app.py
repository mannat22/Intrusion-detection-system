import streamlit as st
import pandas as pd
import joblib

# Load saved model and preprocessing tools
model = joblib.load("intrusion_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
label_encoders = joblib.load("label_encoders.pkl")

st.title("🛡️ AI-Based Intrusion Detection System")
st.write("Detect suspicious network activities using AI")

# User input fields
protocol = st.selectbox("Protocol Type", ["TCP", "UDP", "ICMP"])
encryption = st.selectbox("Encryption Used", list(label_encoders['encryption_used'].classes_))
browser = st.selectbox("Browser Type", list(label_encoders['browser_type'].classes_))
packet_size = st.number_input("Network Packet Size", min_value=0)
login_attempts = st.number_input("Login Attempts", min_value=0)
session_duration = st.number_input("Session Duration (sec)", min_value=0.0)
ip_score = st.number_input("IP Reputation Score (0-1)", min_value=0.0, max_value=1.0)
failed_logins = st.number_input("Failed Logins", min_value=0)

# Prepare input for prediction
input_data = pd.DataFrame({
    'network_packet_size': [packet_size],
    'protocol_type': [label_encoders['protocol_type'].transform([protocol])[0]],
    'login_attempts': [login_attempts],
    'session_duration': [session_duration],
    'encryption_used': [label_encoders['encryption_used'].transform([encryption])[0]],
    'ip_reputation_score': [ip_score],
    'failed_logins': [failed_logins],
    'browser_type': [label_encoders['browser_type'].transform([browser])[0]]
})

# Scale features
input_scaled = scaler.transform(input_data)

# Prediction
if st.button("🔍 Detect"):
    prediction = model.predict(input_scaled)[0]
    if prediction == 1:
        st.error("⚠️ Suspicious Activity Detected!")
    else:
        st.success("✅ Normal Activity.")
