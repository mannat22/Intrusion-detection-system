import streamlit as st
import pandas as pd
import joblib

# Load saved model and preprocessing tools
model = joblib.load("intrusion_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
label_encoders = joblib.load("label_encoders.pkl")

st.title("🛡️ AI-Based Intrusion Detection System")
st.write("Detect suspicious network activities using AI")

# ---- Auto-load classes from model encoders ----
protocol_classes = list(label_encoders['protocol_type'].classes_)
encryption_classes = list(label_encoders['encryption_used'].classes_)
browser_classes = list(label_encoders['browser_type'].classes_)

# ---- User Inputs ----
protocol = st.selectbox("Protocol Type", protocol_classes)
encryption = st.selectbox("Encryption Used", encryption_classes)
browser = st.selectbox("Browser Type", browser_classes)
packet_size = st.number_input("Network Packet Size", min_value=0)
login_attempts = st.number_input("Login Attempts", min_value=0)
session_duration = st.number_input("Session Duration (sec)", min_value=0.0)
ip_score = st.number_input("IP Reputation Score (0-1)", min_value=0.0, max_value=1.0)
failed_logins = st.number_input("Failed Logins", min_value=0)

# ---- Encode categorical features ----
encoded_protocol = label_encoders['protocol_type'].transform([protocol])[0]
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
