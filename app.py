import streamlit as st
import pandas as pd
import joblib

# ---- Load saved model and preprocessing tools ----
model = joblib.load("intrusion_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
label_encoders = joblib.load("label_encoders.pkl")

# ---- UI Header ----
st.title("🛡️ AI-Based Intrusion Detection System")
st.write("Detect suspicious network activities using AI")

# ---- Manually defined readable protocol names ----
protocol_mapping = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2,
    "HTTP": 3,
    "HTTPS": 4
}

# ---- Optional readable encryption and browser names ----
encryption_mapping = {
    "DES": 0,
    "AES": 1,
    "RSA": 2
}

browser_mapping = {
    "Chrome": 0,
    "Firefox": 1,
    "Edge": 2,
    "Safari": 3
}

# ---- Streamlit Dropdowns ----
protocol = st.selectbox("Protocol Type", list(protocol_mapping.keys()))
encryption = st.selectbox("Encryption Used", list(encryption_mapping.keys()))
browser = st.selectbox("Browser Type", list(browser_mapping.keys()))
packet_size = st.number_input("Network Packet Size", min_value=0)
login_attempts = st.number_input("Login Attempts", min_value=0)
session_duration = st.number_input("Session Duration (sec)", min_value=0.0)
ip_score = st.number_input("IP Reputation Score (0-1)", min_value=0.0, max_value=1.0)
failed_logins = st.number_input("Failed Logins", min_value=0)

# ---- Convert readable choices into encoded values ----
encoded_protocol = protocol_mapping[protocol]
encoded_encryption = encryption_mapping[encryption]
encoded_browser = browser_mapping[browser]

# ---- Prepare input DataFrame ----
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

# ---- Align feature order with scaler/model ----
expected_features = getattr(scaler, 'feature_names_in_', None)
if expected_features is not None:
    for col in expected_features:
        if col not in input_data.columns:
            input_data[col] = 0
    input_data = input_data[expected_features]

# ---- Prediction Button ----
if st.button("🔍 Detect Intrusion"):
    try:
        input_scaled = scaler.transform(input_data)
        prediction = model.predict(input_scaled)[0]

        if prediction == 1:
            st.error("⚠️ Suspicious Activity Detected!")
        else:
            st.success("✅ Normal Activity.")
    except Exception as e:
        st.error(f"An error occurred during detection: {e}")
