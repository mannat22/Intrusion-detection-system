import streamlit as st
import pandas as pd
import joblib

# Load saved model and preprocessing tools
model = joblib.load("intrusion_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
label_encoders = joblib.load("label_encoders.pkl")

st.title("🛡️ AI-Based Intrusion Detection System")
st.write("Detect suspicious network activities using AI")

# Define user-friendly protocol options
protocol_options = {
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp"
}

# User input fields
protocol_display = st.selectbox("Protocol Type", list(protocol_options.keys()))
protocol_value = protocol_options[protocol_display]

encryption = st.selectbox("Encryption Used", list(label_encoders['encryption_used'].classes_))
browser = st.selectbox("Browser Type", list(label_encoders['browser_type'].classes_))
packet_size = st.number_input("Network Packet Size", min_value=0)
login_attempts = st.number_input("Login Attempts", min_value=0)
session_duration = st.number_input("Session Duration (sec)", min_value=0.0)
failed_logins = st.number_input("Failed Logins", min_value=0)

# Button to get prediction
if st.button("🔍 Detect"):
    try:
        # Transform categorical values using label encoders
        protocol_encoded = label_encoders['protocol_type'].transform([protocol_value])[0]
        encryption_encoded = label_encoders['encryption_used'].transform([encryption])[0]
        browser_encoded = label_encoders['browser_type'].transform([browser])[0]

        # Prepare input for prediction
        input_data = pd.DataFrame({
            'network_packet_size': [packet_size],
            'protocol_type': [protocol_encoded],
            'login_attempts': [login_attempts],
            'session_duration': [session_duration],
            'encryption_used': [encryption_encoded],
            'failed_logins': [failed_logins],
            'browser_type': [browser_encoded]
        })

        # Scale features
        input_scaled = scaler.transform(input_data)

        # Prediction
        prediction = model.predict(input_scaled)[0]

        # Display result
        if prediction == 1:
            st.error("⚠️ Suspicious Activity Detected!")
        else:
            st.success("✅ Normal Activity.")

    except Exception as e:
        st.error(f"An error occurred: {e}")
