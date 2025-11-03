import streamlit as st
import pandas as pd
import joblib

# Load saved model and preprocessing tools
model = joblib.load("intrusion_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
label_encoders = joblib.load("label_encoders.pkl")

st.title("🛡️ AI-Based Intrusion Detection System")
st.write("Detect suspicious network activities using AI")

# --- Step 1: Define human-friendly protocol mapping ---
# You can edit this mapping according to your dataset
protocol_display = ["TCP", "UDP", "ICMP"]
protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}

# --- Step 2: User Input Fields ---
protocol = st.selectbox("Protocol Type", protocol_display)
encryption = st.selectbox("Encryption Used", list(label_encoders['encryption_used'].classes_))
browser = st.selectbox("Browser Type", list(label_encoders['browser_type'].classes_))
packet_size = st.number_input("Network Packet Size", min_value=0)
login_attempts = st.number_input("Login Attempts", min_value=0)
session_duration = st.number_input("Session Duration (sec)", min_value=0.0)
failed_logins = st.number_input("Failed Logins", min_value=0)

# --- Step 3: Button for Prediction ---
if st.button("🔍 Detect"):
    try:
        # Convert selections into model-ready format
        protocol_encoded = protocol_map[protocol]
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

        # Scale the features
        input_scaled = scaler.transform(input_data)

        # Predict
        prediction = model.predict(input_scaled)[0]

        # Display results
        if prediction == 1:
            st.error("🚨 Suspicious Activity Detected!")
        else:
            st.success("✅ Normal Network Activity.")

    except Exception as e:
        st.error(f"⚠️ Error during prediction: {e}")
