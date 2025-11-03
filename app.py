import streamlit as st
import pandas as pd
import pickle

# Load model and encoders
model = pickle.load(open('model.pkl', 'rb'))
label_encoders = pickle.load(open('label_encoders.pkl', 'rb'))

st.title("🔍 Detect Suspicious Network Activities using AI")
st.write("This AI model predicts whether a network activity is **normal or an intrusion** based on input parameters.")

# --- User Inputs ---
# Human-readable protocol list
protocol_display = ["TCP", "UDP", "ICMP"]
protocol = st.selectbox("Protocol Type", protocol_display)

service = st.text_input("Service (e.g., http, ftp, smtp):")
flag = st.text_input("Flag (e.g., SF, S0, REJ):")
src_bytes = st.number_input("Source Bytes", min_value=0)
dst_bytes = st.number_input("Destination Bytes", min_value=0)

# --- Predict Button ---
if st.button("🚀 Predict Activity"):
    try:
        # Convert readable protocol to lowercase (match training data)
        protocol_lower = protocol.lower()

        # Transform using encoder
        proto_encoded = label_encoders['protocol_type'].transform([protocol_lower])[0]
    except ValueError:
        st.error("⚠️ The selected protocol is not recognized by the model.")
        st.stop()

    try:
        service_encoded = label_encoders['service'].transform([service])[0]
    except ValueError:
        st.error("⚠️ The entered service is not recognized by the model.")
        st.stop()

    try:
        flag_encoded = label_encoders['flag'].transform([flag])[0]
    except ValueError:
        st.error("⚠️ The entered flag is not recognized by the model.")
        st.stop()

    # Combine into input dataframe
    input_data = pd.DataFrame([{
        'protocol_type': proto_encoded,
        'service': service_encoded,
        'flag': flag_encoded,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes
    }])

    # Predict
    prediction = model.predict(input_data)[0]

    # Output result
    if prediction == 0:
        st.success("✅ Normal Network Activity.")
    else:
        st.error("🚨 Intrusion Detected!")
