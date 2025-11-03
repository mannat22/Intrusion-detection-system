import streamlit as st
import pandas as pd
import pickle

# Load trained model and encoders
model = pickle.load(open('model.pkl', 'rb'))
label_encoders = pickle.load(open('label_encoders.pkl', 'rb'))

st.title("🔒 Intrusion Detection System")
st.write("This application predicts whether the given network activity is normal or an intrusion attempt.")

# --- User Inputs ---
protocol = st.selectbox("Protocol Type", ["TCP", "UDP", "ICMP"])

service = st.text_input("Service (e.g., http, ftp, smtp):")
flag = st.text_input("Flag (e.g., SF, S0, REJ):")
src_bytes = st.number_input("Source Bytes", min_value=0)
dst_bytes = st.number_input("Destination Bytes", min_value=0)

# Prediction Button
if st.button("🔍 Predict Activity"):
    # Ensure that entered protocol is valid for the model
    try:
        proto_encoded = label_encoders['protocol_type'].transform([protocol])[0]
    except ValueError:
        st.error("⚠️ The selected protocol type is not recognized by the model.")
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

    # Create input dataframe
    input_data = pd.DataFrame([{
        'protocol_type': proto_encoded,
        'service': service_encoded,
        'flag': flag_encoded,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes
    }])

    # Make prediction
    prediction = model.predict(input_data)[0]

    if prediction == 0:
        st.success("✅ Normal Activity.")
    else:
        st.error("🚨 Intrusion Detected!")
