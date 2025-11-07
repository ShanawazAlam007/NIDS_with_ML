import flask
import joblib
import json
import pandas as pd
import logging

app = flask.Flask(__name__)

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the consolidated model
try:
    model_components = joblib.load('nids_model_cpu.pkl')
    logging.info("[INFO] Loaded consolidated model.")
except Exception as e:
    logging.error(f"[ERROR] Failed to load model: {e}")
    exit()

# Extract model components
scaler = model_components['preprocessor']
ipca = model_components['pca']
kmeans = model_components['kmeans']
rf = model_components['classifier']
cluster_to_protocol = model_components['cluster_protocol_map']

# Load feature list
try:
    with open('features.json', 'r') as f:
        features_data = json.load(f)
        feature_columns = features_data['features']
except Exception as e:
    logging.error(f"[ERROR] Failed to load features.json: {e}")
    exit()

flow_count = 0

@app.route("/predict", methods=["POST"])
def predict():
    global flow_count
    data = {"success": False}
    if flask.request.get_json():
        raw_features = flask.request.get_json()
        logging.info(f"Received request: {raw_features}")

        # Whitelist SSDP traffic to prevent false positives
        if raw_features.get("protocol_num") == 17 and raw_features.get("dst_ip") == "239.255.255.250":
            data["prediction"] = 0  # Benign
            data["protocol_name"] = "UDP"
            data["success"] = True
            logging.info(f"Whitelisted SSDP traffic from {raw_features.get('src_ip')} to {raw_features.get('dst_ip')}")
            return flask.jsonify(data)
        
        # Create a DataFrame with the correct columns and order
        features_df = pd.DataFrame(columns=feature_columns)
        features_df.loc[0] = 0  # Initialize with zeros

        # Fill in the values from the request
        if 'packet_size' in raw_features:
            packet_size = raw_features['packet_size']
            features_df['LONGEST_FLOW_PKT'] = packet_size
            features_df['SHORTEST_FLOW_PKT'] = packet_size
            features_df['MIN_IP_PKT_LEN'] = packet_size
            features_df['MAX_IP_PKT_LEN'] = packet_size

        if 'protocol_num' in raw_features:
            protocol_num = raw_features['protocol_num']
            protocol_col = f'PROTOCOL_{protocol_num}.0'
            if protocol_col in features_df.columns:
                features_df[protocol_col] = 1

        try:
            # Preprocess the data
            scaled_features = scaler.transform(features_df)
            
            # Apply PCA and KMeans
            X_pca = ipca.transform(scaled_features)
            cluster = kmeans.predict(X_pca)[0]
            
            # Determine protocol name directly from protocol_num
            protocol_num = raw_features.get("protocol_num", 0)
            if protocol_num == 1:
                protocol_name = "ICMP"
            elif protocol_num == 6:
                protocol_name = "TCP"
            elif protocol_num == 17:
                protocol_name = "UDP"
            else:
                protocol_name = "Unknown"

            # Predict the outcome
            prediction = rf.predict(scaled_features)
            data["prediction"] = int(prediction[0])
            data["protocol_name"] = protocol_name
            data["success"] = True

            # Log the result
            flow_count += 1
            src_ip = raw_features.get("src_ip", "Unknown_Src_IP")
            dst_ip = raw_features.get("dst_ip", "Unknown_Dst_IP")
            log_message = f'{protocol_name} packet detected from {src_ip} -> {dst_ip} | Count: {flow_count}'
            logging.info(log_message)

        except Exception as e:
            logging.error(f"[ERROR] Prediction failed: {e}")
            data["error"] = str(e)

    return flask.jsonify(data)

if __name__ == "__main__":
    logging.info("[INFO] Starting server...")
    try:
        app.run(host='0.0.0.0', port=5001)
    except Exception as e:
        logging.error(f"[ERROR] Server failed to start: {e}")