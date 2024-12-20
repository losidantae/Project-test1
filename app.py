from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import scapy.all as scapy
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # ใช้สำหรับ session

# ตั้งค่า LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # ถ้าผู้ใช้ไม่ได้ล็อกอิน จะไปที่หน้าล็อกอิน

# โมเดล AI
model = None

def train_model():
    data = {
        'packet_size': [500, 600, 450, 700, 900],
        'connection_type': [1, 1, 2, 1, 1],
        'attack': [0, 0, 1, 0, 1]  # 0 = ไม่มีการโจมตี, 1 = การโจมตี
    }
    df = pd.DataFrame(data)

    X = df.drop('attack', axis=1)
    y = df['attack']

    model = RandomForestClassifier()
    model.fit(X, y)
    
    # บันทึกโมเดล
    joblib.dump(model, 'cyber_threat_model.pkl')
    print("Model trained and saved successfully.")  # ใช้ print แทน flash

def load_model():
    model_file = 'cyber_threat_model.pkl'

    # ตรวจสอบว่าไฟล์โมเดลมีอยู่หรือไม่
    if not os.path.exists(model_file):
        print(f"{model_file} not found, training a new model...")  # แจ้งเตือนผ่าน print
        train_model()  # ฝึกโมเดลใหม่
    else:
        try:
            model = joblib.load(model_file)
            if not isinstance(model, RandomForestClassifier):
                raise ValueError("Loaded model is not a RandomForestClassifier")
            print("Model loaded successfully.")  # แจ้งเตือนผ่าน print
        except (FileNotFoundError, ValueError) as e:
            print(f"Error loading model: {e}")  # แจ้งเตือนผ่าน print
            # หากเกิดข้อผิดพลาดในการโหลดโมเดล ให้เรียกฝึกโมเดลใหม่
            train_model()

# ฟังก์ชันสำหรับตรวจจับภัยคุกคาม
def detect_threat(traffic_data):
    if model is None:
        raise ValueError("Model is not loaded.")
    
    # ใช้โมเดลในการทำนาย
    predictions = model.predict(traffic_data)
    
    return predictions

# ฟังก์ชันในการรวบรวมข้อมูลจากทราฟฟิกเครือข่าย
def capture_traffic():
    try:
        packets = scapy.sniff(count=10)
    except Exception as e:
        packets = []  # หรือแจ้งเตือนว่าไม่สามารถจับข้อมูลได้
        print(f"Error capturing traffic: {e}")  # แจ้งเตือนผ่าน print
        return pd.DataFrame()  # ส่งคืน DataFrame ว่าง
    
    if packets == []:
        print("No packets captured.")  # แจ้งเตือนผ่าน print
        return pd.DataFrame()  # ส่งคืน DataFrame ว่างถ้าไม่มีแพ็กเก็ตที่จับได้
    
    data = []
    for packet in packets:
        packet_info = {
            "src_ip": packet[scapy.IP].src if scapy.IP in packet else None,
            "dst_ip": packet[scapy.IP].dst if scapy.IP in packet else None,
            "length": len(packet)
        }
        data.append(packet_info)
    
    return pd.DataFrame(data)


# API สำหรับตรวจจับภัยคุกคาม
@app.route('/scan', methods=['POST'])
@login_required
def scan():
    try:
        traffic_data = capture_traffic()
        if traffic_data.empty:
            flash('No traffic data captured.', 'danger')  # ใช้ flash ได้ที่นี่เพราะเป็นส่วนหนึ่งของ request context
            return jsonify({'alert': 'No traffic data captured.'})

        threat_data = traffic_data[['length']]  # ใช้เฉพาะข้อมูลที่จำเป็น
        predictions = detect_threat(threat_data)  # เรียกใช้ฟังก์ชัน detect_threat

        if 1 in predictions:
            flash('Cyber attack detected!', 'danger')  # ใช้ flash ได้ที่นี่เพราะเป็นส่วนหนึ่งของ request context
            return jsonify({'alert': 'Cyber attack detected!'})
        else:
            flash('No threat detected.', 'success')  # ใช้ flash ได้ที่นี่เพราะเป็นส่วนหนึ่งของ request context
            return jsonify({'alert': 'No threat detected.'})
    except Exception as e:
        flash(f"Error analyzing traffic: {e}", 'danger')  # ใช้ flash ได้ที่นี่เพราะเป็นส่วนหนึ่งของ request context
        return jsonify({'alert': f"Error analyzing traffic: {e}"})

if __name__ == '__main__':
    load_model()  # โหลดหรือฝึกโมเดลก่อนเริ่มเซิร์ฟเวอร์
    app.run(debug=True)

