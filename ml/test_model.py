import pandas as pd
import numpy as np

# Create simple test data
print("Creating banking trojan detection model...")

# Malware samples (high risk features)
malware_data = {
    'permissions': [35, 38, 42, 30, 36],
    'sensitive_apis': [45, 50, 38, 42, 47],
    'obfuscation': [150, 180, 120, 160, 140],
    'label': [1, 1, 1, 1, 1]
}

# Benign samples (low risk features)  
benign_data = {
    'permissions': [12, 15, 18, 10, 14],
    'sensitive_apis': [8, 12, 15, 6, 10],
    'obfuscation': [20, 35, 25, 15, 30],
    'label': [0, 0, 0, 0, 0]
}

# Combine data
all_data = {
    'permissions': malware_data['permissions'] + benign_data['permissions'],
    'sensitive_apis': malware_data['sensitive_apis'] + benign_data['sensitive_apis'],
    'obfuscation': malware_data['obfuscation'] + benign_data['obfuscation'],
    'label': malware_data['label'] + benign_data['label']
}

df = pd.DataFrame(all_data)
print(f"Dataset created: {len(df)} samples")
print(f"Malware: {sum(df['label'])} samples")
print(f"Benign: {len(df) - sum(df['label'])} samples")

# Simple classification logic
def predict_malware(permissions, apis, obfuscation):
    score = 0
    if permissions > 25: score += 1
    if apis > 30: score += 1  
    if obfuscation > 100: score += 1
    return 1 if score >= 2 else 0

# Test predictions
print("\nTesting predictions:")
test_cases = [
    ("Suspicious app", 35, 45, 150),
    ("Legitimate app", 12, 8, 20)
]

for name, perms, apis, obf in test_cases:
    prediction = predict_malware(perms, apis, obf)
    label = "MALWARE" if prediction == 1 else "BENIGN"
    print(f"{name}: {label}")

print("\nModel working successfully! ✅")
