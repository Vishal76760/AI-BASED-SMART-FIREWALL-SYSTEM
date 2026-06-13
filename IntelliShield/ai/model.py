from sklearn.ensemble import IsolationForest
import numpy as np

# Training data
# [Port, Packet Size]

X = np.array([
    [80, 500],
    [443, 450],
    [53, 300],
    [22, 7000]
])

# Create model
model = IsolationForest(contamination=0.1)

# Train model
model.fit(X)

# Test traffic
test_data = [[22, 9000]]

# Predict
result = model.predict(test_data)

# Output
if result[0] == -1:
    print("Suspicious Traffic Detected!")
else:
    print("Normal Traffic")