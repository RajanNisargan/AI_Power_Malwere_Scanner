import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score


# Generate synthetic training data (Example)
def generate_training_data(num_samples=1000):
    X = []
    y = []
    for _ in range(num_samples):
        # Generate random file size and entropy values
        file_size = np.random.randint(1, 10 ** 7)
        entropy = np.random.uniform(0, 8)

        # Label: 1 = Malicious, 0 = Benign
        label = 1 if entropy > 6 or file_size > 5 * 10 ** 6 else 0

        X.append([file_size, entropy])
        y.append(label)

    return np.array(X), np.array(y)


# Generate data
X, y = generate_training_data()

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Model Accuracy: {accuracy * 100:.2f}%')

# Save the model
joblib.dump(model, 'malware_model.pkl')
print("Model saved as 'malware_model.pkl'")
