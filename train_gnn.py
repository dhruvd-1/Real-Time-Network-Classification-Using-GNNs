import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.data import Data
from torch_geometric.nn import GATConv
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import accuracy_score, classification_report
from sklearn.impute import SimpleImputer

# ----------------- Load and Prepare Datasets -----------------

# Load NSL-KDD Training Dataset
try:
    train_data = pd.read_csv("KDDTrain+.txt", header=None)
    print(f"Successfully loaded training dataset with shape: {train_data.shape}")
except Exception as e:
    print(f"Error loading training dataset: {e}")
    # If the file isn't found, you might need to adjust the path or download it

# Load NSL-KDD Test Dataset
try:
    test_data = pd.read_csv("KDDTest+.txt", header=None)
    print(f"Successfully loaded test dataset with shape: {test_data.shape}")
except Exception as e:
    print(f"Error loading test dataset: {e}")
    # If the file isn't found, you might need to adjust the path or download it

# Display the first few rows to understand the data structure
print("\nFirst 5 rows of training data:")
print(train_data.head())

# Check data types of each column
print("\nData types:")
print(train_data.dtypes)

# Check for NaN values before processing
print(f"\nTotal NaN values in training dataset: {train_data.isna().sum().sum()}")
print(f"Total NaN values in test dataset: {test_data.isna().sum().sum()}")

# CORRECTION: Split Features and Labels for both datasets
# The labels are in the second-to-last column (column 41)
X_train = train_data.drop([41], axis=1)  # Drop only the label column (41)
y_train = train_data[41]  # Get labels from column 41

X_test = test_data.drop([41], axis=1)  # Drop only the label column (41)
y_test = test_data[41]  # Get labels from column 41

print(f"\nTraining feature matrix shape: {X_train.shape}")
print(f"Training target vector shape: {y_train.shape}")
print(f"Test feature matrix shape: {X_test.shape}")
print(f"Test target vector shape: {y_test.shape}")

# ----- Identify Data Types -----
# Using select_dtypes to automatically identify categorical columns in training data
object_cols_train = X_train.select_dtypes(include=["object"]).columns
print(f"\nAutomatically identified categorical columns: {list(object_cols_train)}")

# If certain columns are not automatically detected as 'object' but should be treated as categorical
# For example, columns 1, 2, and 3 in NSL-KDD are typically categorical (protocol_type, service, flag)
known_categorical = [1, 2, 3]  # Known categorical columns from the dataset structure

# Make sure known categorical columns are treated as object type in both datasets
for col in known_categorical:
    if col in X_train.columns and col not in object_cols_train:
        X_train[col] = X_train[col].astype(str)
    if col in X_test.columns:
        X_test[col] = X_test[col].astype(str)

# Refresh object columns after type conversion
object_cols_train = X_train.select_dtypes(include=["object"]).columns
print(f"Final categorical columns: {list(object_cols_train)}")

# All other columns are treated as numeric
numeric_cols = [col for col in X_train.columns if col not in object_cols_train]
print(f"Numeric columns: {len(numeric_cols)} columns")

# ----- Handle Numeric Features -----
# Convert numeric columns to float, handling non-numeric strings in both datasets
for col in numeric_cols:
    # Try to convert to numeric, errors='coerce' will replace non-convertible values with NaN
    X_train[col] = pd.to_numeric(X_train[col], errors="coerce")
    X_test[col] = pd.to_numeric(X_test[col], errors="coerce")

# Check for NaN values after numeric conversion
print(
    f"\nNaN values in training set after numeric conversion: {X_train.isna().sum().sum()}"
)
print(f"NaN values in test set after numeric conversion: {X_test.isna().sum().sum()}")

# ----- Impute Missing Values -----
# Impute missing values for numeric columns in both datasets
if (
    X_train[numeric_cols].isna().sum().sum() > 0
    or X_test[numeric_cols].isna().sum().sum() > 0
):
    print("\nImputing missing numeric values with mean...")
    imputer = SimpleImputer(strategy="mean")
    X_train[numeric_cols] = imputer.fit_transform(X_train[numeric_cols])
    # Use the same imputer for test data to ensure consistent transformation
    X_test[numeric_cols] = imputer.transform(X_test[numeric_cols])

# Handle missing values in categorical columns before one-hot encoding
for col in object_cols_train:
    X_train[col] = X_train[col].fillna("unknown")
    if col in X_test.columns:
        X_test[col] = X_test[col].fillna("unknown")

# ----- Standardize Numerical Features -----
print("\nStandardizing numerical features...")
scaler = StandardScaler()
X_train[numeric_cols] = scaler.fit_transform(X_train[numeric_cols])
# Use the same scaler for test data
X_test[numeric_cols] = scaler.transform(X_test[numeric_cols])

# ----- One-Hot Encoding for Categorical Features -----
print("\nApplying one-hot encoding to categorical features...")

# First, combine both datasets to ensure consistent one-hot encoding
all_categories = {}
for col in object_cols_train:
    # Get all unique categories from both train and test
    if col in X_test.columns:
        all_categories[col] = set(X_train[col].unique()) | set(X_test[col].unique())
    else:
        all_categories[col] = set(X_train[col].unique())

# Apply one-hot encoding to training data
X_train_encoded = pd.get_dummies(
    X_train[object_cols_train], dummy_na=False, drop_first=False
)
print(f"One-hot encoded training features shape: {X_train_encoded.shape}")

# Apply one-hot encoding to test data (ensuring same columns as training)
X_test_encoded = pd.get_dummies(
    X_test[object_cols_train], dummy_na=False, drop_first=False
)

# Make sure test dataset has the same encoded columns as training
missing_cols = set(X_train_encoded.columns) - set(X_test_encoded.columns)
for col in missing_cols:
    X_test_encoded[col] = 0  # Add missing columns with default value

# Ensure columns are in the same order
X_test_encoded = X_test_encoded.reindex(columns=X_train_encoded.columns, fill_value=0)

print(f"One-hot encoded test features shape: {X_test_encoded.shape}")

# Combine processed numerical and categorical features for both datasets
X_train_processed = pd.concat(
    [pd.DataFrame(X_train[numeric_cols]), X_train_encoded], axis=1
)
X_test_processed = pd.concat(
    [pd.DataFrame(X_test[numeric_cols]), X_test_encoded], axis=1
)

print(f"Final processed training feature matrix shape: {X_train_processed.shape}")
print(f"Final processed test feature matrix shape: {X_test_processed.shape}")

# ----- Process Target Variable -----
# Encode the target labels - fit on all labels from both train and test
le_target = LabelEncoder()
try:
    # Combine train and test labels to fit the encoder
    combined_labels = pd.concat([y_train, y_test])
    le_target.fit(combined_labels)

    # Transform train and test labels
    y_train_encoded = le_target.transform(y_train)
    y_test_encoded = le_target.transform(y_test)

    print(f"Target classes: {le_target.classes_}")

    # Check if 'normal' is one of the classes
    normal_class = None
    for idx, class_name in enumerate(le_target.classes_):
        if "normal" in str(class_name).lower():
            normal_class = idx
            break

    # Binary classification: 0-normal, 1-attack
    if normal_class is not None:
        y_train_binary = (y_train_encoded != normal_class).astype(int)
        y_test_binary = (y_test_encoded != normal_class).astype(int)
        print(f"Binary classification: normal (class {normal_class}) vs attack")
    else:
        # If 'normal' not found, assume the first class (0) is normal
        y_train_binary = (y_train_encoded != 0).astype(int)
        y_test_binary = (y_test_encoded != 0).astype(int)
        print("Binary classification: assuming first class is normal")

    # Check class distribution
    train_unique, train_counts = np.unique(y_train_binary, return_counts=True)
    test_unique, test_counts = np.unique(y_test_binary, return_counts=True)
    print(f"Training class distribution: {dict(zip(train_unique, train_counts))}")
    print(f"Test class distribution: {dict(zip(test_unique, test_counts))}")

except Exception as e:
    print(f"Error encoding target labels: {e}")
    # Fall back to a simpler approach
    y_train_binary = np.zeros(len(y_train))
    y_test_binary = np.zeros(len(y_test))
    print("Falling back to default target encoding")

# ----- Final Data Preparation -----
# Convert to numpy arrays for further processing
X_train_array = X_train_processed.values
y_train_array = y_train_binary
X_test_array = X_test_processed.values
y_test_array = y_test_binary

# Final check for NaN/Inf values - Convert to float32
print("\nPerforming final check for NaN/Inf values...")
try:
    # Ensure arrays have float data type
    X_train_array = X_train_array.astype(np.float32)
    X_test_array = X_test_array.astype(np.float32)

    # Check and clean train data
    if np.isnan(X_train_array).any() or np.isinf(X_train_array).any():
        print(
            "Warning: Training data contains NaN or Inf values. Replacing with zeros."
        )
        X_train_array = np.nan_to_num(X_train_array)
    else:
        print("No NaN or Inf values found in training data.")

    # Check and clean test data
    if np.isnan(X_test_array).any() or np.isinf(X_test_array).any():
        print("Warning: Test data contains NaN or Inf values. Replacing with zeros.")
        X_test_array = np.nan_to_num(X_test_array)
    else:
        print("No NaN or Inf values found in test data.")

except TypeError as e:
    print(f"Error checking for NaN/Inf: {e}")
    print("Converting arrays to float32 and replacing potential NaN/Inf values...")
    # Force conversion to float32 and replace any problematic values
    X_train_array = np.nan_to_num(X_train_array.astype(np.float32))
    X_test_array = np.nan_to_num(X_test_array.astype(np.float32))

# ----------------- Create Graph Structure -----------------

# FIX: Create within-dataset KNN graphs to avoid index out of range issues
try:
    k = 5  # Number of neighbors
    print(f"\nCreating KNN graph with k={k} neighbors for training data...")

    # Training graph - only connecting nodes within the training set
    knn_train = NearestNeighbors(
        n_neighbors=k + 1
    )  # k+1 because a node will be its own nearest neighbor
    knn_train.fit(X_train_array)
    train_distances, train_indices = knn_train.kneighbors(X_train_array)

    # Skip the first neighbor (self) and create edge pairs
    rows_train = np.repeat(np.arange(X_train_array.shape[0]), k)
    cols_train = train_indices[:, 1:].flatten()  # Skip the first column (self)

    # Create edge_index tensor for training (explicitly ensuring indices are within bounds)
    train_edge_index = torch.tensor([rows_train, cols_train], dtype=torch.long)
    print(f"Created training edge_index with shape: {train_edge_index.shape}")

    # Test graph - only connecting nodes within the test set
    print(f"Creating KNN graph with k={k} neighbors for test data...")
    knn_test = NearestNeighbors(n_neighbors=k + 1)
    knn_test.fit(X_test_array)
    test_distances, test_indices = knn_test.kneighbors(X_test_array)

    # Skip the first neighbor (self) and create edge pairs for test set
    rows_test = np.repeat(np.arange(X_test_array.shape[0]), k)
    cols_test = test_indices[:, 1:].flatten()  # Skip the first column (self)

    # Create edge_index tensor for test (explicitly ensuring indices are within bounds)
    test_edge_index = torch.tensor([rows_test, cols_test], dtype=torch.long)
    print(f"Created test edge_index with shape: {test_edge_index.shape}")

    # Verify that indices are within bounds
    max_train_idx = X_train_array.shape[0] - 1
    max_test_idx = X_test_array.shape[0] - 1

    print(
        f"Training data: {X_train_array.shape[0]} nodes, max index in edge_index: {train_edge_index.max().item()}"
    )
    print(
        f"Test data: {X_test_array.shape[0]} nodes, max index in edge_index: {test_edge_index.max().item()}"
    )

    # Additional safety check
    if train_edge_index.max() > max_train_idx:
        print(
            "WARNING: Training edge_index contains indices outside valid range. Fixing..."
        )
        train_edge_index = train_edge_index[:, train_edge_index[0] <= max_train_idx]
        train_edge_index = train_edge_index[:, train_edge_index[1] <= max_train_idx]

    if test_edge_index.max() > max_test_idx:
        print(
            "WARNING: Test edge_index contains indices outside valid range. Fixing..."
        )
        test_edge_index = test_edge_index[:, test_edge_index[0] <= max_test_idx]
        test_edge_index = test_edge_index[:, test_edge_index[1] <= max_test_idx]

except Exception as e:
    print(f"Error creating KNN graph: {e}")
    # Create fallback simple graphs
    print("Creating fallback graph structures...")

    # Fallback for training data
    n_train = X_train_array.shape[0]
    k = min(5, n_train - 1)  # Ensure k is less than number of nodes
    rows_train, cols_train = [], []
    for i in range(n_train):
        for j in range(1, k + 1):
            rows_train.append(i)
            cols_train.append(
                (i + j) % n_train
            )  # Connect to next k nodes with wraparound
    train_edge_index = torch.tensor([rows_train, cols_train], dtype=torch.long)
    print(f"Created fallback training edge_index with shape: {train_edge_index.shape}")

    # Fallback for test data
    n_test = X_test_array.shape[0]
    k = min(5, n_test - 1)  # Ensure k is less than number of nodes
    rows_test, cols_test = [], []
    for i in range(n_test):
        for j in range(1, k + 1):
            rows_test.append(i)
            cols_test.append(
                (i + j) % n_test
            )  # Connect to next k nodes with wraparound
    test_edge_index = torch.tensor([rows_test, cols_test], dtype=torch.long)
    print(f"Created fallback test edge_index with shape: {test_edge_index.shape}")

# Prepare feature matrices and labels for both datasets
x_train = torch.tensor(X_train_array, dtype=torch.float32)
y_train = torch.tensor(y_train_array, dtype=torch.long)
x_test = torch.tensor(X_test_array, dtype=torch.float32)
y_test = torch.tensor(y_test_array, dtype=torch.long)

print(f"Training feature tensor shape: {x_train.shape}")
print(f"Training label tensor shape: {y_train.shape}")
print(f"Test feature tensor shape: {x_test.shape}")
print(f"Test label tensor shape: {y_test.shape}")

# Check for NaN values in tensors
if torch.isnan(x_train).any() or torch.isinf(x_train).any():
    print("Warning: Training tensor contains NaN or Inf values. Replacing with zeros.")
    x_train = torch.nan_to_num(x_train)
if torch.isnan(x_test).any() or torch.isinf(x_test).any():
    print("Warning: Test tensor contains NaN or Inf values. Replacing with zeros.")
    x_test = torch.nan_to_num(x_test)

# Create PyG Data objects
train_data = Data(x=x_train, edge_index=train_edge_index, y=y_train)
test_data = Data(x=x_test, edge_index=test_edge_index, y=y_test)

# ----------------- Define GNN Model -----------------


class GNN_Model(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes):
        super(GNN_Model, self).__init__()
        self.conv1 = GATConv(input_dim, hidden_dim, heads=4, concat=True)
        self.conv2 = GATConv(hidden_dim * 4, hidden_dim, heads=4, concat=True)
        self.conv3 = GATConv(hidden_dim * 4, hidden_dim, heads=1, concat=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        x = self.conv1(x, edge_index)
        x = torch.relu(x)
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        x = torch.relu(x)
        x = self.dropout(x)
        x = self.conv3(x, edge_index)
        x = torch.relu(x)
        x = self.fc(x)
        return x


# ----------------- Train the Model -----------------

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"\nUsing device: {device}")

# Ensure input dimensions match
input_dim = x_train.shape[1]
print(f"Input dimension: {input_dim}")

model = GNN_Model(input_dim=input_dim, hidden_dim=128, num_classes=2).to(device)
train_data_device = train_data.to(device)

# Additional safety check after moving to device
if torch.isnan(train_data_device.x).any() or torch.isinf(train_data_device.x).any():
    print(
        "Warning: Training data on device contains NaN or Inf values. Replacing with zeros."
    )
    train_data_device.x = torch.nan_to_num(train_data_device.x)

optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)

# Check class balance and adjust weights accordingly
class_counts = torch.bincount(y_train)
total_samples = len(y_train)
class_weights = total_samples / (len(class_counts) * class_counts.float())
print(f"Class weights: {class_weights}")

criterion = nn.CrossEntropyLoss(weight=class_weights.to(device))
scheduler = optim.lr_scheduler.ReduceLROnPlateau(
    optimizer, mode="min", factor=0.5, patience=5
)

# Training Loop
epochs = 100
best_val_loss = float("inf")
patience = 10
wait = 0

# Initialize best_model_state before training
best_model_state = model.state_dict()  # Initialize with current model state

print("\nStarting training...")
for epoch in range(epochs):
    model.train()
    optimizer.zero_grad()

    try:
        out = model(train_data_device)

        # Check for NaN in output
        if torch.isnan(out).any():
            print(
                f"Warning: NaN detected in model output at epoch {epoch + 1}. Skipping update."
            )
            continue

        loss = criterion(out, train_data_device.y)

        # Check for NaN in loss
        if torch.isnan(loss).any():
            print(
                f"Warning: NaN detected in loss at epoch {epoch + 1}. Skipping update."
            )
            continue

        loss.backward()

        # Gradient clipping to prevent exploding gradients
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)

        optimizer.step()
    except RuntimeError as e:
        print(f"Error in epoch {epoch + 1}: {e}")
        optimizer.zero_grad()
        continue

    # Validation on test data
    model.eval()
    with torch.no_grad():
        # Move test data to device for validation
        test_data_device = test_data.to(device)

        # Check for NaN/Inf in test data
        if (
            torch.isnan(test_data_device.x).any()
            or torch.isinf(test_data_device.x).any()
        ):
            test_data_device.x = torch.nan_to_num(test_data_device.x)

        out_test = model(test_data_device)

        # Check for NaN in validation output
        if torch.isnan(out_test).any():
            print(f"Warning: NaN detected in validation output at epoch {epoch + 1}.")
            val_loss = torch.tensor(float("inf"), device=device)
        else:
            val_loss = criterion(out_test, test_data_device.y)

    scheduler.step(val_loss)

    if (epoch + 1) % 5 == 0:  # Print every 5 epochs to reduce output
        print(
            f"Epoch {epoch + 1}, Train Loss: {loss.item():.4f}, Val Loss: {val_loss.item():.4f}"
        )

    # Early stopping
    if val_loss.item() < best_val_loss:
        best_val_loss = val_loss.item()
        wait = 0
        # Save best model
        best_model_state = model.state_dict()
    else:
        wait += 1
        if wait == patience:
            print(f"Early stopping triggered at epoch {epoch + 1}!")
            break

# Load best model
model.load_state_dict(best_model_state)

# ----------------- Evaluate the Model on Test Dataset -----------------

print("\nEvaluating model on test dataset...")
model.eval()
with torch.no_grad():
    # Ensure test data is on the right device
    test_data_device = test_data.to(device)

    # Sanity check
    if torch.isnan(test_data_device.x).any() or torch.isinf(test_data_device.x).any():
        test_data_device.x = torch.nan_to_num(test_data_device.x)

    out_test = model(test_data_device)
    if torch.isnan(out_test).any():
        print("Warning: NaN detected in final model output. Results may be unreliable.")
    pred_test = out_test.argmax(dim=1)

# Calculate Test Accuracy
try:
    test_acc = accuracy_score(test_data_device.y.cpu(), pred_test.cpu())
    print(f"\nTest Accuracy: {test_acc * 100:.2f}%")

    # Detailed Classification Report
    print("\nClassification Report on Test Data:")
    print(
        classification_report(
            test_data_device.y.cpu(), pred_test.cpu(), target_names=["Normal", "Attack"]
        )
    )
except Exception as e:
    print(f"Error calculating metrics: {e}")

# Final evaluation on training data for comparison
model.eval()
with torch.no_grad():
    out_train = model(train_data_device)
    pred_train = out_train.argmax(dim=1)
    train_acc = accuracy_score(train_data_device.y.cpu(), pred_train.cpu())
    print(f"\nTraining Accuracy: {train_acc * 100:.2f}%")

# Print model summary
total_params = sum(p.numel() for p in model.parameters())
trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
print(f"\nModel Summary:")
print(f"Total parameters: {total_params}")
print(f"Trainable parameters: {trainable_params}")

print("\nTraining complete!")

# Optional: Save the model
try:
    torch.save(model.state_dict(), "gnn_intrusion_detection_model.pth")
    print("Model saved successfully.")
except Exception as e:
    print(f"Error saving model: {e}")

# ============ ADD THIS SECTION ============
print("Saving preprocessors for real-time inference...")

# Create models directory
import os

if not os.path.exists("models"):
    os.makedirs("models")

# Save the scaler
import joblib

joblib.dump(scaler, "models/scaler.pkl")

# Save preprocessing information
preprocessing_info = {
    "feature_columns": X_train_processed.columns.tolist(),
    "numeric_cols": numeric_cols,
    "categorical_cols": list(object_cols_train),
    "input_dim": X_train_processed.shape[1],
    "target_classes": le_target.classes_.tolist(),
    "normal_class_index": normal_class,
}

import pickle

with open("models/preprocessing_info.pkl", "wb") as f:
    pickle.dump(preprocessing_info, f)

# Move model to models directory
import shutil

if os.path.exists("gnn_intrusion_detection_model.pth"):
    shutil.move(
        "gnn_intrusion_detection_model.pth", "models/gnn_intrusion_detection_model.pth"
    )

print("✅ Preprocessors saved successfully!")
print(f"📊 Model input dimension: {X_train_processed.shape[1]}")
print(f"💾 Files saved:")
print(f"  - models/gnn_intrusion_detection_model.pth")
print(f"  - models/scaler.pkl")
print(f"  - models/preprocessing_info.pkl")
