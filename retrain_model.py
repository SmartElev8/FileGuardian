import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split
import pickle
import os

# Load the dataset
print("Loading dataset...")
dataset = pd.read_csv('Dataset/data.csv', sep='|')

# Prepare features and target
print("Preparing features...")
X = dataset.drop(['Name', 'md5', 'legitimate'], axis=1).values
y = dataset['legitimate'].values

# Feature selection
print("Selecting features...")
extratrees = ExtraTreesClassifier().fit(X, y)
model = SelectFromModel(extratrees, prefit=True)
X_new = model.transform(X)
nbfeatures = X_new.shape[1]

# Get feature names
features = []
index = np.argsort(extratrees.feature_importances_)[::-1][:nbfeatures]
for f in range(nbfeatures):
    print("%d. feature %s (%f)" % (f + 1, dataset.columns[2+index[f]], extratrees.feature_importances_[index[f]]))
    features.append(dataset.columns[2+f])

# Split data
print("Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(X_new, y, test_size=0.29, stratify=y)

# Train models
print("Training models...")
models = {
    "DecisionTree": RandomForestClassifier(n_estimators=50, max_depth=10),
    "RandomForest": RandomForestClassifier(n_estimators=50)
}

results = {}
for algo in models:
    print(f"Training {algo}...")
    clf = models[algo]
    clf.fit(X_train, y_train)
    score = clf.score(X_test, y_test)
    print(f"{algo} score: {score}")
    results[algo] = score

# Select best model
winner = max(results, key=results.get)
print(f"\nUsing {winner} for classification, with {len(features)} features.")

# Save model and features
print("Saving model and features...")
os.makedirs('Classifier', exist_ok=True)
joblib.dump(models[winner], 'Classifier/classifier.pkl')
with open('Classifier/features.pkl', 'wb') as f:
    pickle.dump(features, f)

print("Done! Model has been retrained and saved.") 