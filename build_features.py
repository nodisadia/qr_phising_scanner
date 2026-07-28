import pandas as pd
from features import extract_features

df = pd.read_csv('data/urls_binary.csv')

print("Extracting features... this will take a minute or two")
feature_dicts = df['url'].apply(extract_features)
features_df = pd.DataFrame(list(feature_dicts))

# Combine features with the label
final_df = pd.concat([features_df, df['label']], axis=1)

final_df.to_csv('data/features_final.csv', index=False)
print("Done. Saved data/features_final.csv")
print(final_df.head())
print(final_df.shape)