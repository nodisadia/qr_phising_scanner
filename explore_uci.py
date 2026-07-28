import pandas as pd

df = pd.read_csv('data_uci/uci-ml-phishing-dataset.csv')
print(df.shape)
print(df.columns.tolist())
print(df.head())
print(df.dtypes)