import pandas as pd

def filter_csv(input_file, output_file, column_name, threshold):
    df = pd.read_csv(input_file)
    filtered_df = df[df[column_name] > threshold]
    filtered_df.to_csv(output_file, index=False)

if __name__ == '__main__':
    filter_csv('input.csv', 'output.csv', 'age', 18)
