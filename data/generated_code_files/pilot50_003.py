import pandas as pd


def filter_csv(input_file, output_file, column_name, min_value):
    df = pd.read_csv(input_file)

    if column_name not in df.columns:
        raise ValueError(f"Column not found: {column_name}")

    filtered_df = df[df[column_name] >= min_value]
    filtered_df.to_csv(output_file, index=False)

    return len(filtered_df)


if __name__ == "__main__":
    input_path = "input.csv"
    output_path = "filtered_output.csv"
    target_column = "score"
    threshold = 60

    try:
        count = filter_csv(input_path, output_path, target_column, threshold)
        print(f"Filtered CSV saved to {output_path}")
        print(f"Rows kept: {count}")
    except Exception as e:
        print(f"Error: {e}")