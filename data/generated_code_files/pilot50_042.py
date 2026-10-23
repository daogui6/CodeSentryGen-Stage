import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from scipy import stats


def create_time_series() -> pd.DataFrame:
    dates = pd.date_range(start="2024-01-01", periods=30, freq="D")
    values = np.random.normal(loc=100, scale=15, size=len(dates))

    return pd.DataFrame({
        "date": dates,
        "value": values,
    })


def analyze_data(data: pd.DataFrame) -> dict[str, float]:
    values = data["value"]

    return {
        "mean": float(values.mean()),
        "median": float(values.median()),
        "std": float(values.std()),
        "skewness": float(stats.skew(values)),
    }


def add_rolling_features(data: pd.DataFrame) -> pd.DataFrame:
    result = data.copy()
    result["rolling_mean_7"] = result["value"].rolling(window=7, min_periods=1).mean()
    result["rolling_std_7"] = result["value"].rolling(window=7, min_periods=1).std()
    return result


def plot_time_series(data: pd.DataFrame) -> None:
    plt.figure(figsize=(10, 5))
    plt.plot(data["date"], data["value"], label="value")
    plt.plot(data["date"], data["rolling_mean_7"], label="7-day rolling mean")
    plt.xlabel("Date")
    plt.ylabel("Value")
    plt.title("Time Series Data")
    plt.legend()
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    df = create_time_series()
    df = add_rolling_features(df)

    summary = analyze_data(df)
    print(summary)

    plot_time_series(df)
