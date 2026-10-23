import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats


class TimeSeriesAnalyzer:
    def __init__(self, data=None, index=None):
        if data is None:
            data = pd.DataFrame()
        self.df = pd.DataFrame(data, index=index)
        if not isinstance(self.df.index, pd.DatetimeIndex):
            try:
                self.df.index = pd.to_datetime(self.df.index)
            except Exception:
                pass

    def add_series(self, name, values):
        self.df[name] = values

    def get_statistics(self):
        return self.df.describe()

    def calculate_rolling_mean(self, window=5):
        return self.df.rolling(window=window).mean()

    def plot_series(self, column_name):
        plt.figure(figsize=(10, 5))
        plt.plot(self.df.index, self.df[column_name], label=column_name)
        plt.title(f"{column_name} Time Series")
        plt.xlabel("Time")
        plt.ylabel("Value")
        plt.legend()
        plt.show()

    def normality_test(self, column_name):
        stat, p = stats.shapiro(self.df[column_name].dropna())
        return stat, p
