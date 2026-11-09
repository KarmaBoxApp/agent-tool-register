"""Example: estimates how a book of positions moves under a rate shock. Uses pandas.
The scanner only hints at this one; the owner has to declare --quantitative."""
import pandas as pd

positions = pd.read_csv("positions_sample.csv")
positions["shocked_value"] = positions["value"] * (1 - positions["duration"] * 0.01)
print(positions["shocked_value"].sum())
