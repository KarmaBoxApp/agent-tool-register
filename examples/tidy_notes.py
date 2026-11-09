"""Example: a personal script. Reads my own notes, writes a cleaned copy. No triggers expected."""
import csv

with open("my_notes.csv", newline="") as src, open("my_notes_clean.csv", "w", newline="") as dst:
    writer = csv.writer(dst)
    for row in csv.reader(src):
        writer.writerow([cell.strip() for cell in row])
