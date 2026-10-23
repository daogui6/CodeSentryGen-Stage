import numpy as np
import matplotlib.pyplot as plt

# Generate sample data
x = np.linspace(0, 10, 100)
y = np.sin(x)

# Create the plot
plt.figure(figsize=(10, 6))
plt.plot(x, y, color='teal', linestyle='--', linewidth=2, marker='o', markersize=5, label='sin(x)')

# Customize appearance
plt.title('Sine Wave Plot', fontsize=16, fontweight='bold')
plt.xlabel('X-axis', fontsize=12)
plt.ylabel('Y-axis', fontsize=12)
plt.legend()
plt.grid(True, linestyle=':', alpha=0.7)
plt.xlim(0, 10)
plt.ylim(-1.5, 1.5)

# Show the plot
plt.tight_layout()
plt.show()
