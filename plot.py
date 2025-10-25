import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np # Needed for handling '<0.1%'

# Data extracted from the LaTeX table
data = {
    'Dataset': ['LLM', 'Jotai', 'Juliet'],
    'Build Attempts': [464, 18000, 1200],
    'Built OK': [394, 18000, 1198],
    'Crashes': [198, 1, 0],
    'Rate (vs Built) %': ['50.3%', '<0.1%', '0.0%']
}

df = pd.DataFrame(data)

# --- Data Cleaning ---
# Convert 'Rate (vs Built) %' to numeric, handling '<0.1%'
def parse_percentage(rate_str):
    if '<' in rate_str:
        # Represent '<0.1%' as a small positive value for plotting, e.g., 0.05
        # We use a value slightly less than 0.1 for visual distinction if needed
        return 0.05
    try:
        # Remove '%' and convert to float
        return float(rate_str.strip('%'))
    except ValueError:
        return np.nan # Return NaN for unparseable strings

df['Rate_Numeric'] = df['Rate (vs Built) %'].apply(parse_percentage)

# Drop rows if conversion failed (though unlikely with this specific data)
df.dropna(subset=['Rate_Numeric'], inplace=True)

# Sort by Rate for potentially better visual order (optional)
df_sorted = df.sort_values('Rate_Numeric', ascending=False)

# --- Plotting ---
plt.style.use('seaborn-v0_8-v0_8-colorblind') # Use a nice style
fig, ax = plt.subplots(figsize=(8, 6)) # Adjust figure size as needed

# Define colors
colors = ['#377eb8', '#ff7f00', '#4daf4a'] # Blue, Orange, Green

# Create bars
bars = ax.bar(df_sorted['Dataset'], df_sorted['Rate_Numeric'], color=colors, alpha=0.8)

# --- Formatting ---
ax.set_title('Sanitizer Crash Rate (Crashes / Successfully Built)', fontsize=14, fontweight='bold', pad=15)
ax.set_xlabel('Dataset', fontsize=12, labelpad=10)
ax.set_ylabel('Crash Rate (%)', fontsize=12, labelpad=10)

# Format Y-axis as percentage
ax.yaxis.set_major_formatter(mtick.PercentFormatter())
ax.set_ylim(bottom=0) # Ensure y-axis starts at 0

# Add grid lines
ax.grid(axis='y', linestyle='--', alpha=0.6)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_visible(False)
ax.tick_params(axis='both', which='major', labelsize=11)

# Add value labels on top of bars
for bar in bars:
    yval = bar.get_height()
    # Use original string representation for the label
    label_text = df_sorted.loc[df_sorted['Dataset'] == bar.get_x() + bar.get_width()/2, 'Rate (vs Built) %'].iloc[0]
    # Adjust position slightly based on value for clarity
    v_offset = 2 if yval > 1 else -1.5 # Place below bar if value is very small
    va_align = 'bottom' if yval > 1 else 'top'
    plt.text(bar.get_x() + bar.get_width()/2, yval + v_offset, label_text,
             ha='center', va=va_align, fontsize=10, color='black')

plt.tight_layout() # Adjust layout
plt.show()

# Optional: Save the figure
# plt.savefig("dataset_crash_rate_vs_built.png", dpi=300)

