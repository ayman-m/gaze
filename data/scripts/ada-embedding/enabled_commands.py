import pandas as pd

# Read the CSV file containing the commands
commands_file = 'data/source/commands/enabled_commands.csv'
df = pd.read_csv(commands_file)

# Get the command names from the 'name' column
command_names = df['name'].tolist()

# Read the CSV file containing the command embeddings
embeddings_file = 'data/processed/embedding/commands/ada-all-command-embedding.csv'
df = pd.read_csv(embeddings_file)

# Filter the DataFrame to keep only the rows with command names in the list
filtered_df = df[df['name'].isin(command_names)]

# Save the filtered DataFrame to a new CSV file
output_file = 'data/processed/embedding/commands/ada-enabled-command-embedding.csv'
filtered_df.to_csv(output_file, index=False)

print(f"Wrote {len(filtered_df)} rows to {output_file}.")
