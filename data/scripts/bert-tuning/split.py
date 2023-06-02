from sklearn.model_selection import train_test_split
import pandas as pd
import os
from typing import List

# Directory containing your files
intents_directory = "data/source/intents/basic"


def shuffle_split_save(examples_file_paths: List[str]):
    train_data = pd.DataFrame()
    test_data = pd.DataFrame()

    for file_path in examples_file_paths:
        # Load your data from the file
        with open(file_path, "r") as file:
            data = file.readlines()

        # Convert list to DataFrame
        df = pd.DataFrame(data, columns=['sentences'])

        # Use the file name (without extension) as the label
        label = os.path.splitext(os.path.basename(file_path))[0]
        df['labels'] = label

        # Shuffle your data
        df = df.sample(frac=1).reset_index(drop=True)

        # Split your data into train and test
        train_df, test_df = train_test_split(df, test_size=0.30, random_state=42)

        # Concatenate the splits to previous data
        train_data = pd.concat([train_data, train_df])
        test_data = pd.concat([test_data, test_df])

    # Shuffle the final datasets
    train_data = train_data.sample(frac=1).reset_index(drop=True)
    test_data = test_data.sample(frac=1).reset_index(drop=True)

    # Save your splits to separate files
    train_data.to_csv("data/processed/tuning/splits/train_data.csv", index=False)
    test_data.to_csv("data/processed/tuning/splits/test_data.csv", index=False)


# List comprehension to generate full paths to the files
example_files = [os.path.join(intents_directory, f) for f in os.listdir(intents_directory)
                 if os.path.isfile(os.path.join(intents_directory, f))]

shuffle_split_save(example_files)
