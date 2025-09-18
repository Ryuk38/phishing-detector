# merge_files.py (Updated Version)
import pandas as pd

print("Loading your two datasets...")

try:
    # Load legitimate data, using the 'domain' column
    legit_df = pd.read_csv('data/legitimate_urls.csv')
    # Rename the 'domain' column to 'url' for consistency
    legit_df.rename(columns={'domain': 'url'}, inplace=True)
    legit_df['label'] = 0

    # Load phishing data, using both 'url' and 'label' columns
    phish_df = pd.read_csv('data/phishing_urls.csv')
    # Ensure the label is an integer
    phish_df['label'] = 1

except FileNotFoundError as e:
    print(f"Error: {e}")
    print("Please make sure both 'legitimate_urls.csv' and 'phishing_urls.csv' are in the 'data/' folder.")
    exit()


print("Combining files into a single dataset...")
# Keep only the 'url' and 'label' columns from both
combined_df = pd.concat([
    phish_df[['url', 'label']], 
    legit_df[['url', 'label']]
], ignore_index=True)

# Shuffle the dataset randomly
combined_df = combined_df.sample(frac=1).reset_index(drop=True)

# Save to the new single file
output_path = 'data/large_dataset.csv'
combined_df.to_csv(output_path, index=False)

print(f"\nSuccess! Your two datasets have been combined and saved to '{output_path}'.")
print(f"Total links in the new dataset: {len(combined_df)}")