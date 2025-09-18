<h1 align="center">🛡️ Intelligent Phishing Detector</h1>
<h3 align="center">A Multi-Layered AI Phishing Detection System with Live Analysis</h3>

<p align="center">
<em>An advanced, real-time phishing URL detector powered by a multi-layered AI model and a dynamic Streamlit user interface. This project goes beyond simple lexical analysis to perform live background checks on domains (WHOIS) and security certificates (SSL) to make highly accurate, context-aware predictions.</em>
</p>

<div align="center">

(Note: You can replace the link above with a real screenshot of your app once it's running.)

</div>

✨ Key Features
Multi-Layered Analysis: Combines three layers of evidence for maximum accuracy:

Lexical Analysis: Instant checks for suspicious keywords, URL length, and structure.

Domain Analysis: Live WHOIS lookups to verify domain age and registration history.

SSL Analysis: Live SSL certificate checks to validate the issuer and security setup.

Intelligent AI Model: A LightGBM classifier trained on thousands of enriched data points to recognize complex phishing patterns.

Post-Prediction Safety Net: An expert-rules engine that adjusts the AI's prediction to reduce false positives on trusted, well-established domains (e.g., .edu, .gov, google.com).

Hybrid Data Strategy: Uses a pre-computed knowledge base (enriched_dataset.csv) for speed and performs live lookups for new, unseen URLs.

Modern & User-Friendly UI: A clean, professional interface built with Streamlit that presents the complex analysis in a simple, scannable "Security Report Card."

⚙️ How It Works
The application follows a sophisticated workflow to analyze URLs in real time:

🔍 Initial Scan: The URL's text is instantly checked for lexical red flags.

🧠 Knowledge Base Check: The app checks if the URL's domain exists in its pre-computed cache of 5,000 enriched URLs. If so, it uses that data for a fast analysis.

📡 Live Investigation: If the domain is new, the app performs live WHOIS and SSL lookups to gather fresh intelligence.

🤖 AI Prediction: The combined lexical and enrichment features are fed into the trained AI model to get a raw phishing probability score.

🛡️ Safety Net Review: The model's score is passed through a safety layer that checks for whitelisted domains and other strong trust signals to prevent false positives.

📊 Final Report: The final, adjusted score is presented to the user in a clear, visual report card with a definitive verdict.

🛠️ Tech Stack
Backend & ML: Python, Pandas, Scikit-learn, LightGBM

Frontend: Streamlit

Data Enrichment: python-whois, pyopenssl, tldextract

Visualization: Plotly

📁 Project Structure
phishing-detector/
│
├── data/
│   ├── phishing_urls.csv       # Raw phishing data from PhishTank
│   ├── legitimate_urls.csv     # Raw legitimate data from Tranco
│   ├── large_dataset.csv       # Combined raw data
│   └── enriched_dataset.csv    # Final dataset used for training
│
├── models/                     # Stores the trained model artifacts
│   ├── model.joblib
│   ├── scaler.joblib
│   ├── tfidf.joblib
│   └── all_feature_cols.joblib
│
├── merge_files.py              # Script to combine raw datasets
├── enrich_data.py              # Script to perform slow, one-time data enrichment
├── train_model.py              # Fast script to train the model on enriched data
└── app.py                      # The main Streamlit application

🚀 Setup and Installation
Follow these steps to get the project running locally.

1. Prerequisites
Python 3.9+

pip and venv

2. Installation
Clone the repository and set up the virtual environment:

# Clone the repo
git clone <your-repo-url>
cd phishing-detector

# Create and activate a virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# Install all required packages
pip install streamlit pandas scikit-learn lightgbm joblib tqdm python-whois pyopenssl tldextract plotly

3. Data Acquisition
You need to download the raw datasets and place them in the data/ folder:

Phishing URLs: Download verified_online.csv from PhishTank and rename it to phishing_urls.csv.

Legitimate URLs: Download the top 1 million list from Tranco and rename it to legitimate_urls.csv.

4. Running the Full Workflow
Run the scripts from your terminal in the following order:

Step 1: Merge the raw datasets (fast)

python merge_files.py

Step 2: Create the enriched dataset (slow - run once)
This script takes a 5,000-URL sample from your merged data and performs the slow network lookups. This will take several minutes.

python enrich_data.py

Step 3: Train the model (very fast)
This uses the file from the previous step to train the AI model.

python train_model.py

Step 4: Launch the application

streamlit run app.py

💡 Future Improvements
Asynchronous Lookups: Convert the live WHOIS/SSL lookups to be asynchronous to prevent the UI from freezing on slow requests.

Expanded Whitelist: Integrate a larger, more comprehensive list of trusted domains and TLDs.

Scheduled Retraining: In a production environment, automate the enrich_data.py and train_model.py scripts to run periodically to keep the model up-to-date with new threats.
