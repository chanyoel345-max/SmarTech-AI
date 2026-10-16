
import pandas as pd
from pathlib import Path

# Load security logs
BASE_DIR = Path(__file__).resolve().parent.parent
file_path = BASE_DIR / "data" / "security_logs.csv"
output_path = BASE_DIR / "data" / "analysis_results.csv"

df = pd.read_csv(file_path)

# Analyze failed login attempts
def assess_risk(attempts):
    if attempts >= 10:
        return "High"
    elif attempts >= 5:
        return "Medium"
    return "Low"

df["risk_level"] = df["failed_attempts"].apply(assess_risk)

# Summary
print("=== NexusAI Security Analytics ===")
print(f"Total events: {len(df)}")
print(f"Failed login events: {(df['event'] == 'login_failed').sum()}")

print("\n=== Risk Assessment ===")
print(
    df[["username", "ip_address", "failed_attempts", "risk_level"]]
    .to_string(index=False)
)

# Save results for the dashboard
df.to_csv(output_path, index=False, encoding="utf-8-sig")
print(f"\nResults saved to: {output_path}")
print("Analysis completed successfully.")
