
export type Summary = {
total_events: number;
failed_login_events: number;
high_risk_events: number;
medium_risk_events: number;
low_risk_events: number;
};

export type SecurityAlert = {
username: string;
ip_address: string;
failed_attempts: number;
risk_level: string;
event?: string;
timestamp?: string;
recommendation?: string;
};

export type PageId =
| "overview"
| "analysis"
| "alerts"
| "recommendations"
| "logs"
| "status";
