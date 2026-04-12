export type CostEntry = {
  timestamp: string;
  provider: string; // "openai" | "anthropic" | "google" | etc
  model: string;
  inputTokens: number;
  outputTokens: number;
  cost: number; // USD
  endpoint?: string;
  sessionId?: string;
};

export type CostReport = {
  totalCost: number;
  byProvider: Record<string, number>;
  byModel: Record<string, number>;
  byDay: Record<string, number>;
  averageCostPerRequest: number;
  totalRequests: number;
  projectedMonthlyCost: number;
  alerts: CostAlert[];
};

export type CostAlert = {
  type: "budget_exceeded" | "spike_detected" | "unusual_model" | "rate_limit_approaching";
  message: string;
  severity: "critical" | "warning" | "info";
};

export type BudgetConfig = {
  dailyLimit?: number;
  monthlyLimit?: number;
  perRequestLimit?: number;
  alertThreshold?: number; // 0-1, percentage of budget
};
