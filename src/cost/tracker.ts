import { readFileSync, appendFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import type { CostEntry, CostReport, CostAlert, BudgetConfig } from "./types.js";

// Pricing per million tokens: [input, output] in USD
const MODEL_PRICING: Record<string, [number, number]> = {
  // OpenAI
  "gpt-4o":               [2.50, 10.00],
  "gpt-4o-mini":          [0.15, 0.60],
  "gpt-4-turbo":          [10.00, 30.00],
  "gpt-4":                [30.00, 60.00],
  "gpt-3.5-turbo":        [0.50, 1.50],
  "o1":                   [15.00, 60.00],
  "o1-mini":              [3.00, 12.00],
  "o1-pro":               [150.00, 600.00],
  "o3":                   [10.00, 40.00],
  "o3-mini":              [1.10, 4.40],
  "o4-mini":              [1.10, 4.40],
  // Anthropic
  "claude-opus-4":        [15.00, 75.00],
  "claude-sonnet-4":      [3.00, 15.00],
  "claude-3.5-sonnet":    [3.00, 15.00],
  "claude-3.5-haiku":     [0.80, 4.00],
  "claude-3-opus":        [15.00, 75.00],
  "claude-3-sonnet":      [3.00, 15.00],
  "claude-3-haiku":       [0.25, 1.25],
  // Google
  "gemini-2.5-pro":       [1.25, 10.00],
  "gemini-2.5-flash":     [0.15, 0.60],
  "gemini-2.0-flash":     [0.10, 0.40],
  "gemini-1.5-pro":       [1.25, 5.00],
  "gemini-1.5-flash":     [0.075, 0.30],
};

function inferProvider(model: string): string {
  if (model.startsWith("gpt-") || model.startsWith("o1") || model.startsWith("o3") || model.startsWith("o4")) return "openai";
  if (model.startsWith("claude-")) return "anthropic";
  if (model.startsWith("gemini-")) return "google";
  return "unknown";
}

function computeCost(model: string, inputTokens: number, outputTokens: number): number {
  const pricing = MODEL_PRICING[model];
  if (!pricing) return 0;
  const [inputPerM, outputPerM] = pricing;
  return (inputTokens / 1_000_000) * inputPerM + (outputTokens / 1_000_000) * outputPerM;
}

function todayKey(): string {
  return new Date().toISOString().slice(0, 10);
}

function daysBetween(a: Date, b: Date): number {
  return Math.abs(a.getTime() - b.getTime()) / (24 * 60 * 60 * 1000);
}

export interface CostTracker {
  record(entry: Omit<CostEntry, "timestamp">): CostAlert[];
  getReport(days?: number): CostReport;
  getProjectedCost(): number;
  checkBudget(): CostAlert[];
}

export function createCostTracker(dataDir: string, budget?: BudgetConfig): CostTracker {
  const logFile = join(dataDir, "cost-log.jsonl");

  // Ensure data directory exists
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }

  function readEntries(): CostEntry[] {
    if (!existsSync(logFile)) return [];
    const content = readFileSync(logFile, "utf-8").trim();
    if (!content) return [];
    return content
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line) as CostEntry;
        } catch {
          return null;
        }
      })
      .filter((e): e is CostEntry => e !== null);
  }

  function appendEntry(entry: CostEntry): void {
    const dir = dirname(logFile);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    appendFileSync(logFile, JSON.stringify(entry) + "\n", "utf-8");
  }

  function filterByDays(entries: CostEntry[], days: number): CostEntry[] {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    const cutoffStr = cutoff.toISOString();
    return entries.filter((e) => e.timestamp >= cutoffStr);
  }

  function buildReport(entries: CostEntry[]): CostReport {
    const byProvider: Record<string, number> = {};
    const byModel: Record<string, number> = {};
    const byDay: Record<string, number> = {};
    let totalCost = 0;

    for (const e of entries) {
      totalCost += e.cost;
      byProvider[e.provider] = (byProvider[e.provider] ?? 0) + e.cost;
      byModel[e.model] = (byModel[e.model] ?? 0) + e.cost;
      const day = e.timestamp.slice(0, 10);
      byDay[day] = (byDay[day] ?? 0) + e.cost;
    }

    const totalRequests = entries.length;
    const averageCostPerRequest = totalRequests > 0 ? totalCost / totalRequests : 0;

    // Project monthly cost based on daily average
    const dayKeys = Object.keys(byDay);
    let projectedMonthlyCost = 0;
    if (dayKeys.length > 0) {
      const firstDay = new Date(dayKeys.sort()[0]);
      const spanDays = Math.max(1, daysBetween(new Date(), firstDay));
      const dailyAvg = totalCost / spanDays;
      projectedMonthlyCost = dailyAvg * 30;
    }

    const alerts = checkBudgetInternal(entries, totalCost, byDay);

    return {
      totalCost,
      byProvider,
      byModel,
      byDay,
      averageCostPerRequest,
      totalRequests,
      projectedMonthlyCost,
      alerts,
    };
  }

  function checkBudgetInternal(
    entries: CostEntry[],
    totalCost?: number,
    byDay?: Record<string, number>
  ): CostAlert[] {
    if (!budget) return [];

    const alerts: CostAlert[] = [];
    const all = entries;
    const today = todayKey();
    const threshold = budget.alertThreshold ?? 0.8;

    // Daily limit
    if (budget.dailyLimit !== undefined) {
      let todayCost = 0;
      if (byDay && byDay[today] !== undefined) {
        todayCost = byDay[today];
      } else {
        todayCost = all
          .filter((e) => e.timestamp.startsWith(today))
          .reduce((sum, e) => sum + e.cost, 0);
      }

      if (todayCost > budget.dailyLimit) {
        alerts.push({
          type: "budget_exceeded",
          message: `Daily budget exceeded: $${todayCost.toFixed(4)} / $${budget.dailyLimit.toFixed(2)}`,
          severity: "critical",
        });
      } else if (todayCost > budget.dailyLimit * threshold) {
        alerts.push({
          type: "budget_exceeded",
          message: `Approaching daily budget: $${todayCost.toFixed(4)} / $${budget.dailyLimit.toFixed(2)} (${Math.round((todayCost / budget.dailyLimit) * 100)}%)`,
          severity: "warning",
        });
      }
    }

    // Monthly limit
    if (budget.monthlyLimit !== undefined) {
      const monthPrefix = today.slice(0, 7);
      const monthCost = all
        .filter((e) => e.timestamp.startsWith(monthPrefix))
        .reduce((sum, e) => sum + e.cost, 0);

      if (monthCost > budget.monthlyLimit) {
        alerts.push({
          type: "budget_exceeded",
          message: `Monthly budget exceeded: $${monthCost.toFixed(4)} / $${budget.monthlyLimit.toFixed(2)}`,
          severity: "critical",
        });
      } else if (monthCost > budget.monthlyLimit * threshold) {
        alerts.push({
          type: "budget_exceeded",
          message: `Approaching monthly budget: $${monthCost.toFixed(4)} / $${budget.monthlyLimit.toFixed(2)} (${Math.round((monthCost / budget.monthlyLimit) * 100)}%)`,
          severity: "warning",
        });
      }
    }

    // Spike detection: if today's cost is 3x the average daily cost
    if (all.length > 0) {
      const dayMap: Record<string, number> = byDay ?? {};
      if (!byDay) {
        for (const e of all) {
          const d = e.timestamp.slice(0, 10);
          dayMap[d] = (dayMap[d] ?? 0) + e.cost;
        }
      }
      const dayValues = Object.entries(dayMap)
        .filter(([d]) => d !== today)
        .map(([, v]) => v);
      if (dayValues.length > 0) {
        const avgDaily = dayValues.reduce((a, b) => a + b, 0) / dayValues.length;
        const todayCost = dayMap[today] ?? 0;
        if (avgDaily > 0 && todayCost > avgDaily * 3) {
          alerts.push({
            type: "spike_detected",
            message: `Cost spike detected: today's cost $${todayCost.toFixed(4)} is ${(todayCost / avgDaily).toFixed(1)}x the daily average of $${avgDaily.toFixed(4)}`,
            severity: "warning",
          });
        }
      }
    }

    return alerts;
  }

  return {
    record(entry: Omit<CostEntry, "timestamp">): CostAlert[] {
      // Infer provider from model name if not provided
      const provider = entry.provider || inferProvider(entry.model);

      // Auto-compute cost if not provided or zero, and model is known
      let cost = entry.cost;
      if (cost === 0 && MODEL_PRICING[entry.model]) {
        cost = computeCost(entry.model, entry.inputTokens, entry.outputTokens);
      }

      const fullEntry: CostEntry = {
        ...entry,
        provider,
        cost,
        timestamp: new Date().toISOString(),
      };

      // Per-request limit check
      const alerts: CostAlert[] = [];
      if (budget?.perRequestLimit !== undefined && cost > budget.perRequestLimit) {
        alerts.push({
          type: "budget_exceeded",
          message: `Single request cost $${cost.toFixed(4)} exceeds per-request limit of $${budget.perRequestLimit.toFixed(4)}`,
          severity: "critical",
        });
      }

      appendEntry(fullEntry);

      // Check overall budget after recording
      const entries = readEntries();
      alerts.push(...checkBudgetInternal(entries));

      return alerts;
    },

    getReport(days = 30): CostReport {
      const entries = filterByDays(readEntries(), days);
      return buildReport(entries);
    },

    getProjectedCost(): number {
      const entries = readEntries();
      if (entries.length === 0) return 0;

      const sorted = entries.map((e) => e.timestamp).sort();
      const first = new Date(sorted[0]);
      const spanDays = Math.max(1, daysBetween(new Date(), first));
      const totalCost = entries.reduce((sum, e) => sum + e.cost, 0);
      return (totalCost / spanDays) * 30;
    },

    checkBudget(): CostAlert[] {
      return checkBudgetInternal(readEntries());
    },
  };
}
