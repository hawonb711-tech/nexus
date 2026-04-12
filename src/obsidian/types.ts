export type ObsidianConfig = {
  vaultPath: string;
  folderStructure: "by-date" | "by-project" | "flat";
  includeToolCalls: boolean;
  includeTimestamps: boolean;
  createMOC: boolean;
  createDailyNotes: boolean;
  tagPrefix: string;
};

export type ExportResult = {
  filesCreated: string[];
  filesUpdated: string[];
  mocUpdated: boolean;
  dailyNoteUpdated: boolean;
};
