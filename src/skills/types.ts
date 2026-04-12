export type ExtractedSkill = {
  id: string;
  name: string;
  description: string;
  trigger: string;
  steps: string[];
  toolsUsed: string[];
  filesInvolved: string[];
  sourceSession: string;
  extractedAt: string;
  confidence: number;
};

export type SkillLibrary = {
  skills: ExtractedSkill[];
  version: number;
  updatedAt: string;
};
