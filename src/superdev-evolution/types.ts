export type Skill = {
  id: string;
  name: string;
  description: string;
  trigger: string;
  template: string;
  learnedFrom: string;
  successCount: number;
  failureCount: number;
  createdAt: string;
  updatedAt: string;
};

export type EvolutionLog = {
  skills: Skill[];
  totalInteractions: number;
  skillsCreated: number;
  skillsRetired: number;
  lastEvolvedAt: string;
};
