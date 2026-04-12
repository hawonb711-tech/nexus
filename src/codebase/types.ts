export type ImportInfo = {
  path: string;
  type: "import" | "require";
};

export type FileNode = {
  path: string;
  type: "file" | "directory";
  language?: string;
  size: number;
  imports: string[];
  /** Structured import info with type tracking. */
  importInfos?: ImportInfo[];
  exports: string[];
  functions: string[];
  classes: string[];
  lineCount: number;
};

export type DependencyEdge = {
  from: string;
  to: string;
  type: "import" | "require";
};

export type CodebaseMap = {
  root: string;
  files: FileNode[];
  dependencies: DependencyEdge[];
  languages: Record<string, number>;
  totalFiles: number;
  totalLines: number;
  entryPoints: string[];
  hotspots: string[];
  generatedAt: string;
};

export type MapOptions = {
  root: string;
  ignore?: string[];
  maxFiles?: number;
  maxDepth?: number;
};
