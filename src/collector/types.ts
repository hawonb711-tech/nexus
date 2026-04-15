export type FetchOptions = {
  maxBytes?: number;
  timeoutMs?: number;
  userAgent?: string;
  domain?: string;
  tags?: string[];
};

export type CollectorResult = {
  url: string;
  title: string;
  text: string;
  observationsAdded: number;
  rawBytes: number;
  textBytes: number;
  fetchedAt: string;
};

export type FeedItem = {
  title: string;
  link: string;
  description: string;
  pubDate?: string;
};

export type FeedResult = {
  feedUrl: string;
  feedTitle: string;
  items: FeedItem[];
  itemsIngested: number;
};
