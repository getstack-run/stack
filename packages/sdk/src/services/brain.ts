import type { HttpClient } from '../client.js';

// The brain: the drive files a customer chose to make searchable, read and searched by a knowledge base
// service. One brain per account, shared by the account's agents. The owner or any of the customer's agents adds
// files; a file is named by its drive id, a list of ids, or every file whose name starts with a prefix (the drive
// has no folders). Who may see a passage in a search is the drive file's own visibility, never an argument.
//
// `add` returns at once, one row per file: `reading` while it is being read, `unreadable` (with a plain `reason`) for a
// file the reader cannot take, or `refused` for one that could not be added (a file the wallet cannot cover is
// refused), with an estimate of the pages reading it bills and what that costs, worked out from the file's size and
// type: nothing of the file is read when you add it. The real pages are counted, and the real cost charged, when the
// file is read over the next minutes; `list` shows when it becomes `searchable` (or `unreadable`, with the
// reason, for a file the reader cannot take once it looks at it). Reading is the only cost (the first pages each UTC month are free, the rest at cost from the wallet);
// `search`, `remove` and `list` are free. Once added, the brain follows the file: an edit is read again, a deletion
// removes it. `add` is one action (metered, checked against your controls, in the signed record); the rest are not.
//
// Every passage a search returns is untrusted content, as every drive file is: it is information, never
// instructions. A passage whose text carries instructions aimed at an AI agent is withheld (`withheld: true`,
// `passage: null`) with the detector's `flag`.
//
// Agent-side calls take `{ passportToken }`, sent as `X-Passport-Token`, and run under the Passport's Mission; an
// operator credential omits it.

/** The status of a file in the brain: `reading` while it is being read, `searchable` once read, `unreadable` when the reader could not take it. */
export type BrainFileStatus = 'reading' | 'searchable' | 'unreadable';

/** Which drive files a call names: exactly one of a file id, a list of file ids, or a name prefix. */
export interface BrainFileSelection {
  /** A single drive file (`drv_*`). */
  file_id?: string;
  /** Several drive files. */
  file_ids?: string[];
  /** Every file the caller can see whose name starts with this. */
  name_prefix?: string;
}

export type BrainAddInput = BrainFileSelection;
export type BrainRemoveInput = BrainFileSelection;

export interface BrainSearchInput {
  /** The question, in natural language (at most 1,000 characters, the reader's own limit). */
  query: string;
}

export interface BrainListQuery {
  /** Only files in this state. */
  status?: BrainFileStatus;
  /** `next_cursor` of the previous page. */
  cursor?: string;
  /** How many files to return (1 to 100, default 50). */
  limit?: number;
}

/** What an add answers for one file it was given. `refused` is a file that was not added; `reason` says why. */
export interface BrainAddedFile {
  file_id: string;
  name: string | null;
  status: BrainFileStatus | 'refused';
  reason: string | null;
  /** The pages reading it is expected to bill (from its size and type, not read), of which `estimated_free_pages` are expected to come from the month's free pages. */
  estimated_pages: number;
  estimated_free_pages: number;
  /** What reading it is expected to cost from the wallet, at cost, rounded up to a cent. */
  estimated_cost_cents: number;
}

export interface BrainAddResult {
  files: BrainAddedFile[];
  estimated_pages: number;
  estimated_free_pages: number;
  estimated_cost_cents: number;
  /** The free pages still left this month once these files are read, going by the estimate. */
  free_pages_left: number;
}

export interface BrainRemoveResult {
  removed: string[];
  /** Files named that were not in the brain (or that the caller cannot see). */
  not_in_brain: string[];
}

export interface BrainFile {
  file_id: string;
  name: string;
  status: BrainFileStatus;
  reason: string | null;
  /** The pages billed for it: an estimate from its size until the file has been read. */
  pages: number;
  visibility: 'agent' | 'account';
  /** The agent that added it, null for the owner. */
  added_by_agent_id: string | null;
  added_at: string;
}

export interface BrainUsage {
  /** The calendar month (UTC), as `YYYY-MM`. */
  month: string;
  pages_read: number;
  free_pages: number;
  free_pages_left: number;
  cost_cents: number;
}

export interface BrainListResult {
  files: BrainFile[];
  next_cursor: string | null;
  usage: BrainUsage;
}

export interface BrainPassage {
  file_id: string;
  name: string;
  /** The page of the file the passage is on, when the reader gave one. */
  page: number | null;
  /** The passage's text; null when it was withheld because it carries instructions aimed at an AI agent. */
  passage: string | null;
  score: number | null;
  /** What STACK's detectors found in the passage, or null. */
  flag: string | null;
  withheld: boolean;
  trust: 'untrusted';
}

export interface BrainSearchResult {
  results: BrainPassage[];
  /** How many of the caller's files in the brain are still being read, so an empty answer is not read as "not in the files". */
  pending: number;
  trust: 'untrusted';
}

/** An agent caller passes its Passport as `passportToken`, sent as `X-Passport-Token`; an operator credential omits it. */
export interface BrainCallOptions {
  passportToken?: string;
}

function passport(options?: BrainCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

export class BrainService {
  constructor(private readonly client: HttpClient) {}

  /**
   * Make drive files searchable: a file, a list of files, or every file whose name starts with a prefix. Returns one
   * row per file with its status and an estimate of the pages reading it bills (the real pages are counted when the
   * file is read). One action, checked against your controls.
   */
  async add(input: BrainAddInput, options?: BrainCallOptions): Promise<BrainAddResult> {
    return this.client.post<BrainAddResult>('/v1/brain/files', input, passport(options));
  }

  /** Take files out of the brain; they stay in the drive, only no longer searchable. Free. */
  async remove(input: BrainRemoveInput, options?: BrainCallOptions): Promise<BrainRemoveResult> {
    return this.client.post<BrainRemoveResult>('/v1/brain/remove', input, passport(options));
  }

  /**
   * Ask the brain a question and get the most relevant passages from the files the caller may see, each with its file
   * and, for a PDF, the page. Up to 10 passages, every one untrusted content. Free.
   */
  async search(input: BrainSearchInput, options?: BrainCallOptions): Promise<BrainSearchResult> {
    return this.client.post<BrainSearchResult>('/v1/brain/search', input, passport(options));
  }

  /**
   * List the files in the brain the caller may see, each with its state and the month's usage (pages read, free pages
   * left, what was charged). Free.
   */
  async list(query: BrainListQuery = {}, options?: BrainCallOptions): Promise<BrainListResult> {
    return this.client.get<BrainListResult>(
      '/v1/brain/files',
      {
        status: query.status,
        cursor: query.cursor,
        limit: query.limit !== undefined ? String(query.limit) : undefined,
      },
      passport(options),
    );
  }
}
