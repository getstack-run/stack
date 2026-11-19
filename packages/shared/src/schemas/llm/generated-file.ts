import { z } from 'zod';

/**
 * A file a model or a tool made: saved to the agent's drive when the deployment
 * has one, otherwise returned as bytes (small) or the provider's link. What an
 * image call on the customer's own key returns, and what an account's tool run
 * returns, are the same shape.
 */
export const GeneratedFile = z.object({
  name: z.string(),
  content_type: z.string(),
  size_bytes: z.number().int().nullable(),
  /** The drive file it was saved to, private to the agent that made it. */
  drive_file_id: z.string().nullable(),
  /** Where the provider hosts it (provider links expire). */
  source_url: z.string().nullable(),
  /** The bytes, when the file is small and no drive took it. */
  data_base64: z.string().nullable(),
});
export type GeneratedFile = z.infer<typeof GeneratedFile>;
