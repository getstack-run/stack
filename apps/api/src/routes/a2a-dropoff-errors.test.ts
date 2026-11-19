import { describe, expect, it } from 'vitest';
import {
  DropoffAlreadyCollectedError,
  DropoffExpiredError,
  ForbiddenError,
  NotFoundError,
  SchemaValidationError,
} from '@stack/shared';
import { mapStackErrorToRpc } from './a2a.js';

describe('A2A drop-off error boundary', () => {
  it.each([
    [new NotFoundError('Dropoff', 'dof_sensitive'), -32001, 'Task not found'],
    [new DropoffExpiredError('dof_sensitive'), -32002, 'Task cannot be changed'],
    [new DropoffAlreadyCollectedError('dof_sensitive'), -32002, 'Task cannot be changed'],
    [new ForbiddenError('mission ms_sensitive belongs elsewhere'), -32602, 'Invalid task request'],
    [new SchemaValidationError({ secret_path: '/private/value' }), -32602, 'Invalid task request'],
  ])('does not expose resource ids, internal codes or validation details', (error, code, message) => {
    const result = mapStackErrorToRpc(error);

    expect(result).toEqual({ code, message });
    expect(JSON.stringify(result)).not.toContain('sensitive');
    expect(result).not.toHaveProperty('data');
  });
});
