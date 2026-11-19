import { z } from 'zod';
import { defineIntent } from './types.js';

// Gusto API — https://docs.gusto.com/embedded-payroll/reference. Base:
// api.gusto.com/v1/…. Most resources scope under /companies/{company_uuid}/
// so these intents accept an optional `company_uuid` param for tight
// binding; omitting it allows any company the token is authorized against.

const COMPANY_SCOPED = (
  company: string | undefined,
  rest: string,
): string => {
  const seg = company ? company.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
  return `^/v1/companies/${seg}${rest}$`;
};

export const gustoIntents = [
  defineIntent({
    name: 'gusto.list_employees',
    effect: 'read',
    description:
      'List all employees for a Gusto company. Binds GET /v1/companies/{company_uuid}/employees.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/employees') },
    ],
  }),

  defineIntent({
    name: 'gusto.read_employee',
    effect: 'read',
    description:
      'Retrieve a single Gusto employee by UUID. Binds GET /v1/employees/{employee_uuid}.',
    params: z.object({ employee_uuid: z.string().optional() }),
    expand: (p) => {
      const seg = p.employee_uuid ? p.employee_uuid.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/employees/${seg}$` },
      ];
    },
  }),

  defineIntent({
    name: 'gusto.create_employee',
    effect: 'write',
    description:
      'Create a new Gusto employee on a company. Binds POST /v1/companies/{company_uuid}/employees.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/employees') },
    ],
  }),

  defineIntent({
    name: 'gusto.update_employee',
    effect: 'write',
    description:
      'Update core fields on a Gusto employee record. Binds PUT /v1/employees/{employee_uuid}.',
    params: z.object({ employee_uuid: z.string().optional() }),
    expand: (p) => {
      const seg = p.employee_uuid ? p.employee_uuid.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/employees/${seg}$` },
      ];
    },
  }),

  defineIntent({
    name: 'gusto.terminate_employee',
    effect: 'destructive',
    description:
      'Terminate a Gusto employee as of a given date. Binds POST /v1/employees/{employee_uuid}/terminations.',
    params: z.object({ employee_uuid: z.string().optional() }),
    expand: (p) => {
      const seg = p.employee_uuid ? p.employee_uuid.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/employees/${seg}/terminations$` },
      ];
    },
  }),

  defineIntent({
    name: 'gusto.list_contractors',
    effect: 'read',
    description:
      'List contractors for a Gusto company. Binds GET /v1/companies/{company_uuid}/contractors.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/contractors') },
    ],
  }),

  defineIntent({
    name: 'gusto.create_contractor',
    effect: 'write',
    description:
      'Create a new Gusto contractor on a company. Binds POST /v1/companies/{company_uuid}/contractors.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/contractors') },
    ],
  }),

  defineIntent({
    name: 'gusto.update_contractor',
    effect: 'write',
    description:
      'Update an existing Gusto contractor. Binds PUT /v1/contractors/{contractor_uuid}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/contractors/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'gusto.list_payrolls',
    effect: 'read',
    description:
      'List payrolls for a Gusto company. Binds GET /v1/companies/{company_uuid}/payrolls.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/payrolls') },
    ],
  }),

  defineIntent({
    name: 'gusto.update_payroll',
    effect: 'write',
    description:
      'Edit a Gusto payroll before submission (enter hours, compensations). Binds PUT /v1/companies/{company_uuid}/payrolls/{payroll_uuid}.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/payrolls/[^/]+') },
    ],
  }),

  defineIntent({
    name: 'gusto.submit_payroll',
    effect: 'write',
    description:
      'Submit a calculated Gusto payroll for processing. Binds PUT /v1/companies/{company_uuid}/payrolls/{payroll_uuid}/submit.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/payrolls/[^/]+/submit') },
    ],
  }),

  defineIntent({
    name: 'gusto.list_pay_schedules',
    effect: 'read',
    description:
      'List pay schedules for a Gusto company. Binds GET /v1/companies/{company_uuid}/pay_schedules.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/pay_schedules(/[^/]+)?') },
    ],
  }),

  defineIntent({
    name: 'gusto.create_compensation',
    effect: 'write',
    description:
      'Create a compensation record on an employee job. Binds POST /v1/jobs/{job_uuid}/compensations.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v1/jobs/[^/]+/compensations$' },
    ],
  }),

  defineIntent({
    name: 'gusto.list_departments',
    effect: 'read',
    description:
      'List departments for a Gusto company. Binds GET /v1/companies/{company_uuid}/departments.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/departments(/[^/]+)?') },
    ],
  }),

  defineIntent({
    name: 'gusto.list_locations',
    effect: 'read',
    description:
      'List work locations for a Gusto company. Binds GET /v1/companies/{company_uuid}/locations.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/locations(/[^/]+)?') },
    ],
  }),

  defineIntent({
    name: 'gusto.create_garnishment',
    effect: 'write',
    description:
      'Create a wage garnishment on an employee. Binds POST /v1/employees/{employee_uuid}/garnishments.',
    params: z.object({ employee_uuid: z.string().optional() }),
    expand: (p) => {
      const seg = p.employee_uuid ? p.employee_uuid.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/employees/${seg}/garnishments$` },
      ];
    },
  }),

  defineIntent({
    name: 'gusto.list_employee_benefits',
    effect: 'read',
    description:
      'List benefits enrolled for a Gusto employee. Binds GET /v1/employees/{employee_uuid}/employee_benefits.',
    params: z.object({ employee_uuid: z.string().optional() }),
    expand: (p) => {
      const seg = p.employee_uuid ? p.employee_uuid.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/employees/${seg}/employee_benefits$` },
      ];
    },
  }),

  defineIntent({
    name: 'gusto.read_company',
    effect: 'read',
    description:
      'Read top-level Gusto company metadata. Binds GET /v1/companies/{company_uuid}.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => {
      const seg = p.company_uuid ? p.company_uuid.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/companies/${seg}$` },
      ];
    },
  }),

  defineIntent({
    name: 'gusto.list_time_off_policies',
    effect: 'read',
    description:
      'List time-off policies for a Gusto company. Binds GET /v1/companies/{company_uuid}/time_off_policies.',
    params: z.object({ company_uuid: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: COMPANY_SCOPED(p.company_uuid, '/time_off_policies(/[^/]+)?') },
    ],
  }),

  defineIntent({
    name: 'gusto.list_jobs',
    effect: 'read',
    description:
      'List jobs for a Gusto employee. Binds GET /v1/employees/{employee_uuid}/jobs.',
    params: z.object({ employee_uuid: z.string().optional() }),
    expand: (p) => {
      const seg = p.employee_uuid ? p.employee_uuid.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: `^/v1/employees/${seg}/jobs$` },
      ];
    },
  }),
];
