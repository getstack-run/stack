import { z } from 'zod';
import { defineIntent } from './types.js';

// BambooHR REST API v1 — https://documentation.bamboohr.com/reference.
// Base: api.bamboohr.com/api/gateway.php/{subdomain}/v1/…. Every path is
// tenant-scoped by {subdomain}, which these intents accept as an optional
// `subdomain` param for tight binding.

const SCOPED = (subdomain: string | undefined, rest: string): string => {
  const seg = subdomain ? subdomain.replace(/[-.]/g, (c) => `\\${c}`) : '[^/]+';
  return `^/api/gateway\\.php/${seg}/v1${rest}$`;
};

export const bamboohrIntents = [
  defineIntent({
    name: 'bamboohr.list_employees',
    effect: 'read',
    description:
      'List all employees in a BambooHR directory. Binds GET /api/gateway.php/{subdomain}/v1/employees/directory.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/employees/directory') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.read_employee',
    effect: 'read',
    description:
      'Retrieve a single BambooHR employee by ID. Binds GET /api/gateway.php/{subdomain}/v1/employees/{employeeId}.',
    params: z.object({
      subdomain: z.string().optional(),
      employee_id: z.string().regex(/^\d+$/).optional(),
    }),
    expand: (p) => {
      const id = p.employee_id ? p.employee_id : '\\d+';
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, `/employees/${id}`) },
      ];
    },
  }),

  defineIntent({
    name: 'bamboohr.create_employee',
    effect: 'write',
    description:
      'Create a new BambooHR employee. Binds POST /api/gateway.php/{subdomain}/v1/employees/.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/employees/') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.update_employee',
    effect: 'write',
    description:
      'Update fields on a BambooHR employee record. Binds POST /api/gateway.php/{subdomain}/v1/employees/{employeeId}.',
    params: z.object({
      subdomain: z.string().optional(),
      employee_id: z.string().regex(/^\d+$/).optional(),
    }),
    expand: (p) => {
      const id = p.employee_id ? p.employee_id : '\\d+';
      return [
        { path: 'method', op: 'eq', value: 'POST' },
        { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, `/employees/${id}`) },
      ];
    },
  }),

  defineIntent({
    name: 'bamboohr.list_time_off_requests',
    effect: 'read',
    description:
      'List BambooHR time-off requests with optional filters. Binds GET /api/gateway.php/{subdomain}/v1/time_off/requests/.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/time_off/requests/') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.update_time_off_request_status',
    effect: 'write',
    description:
      'Approve, deny, or cancel a BambooHR time-off request. Binds PUT /api/gateway.php/{subdomain}/v1/time_off/requests/{requestId}/status.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/time_off/requests/\\d+/status') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.add_time_off_request',
    effect: 'write',
    description:
      'Create a new BambooHR time-off request on behalf of an employee. Binds PUT /api/gateway.php/{subdomain}/v1/employees/{employeeId}/time_off/request.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/employees/\\d+/time_off/request') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_timesheets',
    effect: 'read',
    description:
      'List BambooHR timesheet entries for an employee over a date range. Binds GET /api/gateway.php/{subdomain}/v1/time_tracking/timesheet_entries.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/time_tracking/timesheet_entries') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.store_timesheet_entries',
    effect: 'write',
    description:
      'Create or update BambooHR timesheet hour entries in bulk. Binds POST /api/gateway.php/{subdomain}/v1/time_tracking/hour_entries/store.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/time_tracking/hour_entries/store') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_standard_reports',
    effect: 'read',
    description:
      'List BambooHR standard reports. Binds GET /api/gateway.php/{subdomain}/v1/reports.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/reports') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.get_report',
    effect: 'read',
    description:
      'Retrieve a single BambooHR standard report by numeric ID. Binds GET /api/gateway.php/{subdomain}/v1/reports/{reportId}.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/reports/\\d+') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.run_custom_report',
    effect: 'write',
    description:
      'Request a BambooHR custom (ad-hoc) report with arbitrary fields. Binds POST /api/gateway.php/{subdomain}/v1/reports/custom.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/reports/custom') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_fields_meta',
    effect: 'read',
    description:
      'List all BambooHR field definitions and their metadata. Binds GET /api/gateway.php/{subdomain}/v1/meta/fields/.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/meta/fields/') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_tables_meta',
    effect: 'read',
    description:
      'List BambooHR employee-table definitions (education, job info, etc). Binds GET /api/gateway.php/{subdomain}/v1/meta/tables/.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/meta/tables/') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_users',
    effect: 'read',
    description:
      'List BambooHR users (people with application access). Binds GET /api/gateway.php/{subdomain}/v1/meta/users/.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/meta/users/') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_benefit_plans',
    effect: 'read',
    description:
      'List BambooHR benefit plans. Binds GET /api/gateway.php/{subdomain}/v1/benefits/plans.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/benefits/plans') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_training_records',
    effect: 'read',
    description:
      'List BambooHR training records for an employee. Binds GET /api/gateway.php/{subdomain}/v1/training/record/employee/{employeeId}.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/training/record/employee/\\d+') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.add_training_record',
    effect: 'write',
    description:
      'Add a BambooHR training record for an employee. Binds POST /api/gateway.php/{subdomain}/v1/training/record.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/training/record') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.list_employee_files',
    effect: 'read',
    description:
      'List files attached to a BambooHR employee record. Binds GET /api/gateway.php/{subdomain}/v1/employees/{employeeId}/files/view/.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/employees/\\d+/files/view/') },
    ],
  }),

  defineIntent({
    name: 'bamboohr.upload_employee_file',
    effect: 'write',
    description:
      'Upload a new file to a BambooHR employee record. Binds POST /api/gateway.php/{subdomain}/v1/employees/{employeeId}/files/.',
    params: z.object({ subdomain: z.string().optional() }),
    expand: (p) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: SCOPED(p.subdomain, '/employees/\\d+/files/') },
    ],
  }),
];
