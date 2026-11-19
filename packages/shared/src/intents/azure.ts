import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Azure APIs — two shapes:
//   Data plane hosts vary per service:
//     Blob storage: {account}.blob.core.windows.net/{container}/{blob}
//     Key Vault:    {vault}.vault.azure.net/secrets/{name}
//     Cosmos DB:    {account}.documents.azure.com/dbs/{db}/colls/{col}
//   Control plane: management.azure.com/subscriptions/{subId}/resourceGroups/
//     {rg}/providers/{provider}/...
// Intents bind host + pathname so the agent can only touch the declared
// subscription / resource group / container / vault.

const subscriptionId = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, 'invalid subscription_id');
const subList = z.union([subscriptionId, z.array(subscriptionId).min(1)]);
type SubList = z.infer<typeof subList>;
const toSubList = (v: SubList): string[] => (Array.isArray(v) ? v : [v]);

function subPath(sub: SubList, suffixRegex: string): Constraint {
  const list = toSubList(sub);
  const alt = list.length === 1 ? list[0]! : `(${list.join('|')})`;
  return {
    path: 'url.pathname',
    op: 'matches',
    value: `^/subscriptions/${alt}${suffixRegex}$`,
  };
}

const containerName = z.string().min(3).max(63).regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/, 'invalid container name');
const containerList = z.union([containerName, z.array(containerName).min(1)]);
type ContainerList = z.infer<typeof containerList>;
const toContainerList = (v: ContainerList): string[] => (Array.isArray(v) ? v : [v]);

export const azureIntents = [
  defineIntent({
    name: 'azure.blob_get',
    effect: 'read',
    description:
      'Download a blob from Azure Blob Storage. Binds GET {account}.blob.core.windows.net/{container}/{blob} to the declared containers.',
    params: z.object({ container: containerList }),
    expand: ({ container }) => {
      const list = toContainerList(container);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'matches', value: '^[^/]+\\.blob\\.core\\.windows\\.net$' },
        { path: 'url.pathname', op: 'matches', value: `^/${alt}/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'azure.blob_put',
    effect: 'write',
    description:
      'Upload or overwrite a blob in Azure Blob Storage. Binds PUT {account}.blob.core.windows.net/{container}/{blob}.',
    params: z.object({ container: containerList }),
    expand: ({ container }) => {
      const list = toContainerList(container);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'PUT' },
        { path: 'url.host', op: 'matches', value: '^[^/]+\\.blob\\.core\\.windows\\.net$' },
        { path: 'url.pathname', op: 'matches', value: `^/${alt}/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'azure.blob_delete',
    effect: 'destructive',
    description:
      'Delete a blob from Azure Blob Storage. Binds DELETE {account}.blob.core.windows.net/{container}/{blob}. Destructive.',
    params: z.object({ container: containerList }),
    expand: ({ container }) => {
      const list = toContainerList(container);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'DELETE' },
        { path: 'url.host', op: 'matches', value: '^[^/]+\\.blob\\.core\\.windows\\.net$' },
        { path: 'url.pathname', op: 'matches', value: `^/${alt}/.+$` },
      ];
    },
  }),

  defineIntent({
    name: 'azure.blob_list',
    effect: 'read',
    description:
      'List blobs in an Azure container. Binds GET {account}.blob.core.windows.net/{container}?comp=list.',
    params: z.object({ container: containerList }),
    expand: ({ container }) => {
      const list = toContainerList(container);
      const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
      const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
      return [
        { path: 'method', op: 'eq', value: 'GET' },
        { path: 'url.host', op: 'matches', value: '^[^/]+\\.blob\\.core\\.windows\\.net$' },
        { path: 'url.pathname', op: 'matches', value: `^/${alt}/?$` },
      ];
    },
  }),

  defineIntent({
    name: 'azure.function_invoke',
    effect: 'write',
    description:
      'Invoke an Azure Function via its HTTPS trigger. Binds POST {app}.azurewebsites.net/api/{fn}.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      { path: 'url.host', op: 'matches', value: '^[^/]+\\.azurewebsites\\.net$' },
      { path: 'url.pathname', op: 'matches', value: '^/api/[^/]+.*$' },
    ],
  }),

  defineIntent({
    name: 'azure.function_list',
    effect: 'read',
    description:
      'List Azure Functions within a Function App. Binds GET management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app}/functions.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+/providers/Microsoft\\.Web/sites/[^/]+/functions'),
    ],
  }),

  defineIntent({
    name: 'azure.keyvault_get_secret',
    effect: 'read',
    description:
      'Read a secret from Azure Key Vault. Binds GET {vault}.vault.azure.net/secrets/{name}. Sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'matches', value: '^[^/]+\\.vault\\.azure\\.net$' },
      { path: 'url.pathname', op: 'matches', value: '^/secrets/[^/]+(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'azure.keyvault_set_secret',
    effect: 'write',
    description:
      'Write a secret into Azure Key Vault. Binds PUT {vault}.vault.azure.net/secrets/{name}. Sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.host', op: 'matches', value: '^[^/]+\\.vault\\.azure\\.net$' },
      { path: 'url.pathname', op: 'matches', value: '^/secrets/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'azure.cosmos_query',
    effect: 'write',
    description:
      'Query a Cosmos DB container via SQL. Binds POST {account}.documents.azure.com/dbs/{db}/colls/{col}/docs with x-ms-documentdb-isquery.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'matches', value: '^[^/]+\\.documents\\.azure\\.com$' },
      { path: 'url.pathname', op: 'matches', value: '^/dbs/[^/]+/colls/[^/]+/docs$' },
    ],
  }),

  defineIntent({
    name: 'azure.cosmos_upsert',
    effect: 'write',
    description:
      'Upsert a document into a Cosmos DB container. Binds POST {account}.documents.azure.com/dbs/{db}/colls/{col}/docs.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['POST', 'PUT'] },
      { path: 'url.host', op: 'matches', value: '^[^/]+\\.documents\\.azure\\.com$' },
      { path: 'url.pathname', op: 'matches', value: '^/dbs/[^/]+/colls/[^/]+/docs(/[^/]+)?$' },
    ],
  }),

  defineIntent({
    name: 'azure.vm_start',
    effect: 'write',
    description:
      'Start a stopped virtual machine. Binds POST management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/start.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+/providers/Microsoft\\.Compute/virtualMachines/[^/]+/start'),
    ],
  }),

  defineIntent({
    name: 'azure.vm_stop',
    effect: 'write',
    description:
      'Power off a running virtual machine. Binds POST management.azure.com/.../virtualMachines/{vm}/powerOff.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+/providers/Microsoft\\.Compute/virtualMachines/[^/]+/powerOff'),
    ],
  }),

  defineIntent({
    name: 'azure.vm_restart',
    effect: 'write',
    description:
      'Restart a virtual machine. Binds POST management.azure.com/.../virtualMachines/{vm}/restart.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+/providers/Microsoft\\.Compute/virtualMachines/[^/]+/restart'),
    ],
  }),

  defineIntent({
    name: 'azure.vm_deallocate',
    effect: 'write',
    description:
      'Deallocate a virtual machine (stops billing for compute). Binds POST management.azure.com/.../virtualMachines/{vm}/deallocate.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+/providers/Microsoft\\.Compute/virtualMachines/[^/]+/deallocate'),
    ],
  }),

  defineIntent({
    name: 'azure.vm_list',
    effect: 'read',
    description:
      'List virtual machines in a subscription. Binds GET management.azure.com/subscriptions/{subId}/providers/Microsoft.Compute/virtualMachines.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/providers/Microsoft\\.Compute/virtualMachines'),
    ],
  }),

  defineIntent({
    name: 'azure.resource_group_list',
    effect: 'read',
    description:
      'List resource groups in a subscription. Binds GET management.azure.com/subscriptions/{subId}/resourceGroups.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups'),
    ],
  }),

  defineIntent({
    name: 'azure.resource_group_create',
    effect: 'write',
    description:
      'Create or update a resource group. Binds PUT management.azure.com/subscriptions/{subId}/resourceGroups/{name}.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'PUT' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'azure.resource_group_delete',
    effect: 'destructive',
    description:
      'Delete a resource group and everything inside it. Binds DELETE management.azure.com/subscriptions/{subId}/resourceGroups/{name}. Destructive.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+'),
    ],
  }),

  defineIntent({
    name: 'azure.app_service_restart',
    effect: 'write',
    description:
      'Restart an App Service. Binds POST management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app}/restart.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+/providers/Microsoft\\.Web/sites/[^/]+/restart'),
    ],
  }),

  defineIntent({
    name: 'azure.logic_app_trigger',
    effect: 'write',
    description:
      'Trigger a Logic App workflow run. Binds POST management.azure.com/.../Microsoft.Logic/workflows/{name}/triggers/{trigger}/run.',
    params: z.object({ subscription_id: subList }),
    expand: ({ subscription_id }) => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.host', op: 'eq', value: 'management.azure.com' },
      subPath(subscription_id, '/resourceGroups/[^/]+/providers/Microsoft\\.Logic/workflows/[^/]+/triggers/[^/]+/run'),
    ],
  }),
];
